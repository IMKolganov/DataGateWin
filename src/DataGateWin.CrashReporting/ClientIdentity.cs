using System.Reflection;
using System.Text.Json;
using DataGateMonitor.SharedModels.ClientIdentity;

namespace DataGateWin.CrashReporting;

/// <summary>
/// Who is calling the DataGateMonitor backend: <c>X-Client-Name: windows</c> plus the app build version.
/// Header names, query names and error codes come from <see cref="ClientIdentityRules"/> (DataGateMonitor.SharedModels).
/// Lives here so Core, WinUI and the installer share one implementation.
/// </summary>
public static class ClientIdentity
{
    public static string Name => ClientNames.Windows;

    /// <summary>Entry assembly build version (<c>AssemblyVersion</c> in the csproj, e.g. <c>1.0.23</c>).</summary>
    public static string Version { get; } = ResolveVersion(Assembly.GetEntryAssembly());

    /// <summary>Raised once per rejection (HTTP 400 with <c>data.code</c> = <c>client_*</c>): this build must be updated.</summary>
    public static event Action<string>? Rejected;

    public static string ResolveVersion(Assembly? assembly)
    {
        // Projects set AssemblyVersion only, so InformationalVersion would be the SDK default 1.0.0.
        var raw = assembly?.GetName().Version?.ToString(3)
            ?? assembly?.GetCustomAttribute<AssemblyInformationalVersionAttribute>()?.InformationalVersion?.Split('+')[0];
        return SanitizeVersion(raw);
    }

    /// <summary>Printable ASCII only, at most <see cref="ClientIdentityRules.MaxVersionLength"/> chars.</summary>
    public static string SanitizeVersion(string? raw)
    {
        var printable = new string((raw ?? "").Where(c => c is >= (char)0x20 and <= (char)0x7E).ToArray()).Trim();
        if (printable.Length > ClientIdentityRules.MaxVersionLength)
            printable = printable[..ClientIdentityRules.MaxVersionLength].Trim();
        return printable.Length == 0 ? "0" : printable;
    }

    public static void Apply(HttpRequestMessage request, string? version = null)
    {
        request.Headers.Remove(ClientIdentityRules.NameHeader);
        request.Headers.Remove(ClientIdentityRules.VersionHeader);
        request.Headers.TryAddWithoutValidation(ClientIdentityRules.NameHeader, Name);
        request.Headers.TryAddWithoutValidation(ClientIdentityRules.VersionHeader, version ?? Version);
    }

    /// <summary>Appends <c>clientName</c> / <c>clientVersion</c> to a SignalR hub URL, keeping any existing query.</summary>
    public static string AppendToHubUrl(string url, string? version = null)
    {
        var separator = url.Contains('?') ? "&" : "?";
        return url + separator
            + ClientIdentityRules.NameQueryParameter + "=" + Uri.EscapeDataString(Name) + "&"
            + ClientIdentityRules.VersionQueryParameter + "=" + Uri.EscapeDataString(version ?? Version);
    }

    /// <summary>Returns the <c>client_*</c> code of a client-identity 400 body, or null for any other error.</summary>
    public static string? ParseRejectionCode(string? body)
    {
        if (string.IsNullOrWhiteSpace(body))
            return null;
        try
        {
            using var doc = JsonDocument.Parse(body);
            if (!TryGetProperty(doc.RootElement, "data", out var data) || data.ValueKind != JsonValueKind.Object)
                return null;
            if (!TryGetProperty(data, "code", out var code) || code.ValueKind != JsonValueKind.String)
                return null;
            var value = code.GetString();
            return value is ClientIdentityRules.ErrorCodeMissingName
                or ClientIdentityRules.ErrorCodeUnknownName
                or ClientIdentityRules.ErrorCodeMissingVersion
                or ClientIdentityRules.ErrorCodeInvalidVersion
                ? value
                : null;
        }
        catch (JsonException)
        {
            return null;
        }
    }

    internal static void NotifyRejected(string code) => Rejected?.Invoke(code);

    static bool TryGetProperty(JsonElement element, string name, out JsonElement value)
    {
        if (element.ValueKind == JsonValueKind.Object)
        {
            foreach (var p in element.EnumerateObject())
            {
                if (string.Equals(p.Name, name, StringComparison.OrdinalIgnoreCase))
                {
                    value = p.Value;
                    return true;
                }
            }
        }

        value = default;
        return false;
    }
}

/// <summary>
/// Adds the client identity headers to every request of a backend <see cref="HttpClient"/> and reports
/// client-identity rejections. Put it innermost (next to the socket handler) so retries after a token
/// refresh go through it again. Only for DataGateMonitor clients — never for VPN node, GitHub or Google traffic.
/// </summary>
public sealed class ClientIdentityHandler : DelegatingHandler
{
    readonly Func<string> _version;

    public ClientIdentityHandler(HttpMessageHandler innerHandler, Func<string>? version = null)
        : base(innerHandler)
    {
        _version = version ?? (() => ClientIdentity.Version);
    }

    protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
    {
        ClientIdentity.Apply(request, _version());
        var response = await base.SendAsync(request, cancellationToken).ConfigureAwait(false);

        if (response.StatusCode == System.Net.HttpStatusCode.BadRequest && response.Content is not null)
        {
            await response.Content.LoadIntoBufferAsync(cancellationToken).ConfigureAwait(false);
            var body = await response.Content.ReadAsStringAsync(cancellationToken).ConfigureAwait(false);
            var code = ClientIdentity.ParseRejectionCode(body);
            if (code is not null)
            {
                CrashReporter.LogStructured(
                    "client_identity_rejected",
                    ("code", code),
                    ("path", request.RequestUri?.AbsolutePath ?? ""));
                ClientIdentity.NotifyRejected(code);
            }
        }

        return response;
    }
}
