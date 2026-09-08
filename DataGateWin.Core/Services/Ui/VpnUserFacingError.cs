using System.Net;
using System.Net.Http;
using System.Net.Sockets;
using System.Text.RegularExpressions;
using DataGateWin.Localization;
using DataGateWin.Services.Auth;
using Newtonsoft.Json.Linq;

namespace DataGateWin.Services.Ui;

/// <summary>
/// Maps engine/API/exception text to short user-facing strings (never raw JSON, HRESULT, or stacks).
/// </summary>
public static class VpnUserFacingError
{
    private static readonly Regex HtmlTag = new("<[^>]+>", RegexOptions.Compiled | RegexOptions.CultureInvariant);

    public static string FromException(Exception? ex)
    {
        if (ex is null)
            return Loc.T("Home_Error_Generic");

        while (ex is AggregateException { InnerExceptions.Count: 1 } agg)
            ex = agg.InnerExceptions[0];

        for (var cur = ex; cur != null; cur = cur.InnerException)
        {
            if (cur is TimeoutException)
                return Loc.T("Home_Error_Timeout");

            // TaskCanceledException : OperationCanceledException — HttpClient timeouts land here.
            if (cur is TaskCanceledException)
                return Loc.T("Home_Error_Timeout");

            if (cur is OperationCanceledException)
                return Loc.T("Home_Error_Canceled");

            if (cur is HttpListenerException or UnauthorizedAccessException)
                return Loc.T("Home_Error_Permission");

            if (cur is SocketException)
                return Loc.T("Home_Error_Network");

            if (cur is FileNotFoundException fn && IsEngineMissing(fn))
                return Loc.T("Home_Status_EngineMissing");

            if (cur is HttpRequestException http)
            {
                var fromStatus = FromHttpStatus(http.StatusCode);
                if (fromStatus is not null)
                    return fromStatus;
            }
        }

        return FromMessage(FlattenMessages(ex));
    }

    public static string FromMessage(string? message)
    {
        if (string.IsNullOrWhiteSpace(message))
            return Loc.T("Home_Error_Generic");

        var m = StripNoise(message);

        if (TryExtractBodyJson(message, out var jsonMsg) && !string.IsNullOrWhiteSpace(jsonMsg))
        {
            var nested = FromMessageCore(jsonMsg);
            if (nested != Loc.T("Home_Error_Generic"))
                return nested;
        }

        return FromMessageCore(m);
    }

    private static string FromMessageCore(string m)
    {
        if (LoginFlow.IsLoginChallengeExpiredMessage(m))
            return Loc.T("Login_Totp_ChallengeExpired");

        if (ContainsAny(m, "invalid code", "invalid totp", "invalid authenticator"))
            return Loc.T("Login_Totp_Error_Invalid");

        if (ContainsAny(m,
                "already exists",
                "Cannot create a file",
                "tun busy",
                "xray0"))
            return Loc.T("Home_Error_TunBusy");

        if (ContainsAny(m,
                "Access token not available",
                "ExternalId not available",
                "invalid_token")
            || (ContainsAny(m, "401", "Unauthorized", "403", "Forbidden") && ContainsAny(m, "http", "token", "auth", "status")))
            return Loc.T("Home_Error_Auth");

        if (ContainsAny(m,
                "profile_download_failed",
                "Xray link not found",
                "OVPN file not found",
                "Downloaded Xray content is empty",
                "Downloaded OVPN content is empty",
                "xray_bad_payload",
                "Missing xrayShareLinks"))
            return Loc.T("Home_Error_ProfileDownload");

        if (ContainsAny(m,
                "xray_convert_failed",
                "convertShareLinksToXrayJson",
                "Xray profile has no share",
                "no_xray_share",
                "Invalid Xray profile"))
            return Loc.T("Home_Error_XrayConvert");

        if (ContainsAny(m,
                "xray_load_failed",
                "xray_start_failed",
                "xray_not_running",
                "xray_config_failed",
                "Failed to load libXray",
                "runXrayFromJson"))
            return Loc.T("Home_Error_XrayStart");

        if (ContainsAny(m,
                "Attach failed",
                "named pipe",
                "engine.exe",
                "StartOrAttach",
                "not attached",
                "GetStatus failed",
                "StopSession incomplete",
                "Engine process exited",
                "Control pipe"))
            return Loc.T("Home_Error_EngineAttach");

        if (ContainsAny(m, "engine exit", "EngineExited", "xray_exit"))
            return Loc.T("Home_Error_EngineExit");

        if (ContainsAny(m,
                "No eligible",
                "No VPN servers available",
                "no_wss"))
            return Loc.T("Home_Log_NoWss");

        if (ContainsAny(m, "Cannot start Google sign-in listener", "Could not open the browser"))
            return Loc.T("Home_Error_Permission");

        if (ContainsAny(m, "access_denied", "access-denied"))
            return Loc.T("Home_Error_Canceled");

        if (ContainsAny(m, "timeout", "timed out"))
            return Loc.T("Home_Error_Timeout");

        if (ContainsAny(m,
                "no such host",
                "name or service not known",
                "actively refused",
                "network is unreachable",
                "failed to connect",
                "connection timed out",
                "an error occurred while sending",
                "unable to connect",
                "connection reset"))
            return Loc.T("Home_Error_Network");

        if (LooksLikeJson(m) || LooksLikeHtml(m))
        {
            var extracted = TryExtractApiMessage(m);
            if (!string.IsNullOrWhiteSpace(extracted))
                return FromMessageCore(extracted!);
            return Loc.T("Home_Error_ServerRequest");
        }

        if (LooksTechnical(m))
            return Loc.T("Home_Error_Generic");

        return SanitizeShort(m);
    }

    private static string? FromHttpStatus(HttpStatusCode? status) =>
        status switch
        {
            HttpStatusCode.Unauthorized or HttpStatusCode.Forbidden => Loc.T("Home_Error_Auth"),
            HttpStatusCode.RequestTimeout or HttpStatusCode.GatewayTimeout => Loc.T("Home_Error_Timeout"),
            >= HttpStatusCode.InternalServerError => Loc.T("Home_Error_ServerRequest"),
            _ => null,
        };

    private static bool IsEngineMissing(FileNotFoundException fn) =>
        (fn.FileName != null && fn.FileName.EndsWith("engine.exe", StringComparison.OrdinalIgnoreCase))
        || fn.Message.Contains("Engine executable not found", StringComparison.OrdinalIgnoreCase);

    private static string FlattenMessages(Exception ex)
    {
        var parts = new List<string>();
        for (var cur = ex; cur != null; cur = cur.InnerException)
        {
            if (!string.IsNullOrWhiteSpace(cur.Message))
                parts.Add(cur.Message);
        }

        return string.Join(" | ", parts);
    }

    private static string StripNoise(string message)
    {
        var m = HtmlTag.Replace(message.Trim(), " ");
        m = m.Replace('\r', ' ').Replace('\n', ' ');
        while (m.Contains("  ", StringComparison.Ordinal))
            m = m.Replace("  ", " ", StringComparison.Ordinal);
        return m.Trim();
    }

    private static string SanitizeShort(string m)
    {
        if (m.Length == 0 || LooksTechnical(m))
            return Loc.T("Home_Error_Generic");

        if (m.Length <= 140)
            return m;
        return m[..137] + "...";
    }

    private static bool LooksTechnical(string m) =>
        m.Contains("HRESULT", StringComparison.OrdinalIgnoreCase)
        || m.Contains("0x", StringComparison.OrdinalIgnoreCase)
        || m.Contains("Body:", StringComparison.OrdinalIgnoreCase)
        || m.Contains("StatusCode", StringComparison.OrdinalIgnoreCase)
        || (m.Contains("Exception", StringComparison.OrdinalIgnoreCase) && m.Contains(':'))
        || (m.Contains(" at ", StringComparison.Ordinal) &&
            (m.Contains(".cs:", StringComparison.Ordinal) || m.Contains("System.", StringComparison.Ordinal)))
        || m.Contains('{')
        || m.Contains('<');

    private static bool LooksLikeJson(string m)
        => m.StartsWith("{", StringComparison.Ordinal)
           || m.StartsWith("[", StringComparison.Ordinal)
           || m.Contains("\"success\"", StringComparison.OrdinalIgnoreCase);

    private static bool LooksLikeHtml(string m)
        => m.Contains("<html", StringComparison.OrdinalIgnoreCase)
           || m.Contains("<!DOCTYPE", StringComparison.OrdinalIgnoreCase);

    private static bool TryExtractBodyJson(string raw, out string? message)
    {
        message = null;
        var idx = raw.IndexOf("Body:", StringComparison.OrdinalIgnoreCase);
        if (idx < 0)
            return false;
        var json = raw[(idx + 5)..].Trim();
        message = TryExtractApiMessage(json);
        return !string.IsNullOrWhiteSpace(message);
    }

    private static string? TryExtractApiMessage(string raw)
    {
        try
        {
            var obj = JObject.Parse(raw);
            var msg = obj.Value<string>("message")
                      ?? obj.Value<string>("Message")
                      ?? obj.Value<string>("error")
                      ?? obj.Value<string>("title");
            if (string.IsNullOrWhiteSpace(msg))
                return null;
            msg = StripNoise(msg);
            if (msg.Length > 140 || LooksLikeJson(msg) || LooksLikeHtml(msg))
                return null;
            return msg;
        }
        catch
        {
            return null;
        }
    }

    private static bool ContainsAny(string haystack, params string[] needles)
    {
        foreach (var n in needles)
        {
            if (haystack.Contains(n, StringComparison.OrdinalIgnoreCase))
                return true;
        }

        return false;
    }
}
