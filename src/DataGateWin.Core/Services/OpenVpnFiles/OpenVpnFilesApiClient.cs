using DataGateWin.CrashReporting;
using System.Net;
using System.Net.Http;
using System.Text;
using DataGateMonitor.SharedModels.DataGateMonitor.OpenVpnFiles.Requests;
using DataGateMonitor.SharedModels.DataGateMonitor.OpenVpnFiles.Responses;
using DataGateMonitor.SharedModels.Responses;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;

namespace DataGateWin.Services.OpenVpnFiles;

public sealed class OpenVpnFilesApiClient(HttpClient http, Action<string>? log = null)
{
    private readonly HttpClient _http = http;

    public async Task<DownloadFileResponse> EnsureAndDownloadDeviceFileAsync(
        int vpnServerId,
        string commonName,
        string externalId,
        string issuedTo,
        CancellationToken ct)
    {
        var first = await TryDownloadAsync(vpnServerId, commonName, ct).ConfigureAwait(false);
        if (first != null)
            return first;

        await AddWithTokenAsync(vpnServerId, commonName, externalId, issuedTo, ct).ConfigureAwait(false);

        var second = await TryDownloadAsync(vpnServerId, commonName, ct).ConfigureAwait(false);
        if (second != null)
            return second;

        throw new InvalidOperationException("profile_download_failed");
    }

    private async Task<DownloadFileResponse?> TryDownloadAsync(
        int vpnServerId,
        string commonName,
        CancellationToken ct)
    {
        using var req = new HttpRequestMessage(
            HttpMethod.Post,
            "api/open-vpn-files/download-file-by-cn")
        {
            Content = new StringContent(
                JsonConvert.SerializeObject(new DownloadFileByCnRequest
                {
                    VpnServerId = vpnServerId,
                    CommonName = commonName
                }),
                Encoding.UTF8,
                "application/json")
        };

        log?.Invoke("[connect][download] POST download-file-by-cn; waiting for response headers...");
        using var resp = await _http.SendBackendAsync(req, HttpCompletionOption.ResponseHeadersRead, ct).ConfigureAwait(false);
        log?.Invoke($"[connect][download] HTTP {(int)resp.StatusCode}; reading profile response body...");
        var raw = await resp.Content.ReadAsStringAsync(ct).ConfigureAwait(false);
        log?.Invoke($"[connect][download] Response body received chars={raw.Length}; decoding profile...");

        if (resp.StatusCode == HttpStatusCode.NotFound)
            return null;

        if (!resp.IsSuccessStatusCode)
        {
            if (IsNotFoundApiMessage(raw))
                return null;

            // Backend can issue a notification before the OVPN file is actually available.
            // Do not create a second profile or keep retrying a server-side generation timeout.
            if (IsOvpnGenerationTimeout(raw))
            {
                log?.Invoke($"[connect][download] ERROR: HTTP {(int)resp.StatusCode}; VPN server timed out waiting for the generated OVPN file.");
                throw new TimeoutException("VPN server timed out waiting for the generated OVPN file.");
            }
            log?.Invoke($"[connect][download] ERROR: Profile download failed HTTP {(int)resp.StatusCode}.");
            throw new InvalidOperationException("profile_download_failed");
        }

        var api = JsonConvert.DeserializeObject<ApiResponse<DownloadFileResponse>>(raw);
        if (api?.Success != true || api.Data == null)
            return null;

        log?.Invoke($"[connect][download] Profile decoded bytes={api.Data.Content?.Length ?? 0}");
        return api.Data;
    }

    private async Task AddWithTokenAsync(
        int vpnServerId,
        string commonName,
        string externalId,
        string issuedTo,
        CancellationToken ct)
    {
        using var req = new HttpRequestMessage(
            HttpMethod.Post,
            "api/open-vpn-files/add-with-token")
        {
            Content = new StringContent(
                JsonConvert.SerializeObject(new AddFileRequest
                {
                    VpnServerId = vpnServerId,
                    CommonName = commonName,
                    ExternalId = externalId,
                    IssuedTo = issuedTo
                }),
                Encoding.UTF8,
                "application/json")
        };

        log?.Invoke("[connect][issue] POST add-with-token; waiting for response headers...");
        // The issued profile is downloaded by CN below; the creation response body is unused.
        using var resp = await _http.SendBackendAsync(req, HttpCompletionOption.ResponseHeadersRead, ct).ConfigureAwait(false);
        log?.Invoke($"[connect][issue] HTTP {(int)resp.StatusCode}; proceeding to profile download.");
        if (!resp.IsSuccessStatusCode)
            throw new InvalidOperationException("profile_download_failed");
    }

    private static bool IsOvpnGenerationTimeout(string body)
    {
        try
        {
            var message = JObject.Parse(body).Value<string>("message") ?? "";
            return message.Contains("Timed out", StringComparison.OrdinalIgnoreCase)
                && message.Contains("waiting for OVPN", StringComparison.OrdinalIgnoreCase);
        }
        catch (JsonException) { return false; }
    }

    private static bool IsNotFoundApiMessage(string body)
    {
        if (string.IsNullOrWhiteSpace(body))
            return false;

        try
        {
            var obj = JObject.Parse(body);
            return obj.Value<bool?>("success") == false
                   && obj.Value<string>("message")?
                       .Contains("not found", StringComparison.OrdinalIgnoreCase) == true;
        }
        catch
        {
            return false;
        }
    }
}
