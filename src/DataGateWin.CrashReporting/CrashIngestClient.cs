using System.Net.Http.Headers;
using System.Text;

namespace DataGateWin.CrashReporting;

public static class CrashIngestClient
{
    const string RelativePath = "api/v1/windows/crash-ingest";

    public static Uri BuildRequestUri(string baseUrl)
    {
        var trimmed = baseUrl.TrimEnd('/');
        return new Uri($"{trimmed}/{RelativePath}", UriKind.Absolute);
    }

    public static async Task<HttpResponseMessage> PostCrashAsync(
        HttpClient http,
        string baseUrl,
        string crashFilename,
        string processName,
        string? crashToken,
        string payload,
        CancellationToken cancellationToken)
    {
        var uri = BuildRequestUri(baseUrl);
        using var req = new HttpRequestMessage(HttpMethod.Post, uri);
        var content = new StringContent(payload, Encoding.UTF8);
        content.Headers.ContentType = MediaTypeHeaderValue.Parse("text/plain; charset=utf-8");
        req.Content = content;

        req.Headers.TryAddWithoutValidation("X-Crash-Filename", crashFilename);
        req.Headers.TryAddWithoutValidation("X-Crash-Process", processName);
        if (!string.IsNullOrWhiteSpace(crashToken))
            req.Headers.TryAddWithoutValidation("X-Crash-Token", crashToken);

        return await http.SendAsync(req, HttpCompletionOption.ResponseHeadersRead, cancellationToken)
            .ConfigureAwait(false);
    }
}
