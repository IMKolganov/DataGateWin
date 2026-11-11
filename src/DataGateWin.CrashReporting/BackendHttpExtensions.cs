using System.Net.Http.Json;

namespace DataGateWin.CrashReporting;

/// <summary>Mandatory identity for backend requests, including clients with an injected transport.</summary>
public static class BackendHttpExtensions
{
    public static Task<HttpResponseMessage> SendBackendAsync(this HttpClient http,
        HttpRequestMessage request, CancellationToken ct) =>
        http.SendBackendAsync(request, HttpCompletionOption.ResponseContentRead, ct);

    public static Task<HttpResponseMessage> SendBackendAsync(this HttpClient http,
        HttpRequestMessage request, HttpCompletionOption completion, CancellationToken ct)
    {
        ClientIdentity.Apply(request);
        return http.SendAsync(request, completion, ct);
    }

    public static Task<HttpResponseMessage> GetBackendAsync(this HttpClient http, string url, CancellationToken ct) =>
        http.SendBackendAsync(new HttpRequestMessage(HttpMethod.Get, url), ct);

    public static Task<HttpResponseMessage> PostBackendAsync(this HttpClient http, string url,
        HttpContent content, CancellationToken ct) =>
        http.SendBackendAsync(new HttpRequestMessage(HttpMethod.Post, url) { Content = content }, ct);

    public static async Task<T?> GetBackendFromJsonAsync<T>(this HttpClient http, string url, CancellationToken ct)
    {
        using var request = new HttpRequestMessage(HttpMethod.Get, url);
        using var response = await http.SendBackendAsync(request, HttpCompletionOption.ResponseHeadersRead, ct)
            .ConfigureAwait(false);
        response.EnsureSuccessStatusCode();
        return await response.Content.ReadFromJsonAsync<T>(ct).ConfigureAwait(false);
    }
}
