using System.Net;
using DataGateWin.CrashReporting;
using Xunit;

namespace DataGateWin.Tests;

public sealed class CrashIngestClientTests
{
    [Theory]
    [InlineData("https://api.example.com", "https://api.example.com/api/v1/windows/crash-ingest")]
    [InlineData("https://api.example.com/", "https://api.example.com/api/v1/windows/crash-ingest")]
    public void BuildRequestUri_AppendsIngestPath(string baseUrl, string expected)
    {
        var uri = CrashIngestClient.BuildRequestUri(baseUrl);
        Assert.Equal(expected, uri.ToString());
    }

    [Fact]
    public async Task PostCrashAsync_SendsHeadersContentTypeAndOptionalToken()
    {
        using var handler = new RecordingHandler();
        using var http = new HttpClient(handler);

        await CrashIngestClient.PostCrashAsync(
                http,
                "https://api.example.com/",
                "win_crash_1.txt",
                "my.process",
                crashToken: "secret-token",
                payload: "body",
                CancellationToken.None);

        Assert.NotNull(handler.LastRequest);
        Assert.Equal(HttpMethod.Post, handler.LastRequest!.Method);
        Assert.Equal("text/plain; charset=utf-8", handler.LastRequest.Content!.Headers.ContentType!.ToString());

        Assert.True(handler.LastRequest.Headers.TryGetValues("X-Crash-Filename", out var fn));
        Assert.Equal("win_crash_1.txt", Assert.Single(fn));

        Assert.True(handler.LastRequest.Headers.TryGetValues("X-Crash-Process", out var proc));
        Assert.Equal("my.process", Assert.Single(proc));

        Assert.True(handler.LastRequest.Headers.TryGetValues("X-Crash-Token", out var tok));
        Assert.Equal("secret-token", Assert.Single(tok));
    }

    [Fact]
    public async Task PostCrashAsync_OmitsTokenWhenBlank()
    {
        using var handler = new RecordingHandler();
        using var http = new HttpClient(handler);

        await CrashIngestClient.PostCrashAsync(
                http,
                "https://api.example.com",
                "f.txt",
                CrashReporter.DefaultProcessName,
                crashToken: "   ",
                payload: "x",
                CancellationToken.None);

        Assert.False(handler.LastRequest!.Headers.Contains("X-Crash-Token"));
    }

    sealed class RecordingHandler : HttpMessageHandler
    {
        public HttpRequestMessage? LastRequest { get; private set; }

        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            LastRequest = request;
            return Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK));
        }
    }
}
