using System.Net;
using System.Net.Http;
using System.Text;
using DataGateWin.Services.Update;
using Xunit;

namespace DataGateWin.Tests;

public sealed class GitHubUpdateCheckerTests
{
    public GitHubUpdateCheckerTests()
    {
        GitHubUpdateChecker.ResetSessionStateForTests();
    }

    [Fact]
    public async Task TryGetLatestReleaseVersionForDisplayAsync_ReturnsParsedTag()
    {
        using var http = CreateHttpClient("""
            {
              "tag_name": "v1.0.9"
            }
            """);

        var checker = new GitHubUpdateChecker(http, "IMKolganov", "DataGateWin");

        var latest = await checker.TryGetLatestReleaseVersionForDisplayAsync(CancellationToken.None);

        Assert.Equal("1.0.9", latest);
    }

    [Fact]
    public async Task TryGetLatestReleaseVersionForDisplayAsync_ReturnsNullWhenRequestFails()
    {
        using var http = CreateHttpClient("not found", HttpStatusCode.NotFound);
        var checker = new GitHubUpdateChecker(http, "IMKolganov", "DataGateWin");

        var latest = await checker.TryGetLatestReleaseVersionForDisplayAsync(CancellationToken.None);

        Assert.Null(latest);
    }

    [Fact]
    public async Task CheckForUpdateAsync_DoesNotThrowWhenReleaseIsNotNewer()
    {
        var current = typeof(GitHubUpdateChecker).Assembly.GetName().Version ?? new Version(0, 0, 0);
        using var http = CreateHttpClient($$"""
            {
              "tag_name": "{{current.Major}}.{{current.Minor}}.{{current.Build}}"
            }
            """);

        var checker = new GitHubUpdateChecker(http, "IMKolganov", "DataGateWin");

        await checker.CheckForUpdateAsync(CancellationToken.None);
    }

    [Fact]
    public async Task CheckForUpdateAsync_DoesNotThrowWhenGitHubReturnsInvalidJson()
    {
        using var http = CreateHttpClient("{");
        var checker = new GitHubUpdateChecker(http, "IMKolganov", "DataGateWin");

        await checker.CheckForUpdateAsync(CancellationToken.None);
    }

    [Fact]
    public async Task CheckForUpdateAsync_RunsOnlyOneConcurrentCheck()
    {
        var gate = new TaskCompletionSource<HttpStatusCode>(TaskCreationOptions.RunContinuationsAsynchronously);
        var requestCount = 0;
        using var http = new HttpClient(new CountingHandler(gate.Task, () => Interlocked.Increment(ref requestCount)))
        {
            Timeout = TimeSpan.FromSeconds(5)
        };

        var checker = new GitHubUpdateChecker(http, "IMKolganov", "DataGateWin");
        var first = checker.CheckForUpdateAsync(CancellationToken.None);
        var second = checker.CheckForUpdateAsync(CancellationToken.None);

        gate.SetResult(HttpStatusCode.OK);
        await Task.WhenAll(first, second);

        Assert.Equal(1, requestCount);
    }

    static HttpClient CreateHttpClient(string body, HttpStatusCode status = HttpStatusCode.OK)
    {
        var handler = new StaticResponseHandler(body, status);
        return new HttpClient(handler) { Timeout = TimeSpan.FromSeconds(5) };
    }

    sealed class StaticResponseHandler(string body, HttpStatusCode status) : HttpMessageHandler
    {
        protected override Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request,
            CancellationToken cancellationToken)
        {
            var response = new HttpResponseMessage(status)
            {
                Content = new StringContent(body, Encoding.UTF8, "application/json")
            };
            return Task.FromResult(response);
        }
    }

    sealed class CountingHandler(Task<HttpStatusCode> releaseGate, Action onRequest) : HttpMessageHandler
    {
        protected override async Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request,
            CancellationToken cancellationToken)
        {
            onRequest();
            await releaseGate.ConfigureAwait(false);

            var body = """
                {
                  "tag_name": "0.0.1"
                }
                """;
            return new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new StringContent(body, Encoding.UTF8, "application/json")
            };
        }
    }
}
