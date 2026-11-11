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
    public async Task CheckForUpdateAsync_DoesNotThrowWhenReleaseIsNewer_ButUiUnavailable()
    {
        // Newer tag must pass ShouldOfferUpgrade; without a WPF MainWindow the prompt path no-ops safely.
        using var http = CreateHttpClient("""
            {
              "tag_name": "99.0.0"
            }
            """);

        var checker = new GitHubUpdateChecker(http, "IMKolganov", "DataGateWin");
        await checker.CheckForUpdateAsync(CancellationToken.None);
    }

    [Fact]
    public async Task CheckForUpdateAsync_SkipsSecondCallAfterPromptGateWouldComplete_OnNotNewer()
    {
        var current = AppUpdatePolicy.ResolveCurrentAppVersion(
            typeof(GitHubUpdateChecker).Assembly.Location,
            typeof(GitHubUpdateChecker).Assembly.GetName().Version);
        using var http = CreateHttpClient($$"""
            {
              "tag_name": "{{current.Major}}.{{current.Minor}}.{{current.Build}}"
            }
            """);

        var checker = new GitHubUpdateChecker(http, "IMKolganov", "DataGateWin");
        await checker.CheckForUpdateAsync(CancellationToken.None);
        await checker.CheckForUpdateAsync(CancellationToken.None);
    }

    [Fact]
    public void AppUpdatePolicy_DoesNotOfferUpgradeWhenLatestEqualsCurrent_ViciousLoopGuard()
    {
        // The Yes→installer→relaunch→prompt loop happens when latest stays > current.
        // Same/older tags must never offer.
        Assert.False(AppUpdatePolicy.ShouldOfferUpgrade(
            ReleaseVersionParser.ParseTag("1.0.18"),
            ReleaseVersionParser.ParseTag("1.0.18")));
        Assert.False(AppUpdatePolicy.ShouldOfferUpgrade(
            ReleaseVersionParser.ParseTag("1.0.14"),
            ReleaseVersionParser.ParseTag("1.0.18")));
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

    [Theory]
    [InlineData("{}")]
    [InlineData("[]")]
    [InlineData("{\"tag_name\":123}")]
    [InlineData("{\"tag_name\":\"junk\"}")]
    [InlineData("{\"tag_name\":\"99.0.0\",\"prerelease\":true}")]
    [InlineData("{\"tag_name\":\"99.0.0\",\"draft\":true}")]
    public async Task InvalidRelease_IsUnavailable(string json)
    {
        using var http = CreateHttpClient(json);
        var checker = new GitHubUpdateChecker(http, "owner", "repo");
        Assert.Null(await checker.TryGetLatestReleaseVersionForDisplayAsync(default));
        Assert.Equal(UpdateCheckStatus.Unavailable, (await checker.CheckForUpdateAsync(default, manual: true)).Status);
    }

    [Fact]
    public async Task ManualCheck_BypassesCompletedPromptGate()
    {
        using var http = CreateHttpClient("{\"tag_name\":\"999.0.0\"}");
        var prompt = new RecordingPrompter();
        var checker = new GitHubUpdateChecker(http, "owner", "repo", prompt);
        await checker.CheckForUpdateAsync(default);
        await checker.CheckForUpdateAsync(default);
        Assert.Equal(1, prompt.Count);
        var result = await checker.CheckForUpdateAsync(default, manual: true);
        Assert.Equal(UpdateCheckStatus.UpdateAvailable, result.Status);
        Assert.Equal(2, prompt.Count);
    }

    [Fact]
    public async Task Cancellation_ReleasesGateAndAllowsRetry()
    {
        using var http = CreateHttpClient("{\"tag_name\":\"999.0.0\"}");
        var checker = new GitHubUpdateChecker(http, "owner", "repo");
        using var cts = new CancellationTokenSource();
        cts.Cancel();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => checker.CheckForUpdateAsync(cts.Token));
        Assert.Equal(UpdateCheckStatus.UpdateAvailable, (await checker.CheckForUpdateAsync(default)).Status);
    }

    sealed class RecordingPrompter : IUpdatePrompter
    {
        public int Count;
        public Task<bool> PromptAsync(CancellationToken ct) { Count++; return Task.FromResult(true); }
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
