using System.Net;
using System.Text;
using DataGateMonitor.SharedModels.ClientIdentity;
using DataGateMonitor.SharedModels.DataGateMonitor.Auth.Requests;
using DataGateMonitor.SharedModels.DataGateMonitor.VpnServerClients.Requests;
using DataGateWin.CrashReporting;
using DataGateWin.Services.Auth;
using DataGateWin.Services.Access;
using DataGateWin.Services.Statistics;
using DataGateWin.Services.VpnServers;
using Xunit;

namespace DataGateWin.Tests;

public sealed class BackendEndpointIdentityTests
{
    [Fact]
    public async Task ServerList_AlwaysSendsIdentity_WithoutIdentityHandler()
    {
        using var transport = new RecordingHandler(_ => "{\"success\":true,\"data\":{}}");
        using var http = CreateHttp(transport);
        await new OpenVpnServersApiClient(http).GetAllWithStatusAsync(default);
        Assert.Equal(["/api/v3/open-vpn-servers/get-all-with-status"], transport.Paths);
    }

    [Fact]
    public void BackendClients_MustUseMandatoryIdentityTransport()
    {
        var root = new DirectoryInfo(AppContext.BaseDirectory);
        while (root is not null && !File.Exists(Path.Combine(root.FullName, "DataGateWin.sln")))
            root = root.Parent;
        Assert.NotNull(root);
        // Guard every backend client, including new clients, against bypassing mandatory identity.
        var services = Path.Combine(root.FullName, "src", "DataGateWin.Core", "Services");
        var files = Directory.GetFiles(services, "*ApiClient.cs", SearchOption.AllDirectories)
            .Concat(new[] { Path.Combine(services, "Auth", "GoogleAuthService.cs"),
                Path.Combine(services, "Access", "UserVpnAccessClient.cs"),
                Path.Combine(root.FullName, "src", "DataGateWin.CrashReporting", "CrashIngestClient.cs") });
        foreach (var file in files)
        {
            var source = File.ReadAllText(file);
            Assert.DoesNotMatch(@"\.(SendAsync|GetAsync|PostAsync|PutAsync|DeleteAsync|PatchAsync|GetFromJsonAsync|PostAsJsonAsync)\s*[(<]", source);
        }
    }

    internal static void AssertIdentity(HttpRequestMessage request)
    {
        Assert.Equal(ClientIdentity.Name, Assert.Single(request.Headers.GetValues(ClientIdentityRules.NameHeader)));
        Assert.Equal(ClientIdentity.Version, Assert.Single(request.Headers.GetValues(ClientIdentityRules.VersionHeader)));
    }

    [Theory]
    [InlineData("google-login")]
    [InlineData("refresh")]
    [InlineData("totp/verify-login")]
    [InlineData("google-code-login")]
    public async Task Authentication_AlwaysSendsIdentity_WithoutIdentityHandler(string endpoint)
    {
        using var transport = new RecordingHandler(_ => "{\"success\":true,\"data\":{}}");
        using var http = CreateHttp(transport);
        var api = new AuthApiClient(http);
        switch (endpoint)
        {
            case "google-login": await api.GoogleLoginAsync(new GoogleLoginRequest(), default); break;
            case "refresh": await api.RefreshAsync(new RefreshRequest(), default); break;
            case "totp/verify-login": await api.TotpVerifyLoginAsync(new TotpVerifyLoginRequest(), default); break;
            default: await new GoogleAuthService(http).ExchangeCodeAsync(http.BaseAddress!.ToString(), new GoogleCodeLoginRequest(), default); break;
        }
        Assert.Equal(["/api/auth/" + endpoint], transport.Paths);
    }

    [Fact]
    public async Task Statistics_AlwaysSendsIdentity_WithoutIdentityHandler()
    {
        using var transport = new RecordingHandler(_ => "{\"success\":true,\"data\":{}}");
        using var http = CreateHttp(transport);
        await new StatisticsApiClient(http).GetOverviewSeriesAsync(new GetOverviewSeriesRequest
        {
            From = DateTimeOffset.UtcNow.AddDays(-1), To = DateTimeOffset.UtcNow
        }, default);
        Assert.Equal(["/api/open-vpn-clients/overview/series"], transport.Paths);
    }

    [Fact]
    public async Task QuotaPlans_Assignments_AndTrafficSummary_AlwaysSendIdentity()
    {
        using var transport = new RecordingHandler(path => path switch
        {
            "/api/quota-plans/get-all" => """{"success":true,"data":{"quotaPlans":[{"id":1,"monthlyQuotaBytes":1000}]}}""",
            "/api/user-quota-plans/get-by-user-id/7" => """{"success":true,"data":{"items":[{"id":1,"quotaPlanId":1}]}}""",
            _ => """{"success":true,"data":{"totals":{"trafficTotalBytes":123}}}"""
        });
        using var http = CreateHttp(transport);
        var payload = Convert.ToBase64String(Encoding.UTF8.GetBytes("""{"nameid":"7","externalId":"test-user"}"""))
            .TrimEnd('=').Replace('+', '-').Replace('/', '_');
        var result = await new UserVpnAccessClient(http).FetchAsync("e30." + payload + ".sig", default);
        Assert.Equal(123, result.TrafficUsedBytesForPeriod);
        Assert.Equal(new[] { "/api/quota-plans/get-all", "/api/user-quota-plans/get-by-user-id/7",
            "/api/open-vpn-clients/overview/summary" }, transport.Paths);
    }

    [Fact]
    public async Task MandatoryIdentity_OverridesCallerHeaders()
    {
        using var transport = new RecordingHandler(_ => "{}");
        using var http = CreateHttp(transport);
        using var request = new HttpRequestMessage(HttpMethod.Get, "api/test");
        request.Headers.Add(ClientIdentityRules.NameHeader, "other");
        request.Headers.Add(ClientIdentityRules.VersionHeader, "old");
        using var response = await http.SendBackendAsync(request, default);
        Assert.Single(transport.Paths);
    }

    [Theory]
    [InlineData("")]
    [InlineData(" ")]
    [InlineData("bad\r\nversion")]
    public async Task InvalidVersion_PreventsNetworkRequest(string version)
    {
        using var transport = new RecordingHandler(_ => "{}");
        using var http = new HttpClient(new ClientIdentityHandler(transport, () => version));
        await Assert.ThrowsAsync<InvalidOperationException>(() => http.GetAsync("https://api.example.test/api/test"));
        Assert.Empty(transport.Paths);
    }

    private static HttpClient CreateHttp(HttpMessageHandler handler) => new(handler)
    {
        BaseAddress = new Uri("https://api.example.test/")
    };

    private sealed class RecordingHandler(Func<string, string> body) : HttpMessageHandler
    {
        public List<string> Paths { get; } = [];
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken ct)
        {
            AssertIdentity(request);
            var path = request.RequestUri!.AbsolutePath;
            Paths.Add(path);
            return Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new StringContent(body(path), Encoding.UTF8, "application/json")
            });
        }
    }
}
