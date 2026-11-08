using System.Net;
using System.Net.Http;
using System.Text;
using DataGateMonitor.SharedModels.ClientIdentity;
using DataGateMonitor.SharedModels.DataGateMonitor.Auth.Responses;
using DataGateWin.CrashReporting;
using DataGateWin.Services.Auth;
using DataGateWin.Services.Auth.Interfaces;
using Xunit;

namespace DataGateWin.Tests;

public sealed class ClientIdentityHandlerTests
{
    const string Version = "1.0.23";
    static readonly Uri BaseUri = new("https://api.example.test/");

    [Fact]
    public async Task BackendRequest_GetsNameAndVersionHeaders()
    {
        var stub = new RecordingHandler(_ => Ok("{}"));
        using var http = new HttpClient(new ClientIdentityHandler(stub, () => Version)) { BaseAddress = BaseUri };

        using var _ = await http.GetAsync("api/v3/open-vpn-servers/get-all-with-status");

        var sent = Assert.Single(stub.Requests);
        Assert.Equal("windows", sent.Name);
        Assert.Equal(Version, sent.Version);
    }

    [Fact]
    public async Task RetryAfterRefresh_KeepsHeaders()
    {
        var apiCalls = 0;
        var stub = new RecordingHandler(req =>
        {
            if (req.RequestUri!.AbsolutePath.EndsWith("/api/auth/refresh", StringComparison.Ordinal))
                return Ok(RefreshBody);
            return ++apiCalls == 1 ? new HttpResponseMessage(HttpStatusCode.Unauthorized) : Ok("{}");
        });
        var identity = new ClientIdentityHandler(stub, () => Version);
        var authApi = new AuthApiClient(new HttpClient(identity, disposeHandler: false) { BaseAddress = BaseUri });
        var session = new AuthSession(authApi, new MemoryTokenStore(), "device", "agent");
        await session.InitializeAsync(CancellationToken.None);
        using var http = new HttpClient(new AuthenticatedHttpHandler(session, identity)) { BaseAddress = BaseUri };

        using var response = await http.GetAsync("api/v3/open-vpn-servers/get-all-with-status");

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Equal(3, stub.Requests.Count); // 401, refresh, retry
        Assert.All(stub.Requests, r =>
        {
            Assert.Equal("windows", r.Name);
            Assert.Equal(Version, r.Version);
        });
        Assert.Equal("Bearer new-access", stub.Requests[2].Authorization);
    }

    [Fact]
    public async Task ClientIdentityRejection_IsReported_OtherBadRequestIsNot()
    {
        var bodies = new Queue<string>([RejectionBody, """{"success":false,"message":"bad"}"""]);
        var stub = new RecordingHandler(_ => new HttpResponseMessage(HttpStatusCode.BadRequest)
        {
            Content = new StringContent(bodies.Dequeue(), Encoding.UTF8, "application/json")
        });
        using var http = new HttpClient(new ClientIdentityHandler(stub, () => Version)) { BaseAddress = BaseUri };
        var reported = new List<string>();
        void OnRejected(string code) => reported.Add(code);
        ClientIdentity.Rejected += OnRejected;
        try
        {
            using (var first = await http.GetAsync("api/auth/refresh"))
                Assert.Contains("client_version_invalid", await first.Content.ReadAsStringAsync());
            using (await http.GetAsync("api/auth/refresh")) { }
        }
        finally
        {
            ClientIdentity.Rejected -= OnRejected;
        }

        Assert.Equal(["client_version_invalid"], reported);
    }

    [Fact]
    public void HubUrl_GetsQueryParameters_KeepingExistingOnes()
    {
        Assert.Equal(
            "https://api.example.test/api/hubs/frontend?access_token=x&clientName=windows&clientVersion=1.0.23",
            ClientIdentity.AppendToHubUrl("https://api.example.test/api/hubs/frontend?access_token=x", Version));
        Assert.Equal(
            "https://api.example.test/api/hubs/frontend?clientName=windows&clientVersion=1.0.23",
            ClientIdentity.AppendToHubUrl("https://api.example.test/api/hubs/frontend", Version));
    }

    [Fact]
    public void Version_IsValidForBackend()
    {
        Assert.True(ClientIdentityRules.IsValidVersion(ClientIdentity.Version));
        Assert.True(ClientIdentityRules.IsAllowedName(ClientIdentity.Name));
        Assert.Equal("1.0-", ClientIdentity.SanitizeVersion("1.0-é"));
        Assert.Equal(ClientIdentityRules.MaxVersionLength, ClientIdentity.SanitizeVersion(new string('9', 100)).Length);
    }

    [Fact]
    public void ParseRejectionCode_OnlyMatchesClientCodes()
    {
        Assert.Equal("client_name_missing", ClientIdentity.ParseRejectionCode("""{"data":{"code":"client_name_missing"}}"""));
        Assert.Equal("client_name_unknown", ClientIdentity.ParseRejectionCode("""{"Data":{"Code":"client_name_unknown"}}"""));
        Assert.Null(ClientIdentity.ParseRejectionCode("""{"data":{"code":"invalid_token"}}"""));
        Assert.Null(ClientIdentity.ParseRejectionCode("not json"));
        Assert.Null(ClientIdentity.ParseRejectionCode(null));
    }

    [Fact]
    public void UserFacingError_ForRejection_AsksToUpdate()
    {
        Assert.Equal(
            Localization.Loc.T("Msg_ClientOutdatedBody"),
            Services.Ui.VpnUserFacingError.FromMessage("Response status code does not indicate success: 400. Body: " + RejectionBody));
    }

    const string RejectionBody =
        """{"success":false,"message":"Invalid client version","data":{"code":"client_version_invalid","nameHeader":"X-Client-Name","versionHeader":"X-Client-Version","allowedNames":["windows"]}}""";

    static readonly string RefreshBody =
        $$$"""{"success":true,"data":{"token":"new-access","expiration":"{{{DateTimeOffset.UtcNow.AddHours(1):O}}}","refreshToken":"new-refresh","refreshExpiration":"{{{DateTimeOffset.UtcNow.AddDays(30):O}}}"}}""";

    static HttpResponseMessage Ok(string body) =>
        new(HttpStatusCode.OK) { Content = new StringContent(body, Encoding.UTF8, "application/json") };

    sealed record SentRequest(string Path, string? Name, string? Version, string? Authorization);

    sealed class RecordingHandler(Func<HttpRequestMessage, HttpResponseMessage> respond) : HttpMessageHandler
    {
        public List<SentRequest> Requests { get; } = [];

        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            Requests.Add(new SentRequest(
                request.RequestUri!.AbsolutePath,
                Header(request, ClientIdentityRules.NameHeader),
                Header(request, ClientIdentityRules.VersionHeader),
                request.Headers.Authorization?.ToString()));
            return Task.FromResult(respond(request));
        }

        static string? Header(HttpRequestMessage request, string name) =>
            request.Headers.TryGetValues(name, out var values) ? string.Join(",", values) : null;
    }

    sealed class MemoryTokenStore : ITokenStore
    {
        AuthTokensResponse? _tokens = new()
        {
            Token = "old-access",
            Expiration = DateTimeOffset.UtcNow.AddHours(1),
            RefreshToken = "old-refresh",
            RefreshExpiration = DateTimeOffset.UtcNow.AddDays(30),
        };

        public Task<AuthTokensResponse?> LoadAsync(CancellationToken ct) => Task.FromResult(_tokens);

        public Task SaveAsync(AuthTokensResponse tokens, CancellationToken ct)
        {
            _tokens = tokens;
            return Task.CompletedTask;
        }

        public Task ClearAsync(CancellationToken ct)
        {
            _tokens = null;
            return Task.CompletedTask;
        }
    }
}
