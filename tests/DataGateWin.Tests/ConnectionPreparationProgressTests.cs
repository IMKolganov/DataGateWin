using System.Net;
using System.Text;
using DataGateMonitor.SharedModels.DataGateMonitor.Auth.Responses;
using DataGateMonitor.SharedModels.Enums;
using DataGateWin.Services.Auth;
using DataGateWin.Services.Auth.Interfaces;
using DataGateWin.Services.Installation;
using DataGateWin.Services.IpList;
using DataGateWin.Services.Ipc;
using DataGateWin.Services.OpenVpnFiles;
using DataGateWin.Services.VpnServers;
using DataGateWin.Services.Xray;
using Newtonsoft.Json;
using Xunit;

namespace DataGateWin.Tests;

public sealed class ConnectionPreparationProgressTests
{
    [Theory]
    [InlineData(VpnServerType.OpenVpn)]
    [InlineData(VpnServerType.Xray)]
    public async Task DownloadTimeout_RetainsSelectedServer_AndDoesNotReportSuccess(VpnServerType protocol)
    {
        using var fixture = new Fixture(protocol);
        var builder = await fixture.CreateBuilderAsync();
        var stages = new List<(ConnectionPreparationStage Stage, int? Server)>();
        builder.ProgressChanged += (stage, selection) => stages.Add((stage, selection?.ServerId));

        await Assert.ThrowsAsync<TimeoutException>(() => builder.BuildAsync(default));

        Assert.Equal(new[] { ConnectionPreparationStage.Selecting, ConnectionPreparationStage.Selected,
            ConnectionPreparationStage.Authorizing, ConnectionPreparationStage.Downloading }, stages.Select(x => x.Stage));
        Assert.Null(stages[0].Server);
        Assert.All(stages.Skip(1), stage => Assert.Equal(7, stage.Server));
        Assert.Equal(7, builder.LastSelection!.ServerId);
        Assert.Contains("Frankfurt", builder.LastSelection.ServerName);
        Assert.Equal(1, fixture.DownloadCalls);
    }

    [Fact]
    public async Task NextAttempt_ClearsOldServer_BeforeCatalogFailure()
    {
        using var fixture = new Fixture(VpnServerType.OpenVpn);
        var builder = await fixture.CreateBuilderAsync();
        await Assert.ThrowsAsync<TimeoutException>(() => builder.BuildAsync(default));
        Assert.NotNull(builder.LastSelection);
        fixture.FailCatalog = true;
        var events = new List<VpnConnectionSessionInfo?>();
        builder.ProgressChanged += (_, selection) => events.Add(selection);
        await Assert.ThrowsAsync<HttpRequestException>(() => builder.BuildAsync(default));
        Assert.Null(builder.LastSelection);
        Assert.Null(Assert.Single(events));
    }

    [Fact]
    public async Task EmptyCatalog_ReportsOnlySelection_WithoutDownloading()
    {
        using var fixture = new Fixture(VpnServerType.OpenVpn) { EmptyCatalog = true };
        var builder = await fixture.CreateBuilderAsync();
        var events = new List<ConnectionPreparationStage>();
        builder.ProgressChanged += (stage, _) => events.Add(stage);
        Assert.Null(await builder.BuildAsync(default));
        Assert.Equal(new[] { ConnectionPreparationStage.Selecting }, events);
        Assert.Null(builder.LastSelection);
        Assert.Equal(0, fixture.DownloadCalls);
    }

    [Fact]
    public async Task Cancellation_IsNotReportedAsDownloadSuccess()
    {
        using var fixture = new Fixture(VpnServerType.OpenVpn) { CancelDownload = true };
        var builder = await fixture.CreateBuilderAsync();
        var events = new List<ConnectionPreparationStage>();
        builder.ProgressChanged += (stage, _) => events.Add(stage);
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => builder.BuildAsync(default));
        Assert.DoesNotContain(ConnectionPreparationStage.Downloaded, events);
        Assert.DoesNotContain(ConnectionPreparationStage.Ready, events);
        Assert.Equal(7, builder.LastSelection!.ServerId);
    }

    private sealed class Fixture(VpnServerType protocol) : HttpMessageHandler
    {
        private HttpClient? _http;
        public int DownloadCalls;
        public bool FailCatalog, EmptyCatalog, CancelDownload;
        public async Task<StartSessionPayloadBuilder> CreateBuilderAsync()
        {
            _http = new HttpClient(this, false) { BaseAddress = new Uri("https://vpn.test/") };
            var session = new AuthSession(new AuthApiClient(_http), new NoopTokens(), "test-device", "test");
            var payload = Convert.ToBase64String(Encoding.UTF8.GetBytes("{\"externalId\":\"test-user\"}")).TrimEnd('=');
            await session.SetFromLoginAsync(new GoogleLoginResponse
            {
                Token = "e30." + payload + ".test", Expiration = DateTimeOffset.UtcNow.AddHours(1),
            }, default);
            return new StartSessionPayloadBuilder(new WssServerSelector(new OpenVpnServersApiClient(_http)),
                new InstallationIdService(), new OpenVpnFilesApiClient(_http), new XrayClientLinksApiClient(_http),
                session, new IpListRoutesRepository(), installationIdProvider: () => "test-installation");
        }

        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken ct)
        {
            if (request.RequestUri!.AbsolutePath.Contains("get-all-with-status"))
            {
                if (FailCatalog) throw new HttpRequestException("catalog offline");
                var row = new
                {
                    vpnServerResponses = new { vpnServer = new { id = 7, serverName = "Frankfurt tcp 10",
                        serverType = protocol, isOnline = true, isEnableWss = true,
                        isAccessibleForUserQuotaPlan = true, apiUrl = "https://edge.test/" } },
                    countConnectedClients = 1,
                };
                return Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK)
                {
                    Content = new StringContent(JsonConvert.SerializeObject(new
                    { success = true, data = new { vpnServerWithStatuses = EmptyCatalog ? Array.Empty<object>() : new object[] { row } } })),
                });
            }
            DownloadCalls++;
            if (CancelDownload) throw new OperationCanceledException("cancelled");
            throw new TimeoutException("test download timeout");
        }
        protected override void Dispose(bool disposing) { if (disposing) _http?.Dispose(); base.Dispose(disposing); }
    }

    private sealed class NoopTokens : ITokenStore
    {
        public Task<AuthTokensResponse?> LoadAsync(CancellationToken ct) => Task.FromResult<AuthTokensResponse?>(null);
        public Task SaveAsync(AuthTokensResponse tokens, CancellationToken ct) => Task.CompletedTask;
        public Task ClearAsync(CancellationToken ct) => Task.CompletedTask;
    }
}
