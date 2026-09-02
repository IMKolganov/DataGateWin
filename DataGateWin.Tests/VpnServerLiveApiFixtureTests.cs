using DataGateMonitor.SharedModels.DataGateMonitor.VpnServers.Responses;
using DataGateMonitor.SharedModels.Responses;
using DataGateWin.Services.VpnServers;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using Xunit;

namespace DataGateWin.Tests;

public sealed class VpnServerLiveApiFixtureTests
{
    private static string LoadLiveFixture()
    {
        var path = Path.Combine(AppContext.BaseDirectory, "..", "..", "..", "TestData", "v3-live-response.json");
        path = Path.GetFullPath(path);
        Assert.True(File.Exists(path), $"Missing fixture: {path}");
        return File.ReadAllText(path);
    }

    [Fact]
    public void Live_v3_fixture_has_dual_server_arrays()
    {
        var root = JObject.Parse(LoadLiveFixture());
        var data = root["data"] as JObject;
        Assert.NotNull(data);
        Assert.True(data!.ContainsKey("vpnServerWithStatuses"));
        Assert.True(data.ContainsKey("openVpnServerWithStatuses"));
        Assert.Equal(data["vpnServerWithStatuses"]!.Count(), data["openVpnServerWithStatuses"]!.Count());
    }

    [Fact]
    public void Live_v3_fixture_deserializes_to_double_rows_without_dedupe()
    {
        var raw = JsonConvert.DeserializeObject<ApiResponse<VpnServerWithStatusesV3Response>>(LoadLiveFixture());
        Assert.True(raw?.Success);
        Assert.Equal(10, raw!.Data!.VpnServerWithStatuses!.Count);
    }

    [Fact]
    public void Live_v3_fixture_after_dedupe_matches_unique_server_count()
    {
        var raw = JsonConvert.DeserializeObject<ApiResponse<VpnServerWithStatusesV3Response>>(LoadLiveFixture());
        var deduped = VpnServerListDeduper.ByServerId(raw!.Data!.VpnServerWithStatuses);
        Assert.Equal(5, deduped.Count);

        var wss = WssServerSelector.FilterWssEnabled(deduped);
        Assert.Equal(3, wss.Count);
        Assert.All(wss, x => Assert.Equal(
            DataGateMonitor.SharedModels.Enums.VpnServerType.OpenVpn,
            x.VpnServerResponses!.VpnServer.ServerType));
        Assert.DoesNotContain(wss, x => x.VpnServerResponses!.VpnServer.Id == 76); // Norway xray
        Assert.Equal(3, wss.Select(x => x.VpnServerResponses!.VpnServer.Id).Distinct().Count());
    }

    [Fact]
    public void Live_v3_fixture_includes_default_plan()
    {
        var raw = JsonConvert.DeserializeObject<ApiResponse<VpnServerWithStatusesV3Response>>(LoadLiveFixture());
        Assert.Equal("Default", raw!.Data!.UserQuotaPlan!.QuotaPlanName);
    }
}
