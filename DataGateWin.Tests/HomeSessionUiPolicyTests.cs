using DataGateMonitor.SharedModels.Enums;
using DataGateWin.Services.VpnServers;
using Xunit;

namespace DataGateWin.Tests;

public sealed class HomeSessionUiPolicyTests
{
    [Theory]
    [InlineData(true, false)]
    [InlineData(false, true)]
    public void ShouldClearSessionIdentity_OnlyWhenUserDoesNotWantVpn(bool desired, bool expectClear)
        => Assert.Equal(expectClear, HomeSessionUiPolicy.ShouldClearSessionIdentity(desired));

    [Fact]
    public void ComposeConnectedStatus_PrefersServerNameOverBarePhase()
    {
        var text = HomeSessionUiPolicy.ComposeConnectedStatus(
            serverName: "Helsinki 3",
            vpnIp: "10.8.0.2",
            engineState: "connected",
            lastStatusText: "Connected (connected)",
            lastWasConnected: true,
            connectedPlain: "Connected",
            connectedServerFmt: "Connected · {0}",
            connectedIpFmt: "Connected ({0})",
            connectedFmt: "Connected ({0})");

        Assert.Equal("Connected · Helsinki 3", text);
    }

    [Fact]
    public void ComposeConnectedStatus_DoesNotEmitConnectedConnected()
    {
        var text = HomeSessionUiPolicy.ComposeConnectedStatus(
            serverName: null,
            vpnIp: null,
            engineState: "connected",
            lastStatusText: null,
            lastWasConnected: false,
            connectedPlain: "Connected",
            connectedServerFmt: "Connected · {0}",
            connectedIpFmt: "Connected ({0})",
            connectedFmt: "Connected ({0})");

        Assert.Equal("Connected", text);
    }

    [Fact]
    public void ComposeConnectedStatus_KeepsLastRichStatusOverRawPhase()
    {
        var text = HomeSessionUiPolicy.ComposeConnectedStatus(
            serverName: null,
            vpnIp: null,
            engineState: "connected",
            lastStatusText: "Connected · NL-1",
            lastWasConnected: true,
            connectedPlain: "Connected",
            connectedServerFmt: "Connected · {0}",
            connectedIpFmt: "Connected ({0})",
            connectedFmt: "Connected ({0})");

        Assert.Equal("Connected · NL-1", text);
    }
}

public sealed class WssServerSelectorEligibleTests
{
    [Fact]
    public void FilterEligible_RequiresQuotaAccess_AndOpenVpnWss()
    {
        var ok = MakeRow(1, "A", VpnServerType.OpenVpn, wss: true, accessible: true);
        var noQuota = MakeRow(2, "B", VpnServerType.OpenVpn, wss: true, accessible: false);
        var xray = MakeRow(3, "C", VpnServerType.Xray, wss: true, accessible: true);

        var eligible = WssServerSelector.FilterEligible([ok, noQuota, xray]);
        Assert.Single(eligible);
        Assert.Equal(1, eligible[0].VpnServerResponses!.VpnServer.Id);
    }

    private static DataGateMonitor.SharedModels.DataGateMonitor.VpnServers.Dto.VpnServerWithStatusV2Dto MakeRow(
        int id,
        string name,
        VpnServerType type,
        bool wss,
        bool accessible)
    {
        var rowType = typeof(DataGateMonitor.SharedModels.DataGateMonitor.VpnServers.Dto.VpnServerWithStatusV2Dto);
        var responsesType = rowType.GetProperty("VpnServerResponses")!.PropertyType;
        var serverType = typeof(DataGateMonitor.SharedModels.DataGateMonitor.VpnServers.Dto.VpnServerV2Dto);

        var server = Activator.CreateInstance(serverType)!;
        serverType.GetProperty("Id")!.SetValue(server, id);
        serverType.GetProperty("ServerName")!.SetValue(server, name);
        serverType.GetProperty("ServerType")!.SetValue(server, type);
        serverType.GetProperty("IsEnableWss")!.SetValue(server, wss);
        serverType.GetProperty("IsAccessibleForUserQuotaPlan")!.SetValue(server, accessible);

        var responses = Activator.CreateInstance(responsesType)!;
        responsesType.GetProperty("VpnServer")!.SetValue(responses, server);
        var row = Activator.CreateInstance(rowType)!;
        rowType.GetProperty("VpnServerResponses")!.SetValue(row, responses);
        return (DataGateMonitor.SharedModels.DataGateMonitor.VpnServers.Dto.VpnServerWithStatusV2Dto)row;
    }
}
