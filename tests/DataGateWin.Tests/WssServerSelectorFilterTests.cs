using DataGateMonitor.SharedModels.DataGateMonitor.VpnServers.Dto;
using DataGateMonitor.SharedModels.Enums;
using DataGateWin.Services.VpnServers;
using Xunit;

namespace DataGateWin.Tests;

public sealed class WssServerSelectorFilterTests
{
    [Fact]
    public void FilterWssEnabled_keeps_openvpn_with_or_without_wss_and_xray()
    {
        var openVpnWss = MakeRow(1, "Helsinki", VpnServerType.OpenVpn, wss: true);
        var xray = MakeRow(2, "Norway xray", VpnServerType.Xray, wss: false);
        var xrayWithWssFlag = MakeRow(3, "Xray spoof WSS", VpnServerType.Xray, wss: true);
        var openVpnNoWss = MakeRow(4, "Cyprus", VpnServerType.OpenVpn, wss: false);

        var filtered = WssServerSelector.FilterWssEnabled(
            [openVpnWss, xray, xrayWithWssFlag, openVpnNoWss]);

        Assert.Equal(4, filtered.Count);
        Assert.Contains(filtered, r => r.VpnServerResponses!.VpnServer.Id == 1);
        Assert.Contains(filtered, r => r.VpnServerResponses!.VpnServer.Id == 2);
        Assert.Contains(filtered, r => r.VpnServerResponses!.VpnServer.Id == 3);
        Assert.Contains(filtered, r => r.VpnServerResponses!.VpnServer.Id == 4);
    }

    [Fact]
    public void IsWindowsSupported_accepts_xray_and_all_openvpn()
    {
        var xray = MakeServer(VpnServerType.Xray, wss: true);
        var openVpn = MakeServer(VpnServerType.OpenVpn, wss: true);
        var openVpnNoWss = MakeServer(VpnServerType.OpenVpn, wss: false);
        Assert.True(WssServerSelector.IsWindowsSupported(xray));
        Assert.True(WssServerSelector.IsXrayWindowsSupported(xray));
        Assert.True(WssServerSelector.IsWindowsSupported(openVpn));
        Assert.True(WssServerSelector.IsWindowsSupported(openVpnNoWss));
        Assert.True(WssServerSelector.IsOpenVpnDirect(openVpnNoWss));
        Assert.False(WssServerSelector.IsOpenVpnDirect(openVpn));
    }

    private static VpnServerWithStatusV2Dto MakeRow(
        int id,
        string name,
        VpnServerType type,
        bool wss)
    {
        var responsesType = typeof(VpnServerWithStatusV2Dto).GetProperty("VpnServerResponses")!.PropertyType;
        var responses = Activator.CreateInstance(responsesType)!;
        var server = MakeServer(type, wss);
        typeof(VpnServerV2Dto).GetProperty("Id")!.SetValue(server, id);
        typeof(VpnServerV2Dto).GetProperty("ServerName")!.SetValue(server, name);
        responsesType.GetProperty("VpnServer")!.SetValue(responses, server);
        var row = Activator.CreateInstance(typeof(VpnServerWithStatusV2Dto))!;
        typeof(VpnServerWithStatusV2Dto).GetProperty("VpnServerResponses")!.SetValue(row, responses);
        return (VpnServerWithStatusV2Dto)row;
    }

    private static VpnServerV2Dto MakeServer(VpnServerType type, bool wss)
    {
        var server = Activator.CreateInstance(typeof(VpnServerV2Dto))!;
        typeof(VpnServerV2Dto).GetProperty("ServerType")!.SetValue(server, type);
        typeof(VpnServerV2Dto).GetProperty("IsEnableWss")!.SetValue(server, wss);
        return (VpnServerV2Dto)server;
    }
}
