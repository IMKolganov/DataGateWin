using DataGateMonitor.SharedModels.DataGateMonitor.VpnServers.Dto;
using DataGateWin.Services.VpnServers;
using Xunit;

namespace DataGateWin.Tests;

public sealed class WssServerSelectorFilterTests
{
    [Fact]
    public void FilterWssEnabled_keeps_wss_rows_only()
    {
        var responsesType = typeof(VpnServerWithStatusV2Dto).GetProperty("VpnServerResponses")!.PropertyType;
        var rowType = typeof(VpnServerWithStatusV2Dto);
        var serverType = typeof(VpnServerV2Dto);

        var responses = Activator.CreateInstance(responsesType)!;
        var server = Activator.CreateInstance(serverType)!;
        serverType.GetProperty("Id")!.SetValue(server, 1);
        serverType.GetProperty("ServerName")!.SetValue(server, "Helsinki");
        serverType.GetProperty("IsEnableWss")!.SetValue(server, true);
        responsesType.GetProperty("VpnServer")!.SetValue(responses, server);

        var wssRow = Activator.CreateInstance(rowType)!;
        rowType.GetProperty("VpnServerResponses")!.SetValue(wssRow, responses);

        var xrayServer = Activator.CreateInstance(serverType)!;
        serverType.GetProperty("Id")!.SetValue(xrayServer, 2);
        serverType.GetProperty("ServerName")!.SetValue(xrayServer, "Norway xray");
        serverType.GetProperty("IsEnableWss")!.SetValue(xrayServer, false);
        var xrayResponses = Activator.CreateInstance(responsesType)!;
        responsesType.GetProperty("VpnServer")!.SetValue(xrayResponses, xrayServer);
        var xrayRow = Activator.CreateInstance(rowType)!;
        rowType.GetProperty("VpnServerResponses")!.SetValue(xrayRow, xrayResponses);

        var filtered = WssServerSelector.FilterWssEnabled(new[] { (VpnServerWithStatusV2Dto)wssRow, (VpnServerWithStatusV2Dto)xrayRow });

        Assert.Single(filtered);
        Assert.Equal(1, filtered[0].VpnServerResponses!.VpnServer.Id);
    }
}
