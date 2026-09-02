using DataGateMonitor.SharedModels.DataGateMonitor.VpnServers.Dto;
using DataGateWin.Services.VpnServers;
using Xunit;

namespace DataGateWin.Tests;

public sealed class VpnConnectionSessionInfoFactoryTests
{
    [Fact]
    public void FromStatusRow_MapsServerNameAndRemoteIp()
    {
        var row = BuildRow(serverId: 7, serverName: "NL-1", remoteIp: " 5.22.212.200 ");
        var info = VpnConnectionSessionInfoFactory.FromStatusRow(row);

        Assert.Equal(7, info.ServerId);
        Assert.Equal("NL-1", info.ServerName);
        Assert.Equal("5.22.212.200", info.ExternalIp);
        Assert.True(info.HasIdentity);
    }

    [Fact]
    public void FromStatusRow_TreatsDashRemoteAsMissing()
    {
        var row = BuildRow(serverId: 1, serverName: "X", remoteIp: "-");
        var info = VpnConnectionSessionInfoFactory.FromStatusRow(row);
        Assert.Null(info.ExternalIp);
    }

    private static VpnServerWithStatusV2Dto BuildRow(int serverId, string serverName, string? remoteIp)
    {
        // Prefer JSON round-trip so we stay resilient to DTO ctor churn.
        var json = $$"""
            {
              "vpnServerResponses": {
                "vpnServer": { "id": {{serverId}}, "serverName": "{{serverName}}", "isEnableWss": true, "isOnline": true }
              },
              "vpnServerStatusLogResponse": { "serverRemoteIp": {{(remoteIp is null ? "null" : $"\"{remoteIp}\"")}} },
              "countConnectedClients": 0
            }
            """;
        var row = Newtonsoft.Json.JsonConvert.DeserializeObject<VpnServerWithStatusV2Dto>(json);
        Assert.NotNull(row);
        return row!;
    }
}
