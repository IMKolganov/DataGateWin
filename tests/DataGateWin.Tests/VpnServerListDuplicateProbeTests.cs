using DataGateMonitor.SharedModels.DataGateMonitor.VpnServers.Dto;
using DataGateMonitor.SharedModels.DataGateMonitor.VpnServers.Responses;
using DataGateMonitor.SharedModels.Responses;
using DataGateWin.Services.VpnServers;
using Newtonsoft.Json;
using Xunit;

namespace DataGateWin.Tests;

public sealed class VpnServerListDuplicateProbeTests
{
    private const string DualKeyJson = """
        {
          "success": true,
          "data": {
            "vpnServerWithStatuses": [
              {
                "vpnServerResponses": {
                  "vpnServer": { "id": 69, "serverName": "Helsinki 3", "isEnableWss": true, "isOnline": true }
                },
                "countConnectedClients": 9
              }
            ],
            "openVpnServerWithStatuses": [
              {
                "openVpnServerResponses": {
                  "openVpnServer": { "id": 69, "serverName": "Helsinki 3", "isEnableWss": true, "isOnline": true }
                },
                "countConnectedClients": 9
              }
            ]
          }
        }
        """;

    [Fact]
    public void SharedModels_merges_dual_json_keys_into_duplicate_rows()
    {
        var raw = JsonConvert.DeserializeObject<ApiResponse<VpnServerWithStatusesV3Response>>(DualKeyJson);
        Assert.Equal(2, raw!.Data!.VpnServerWithStatuses!.Count);
    }

    [Fact]
    public void Deduper_collapses_dual_key_rows_by_server_id()
    {
        var raw = JsonConvert.DeserializeObject<ApiResponse<VpnServerWithStatusesV3Response>>(DualKeyJson);
        var deduped = VpnServerListDeduper.ByServerId(raw!.Data!.VpnServerWithStatuses);
        Assert.Single(deduped);
        Assert.Equal(69, deduped[0].VpnServerResponses!.VpnServer.Id);
        Assert.Equal(9, deduped[0].CountConnectedClients);
    }

    [Fact]
    public void Deduper_keeps_distinct_server_ids()
    {
        var rows = new List<VpnServerWithStatusV2Dto>
        {
            MakeRow(1, "A"),
            MakeRow(1, "A-dup"),
            MakeRow(2, "B"),
        };

        var deduped = VpnServerListDeduper.ByServerId(rows);
        Assert.Equal(2, deduped.Count);
        Assert.Equal("A", deduped[0].VpnServerResponses!.VpnServer.ServerName);
        Assert.Equal("B", deduped[1].VpnServerResponses!.VpnServer.ServerName);
    }

    private static VpnServerWithStatusV2Dto MakeRow(int id, string name)
    {
        var responsesType = typeof(VpnServerWithStatusV2Dto).GetProperty("VpnServerResponses")!.PropertyType;
        var responses = Activator.CreateInstance(responsesType)!;
        var server = Activator.CreateInstance(typeof(VpnServerV2Dto))!;
        typeof(VpnServerV2Dto).GetProperty("Id")!.SetValue(server, id);
        typeof(VpnServerV2Dto).GetProperty("ServerName")!.SetValue(server, name);
        typeof(VpnServerV2Dto).GetProperty("IsEnableWss")!.SetValue(server, true);
        responsesType.GetProperty("VpnServer")!.SetValue(responses, server);
        var row = Activator.CreateInstance(typeof(VpnServerWithStatusV2Dto))!;
        typeof(VpnServerWithStatusV2Dto).GetProperty("VpnServerResponses")!.SetValue(row, responses);
        return (VpnServerWithStatusV2Dto)row;
    }
}
