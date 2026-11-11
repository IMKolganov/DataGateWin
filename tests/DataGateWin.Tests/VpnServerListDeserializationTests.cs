using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using DataGateMonitor.SharedModels.DataGateMonitor.VpnServers.Responses;
using DataGateMonitor.SharedModels.Responses;
using DataGateWin.Services.VpnServers;
using Xunit;

namespace DataGateWin.Tests;

public sealed class VpnServerListDeserializationTests
{
    private const string V3ApiJsonSample = """
        {
          "success": true,
          "data": {
            "userQuotaPlan": { "quotaPlanName": "Pro" },
            "vpnServerWithStatuses": [
              {
                "vpnServerResponses": {
                  "vpnServer": {
                    "id": 69,
                    "serverName": "Helsinki",
                    "isOnline": true,
                    "isEnableWss": true,
                    "isAccessibleForUserQuotaPlan": true,
                    "apiUrl": "https://s4.datagateapp.com/"
                  }
                },
                "countConnectedClients": 1
              },
              {
                "vpnServerResponses": {
                  "vpnServer": {
                    "id": 75,
                    "serverName": "Norway",
                    "isOnline": true,
                    "isEnableWss": true,
                    "isAccessibleForUserQuotaPlan": false,
                    "apiUrl": "https://s5.datagateapp.com/"
                  }
                },
                "countConnectedClients": 0
              }
            ]
          }
        }
        """;

    [Fact]
    public void Deserialize_v3_api_shape_populates_vpn_server_list()
    {
        var result = JsonConvert.DeserializeObject<ApiResponse<VpnServerWithStatusesV3Response>>(V3ApiJsonSample);

        Assert.True(result?.Success);
        Assert.NotNull(result?.Data);
        Assert.Equal(2, result!.Data!.VpnServerWithStatuses?.Count ?? 0);
    }

    [Fact]
    public void V3_api_shape_enables_wss_and_quota_filter()
    {
        var result = JsonConvert.DeserializeObject<ApiResponse<VpnServerWithStatusesV3Response>>(V3ApiJsonSample);
        var eligible = WssServerSelector.FilterEligible(result!.Data!.VpnServerWithStatuses);

        Assert.Single(eligible);
        Assert.Equal(69, eligible[0].VpnServerResponses!.VpnServer.Id);
        Assert.True(eligible[0].VpnServerResponses.VpnServer.IsEnableWss);
        Assert.True(eligible[0].VpnServerResponses.VpnServer.IsAccessibleForUserQuotaPlan);
    }

    [Fact]
    public void Legacy_v1_json_keys_still_deserialize_via_shared_models_aliases()
    {
        const string legacyJson = """
            {
              "success": true,
              "data": {
                "openVpnServerWithStatuses": [
                  {
                    "openVpnServerResponses": {
                      "openVpnServer": {
                        "id": 69,
                        "serverName": "Helsinki",
                        "isOnline": true,
                        "isEnableWss": true,
                        "apiUrl": "https://s4.datagateapp.com/"
                      }
                    },
                    "countConnectedClients": 1
                  }
                ]
              }
            }
            """;

        var result = JsonConvert.DeserializeObject<ApiResponse<VpnServerWithStatusesV3Response>>(legacyJson);

        Assert.True(result?.Success);
        Assert.Single(result!.Data!.VpnServerWithStatuses!);
        Assert.Equal(69, result.Data.VpnServerWithStatuses[0].VpnServerResponses.VpnServer.Id);
    }

    [Fact]
    public void JObject_probe_shows_v3_root_key()
    {
        var root = JObject.Parse(V3ApiJsonSample);
        var data = root["data"] as JObject;
        Assert.NotNull(data);
        Assert.True(data!.ContainsKey("vpnServerWithStatuses"));
    }
}
