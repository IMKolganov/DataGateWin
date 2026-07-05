using DataGateMonitor.SharedModels.DataGateMonitor.VpnServers.Responses;
using Newtonsoft.Json;
using DataGateMonitor.SharedModels.Responses;
using Xunit;

namespace DataGateWin.Tests;

public sealed class VpnServerV3ResponseProbe
{
    private const string Sample = """
        {
          "success": true,
          "data": {
            "userQuotaPlan": { "quotaPlanName": "Default" },
            "vpnServerWithStatuses": []
          }
        }
        """;

    [Fact]
    public void V3_response_deserializes_user_quota_plan_name()
    {
        var result = JsonConvert.DeserializeObject<ApiResponse<VpnServerWithStatusesV3Response>>(Sample);
        Assert.NotNull(result?.Data?.UserQuotaPlan);
        Assert.Equal("Default", result!.Data!.UserQuotaPlan!.QuotaPlanName);
    }
}
