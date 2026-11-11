using DataGateMonitor.SharedModels.DataGateMonitor.VpnServers.Responses;
using Xunit;

namespace DataGateWin.Tests;

public sealed class SharedModelsV3TypeProbe
{
    [Fact]
    public void SharedModels_exposes_v3_server_list_response_type()
    {
        var t = typeof(VpnServerWithStatusesV3Response);
        Assert.NotNull(t.GetProperty("VpnServerWithStatuses"));
    }
}
