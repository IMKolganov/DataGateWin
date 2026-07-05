using DataGateMonitor.SharedModels.DataGateMonitor.VpnServers.Responses;
using Newtonsoft.Json;
using Xunit;

namespace DataGateWin.Tests;

public sealed class SharedModelsJsonContractTests
{
    [Fact]
    public void VpnServerWithStatusesResponse_property_has_no_legacy_json_alias()
    {
        var prop = typeof(VpnServerWithStatusesResponse).GetProperty(nameof(VpnServerWithStatusesResponse.VpnServerWithStatuses));
        Assert.NotNull(prop);

        var jsonName = prop!.GetCustomAttributes(typeof(JsonPropertyAttribute), inherit: false)
            .Cast<JsonPropertyAttribute>()
            .Select(a => a.PropertyName)
            .FirstOrDefault();

        Assert.Null(jsonName);
        Assert.Equal("VpnServerWithStatuses", prop!.Name);
    }
}
