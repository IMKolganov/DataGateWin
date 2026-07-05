using DataGateMonitor.SharedModels.DataGateMonitor.VpnServers.Dto;
using Xunit;

namespace DataGateWin.Tests;

public sealed class SharedModelsV2DtoProbe
{
    [Fact]
    public void VpnServerV2Dto_has_fields_used_by_windows_client()
    {
        var props = typeof(VpnServerV2Dto).GetProperties().Select(p => p.Name).ToHashSet(StringComparer.OrdinalIgnoreCase);
        foreach (var name in new[] { "Id", "ServerName", "IsOnline", "IsEnableWss", "ApiUrl", "IsAccessibleForUserQuotaPlan" })
            Assert.Contains(name, props);
    }

    [Fact]
    public void VpnServerWithStatusV2Dto_nested_server_type()
    {
        var responsesProp = typeof(VpnServerWithStatusV2Dto).GetProperty("VpnServerResponses");
        Assert.NotNull(responsesProp);
        var serverProp = responsesProp!.PropertyType.GetProperty("VpnServer");
        Assert.NotNull(serverProp);
        Assert.Equal(typeof(VpnServerV2Dto), serverProp!.PropertyType);
    }
}
