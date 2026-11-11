using DataGateWin.Services.Traffic;
using Xunit;

namespace DataGateWin.Tests;

public sealed class VpnAdapterNetworkInfoReaderTests
{
    [Fact]
    public void Xray_PicksItsTunnelInsteadOfLeftoverOpenVpn()
    {
        var openVpn = new VpnAdapterNetworkInfo("DataGate", "10.51.67.34", ["10.51.67.1"]);
        var xray = new VpnAdapterNetworkInfo("xray0", "198.18.0.1", ["10.51.119.1"]);
        Assert.Same(xray, VpnAdapterNetworkInfoReader.Select([openVpn, xray], "xray0", null));
    }

    [Fact]
    public void OpenVpn_ReadsDnsFromMatchingTunnel()
    {
        var tunnel = new VpnAdapterNetworkInfo("DataGate", "10.51.67.34", ["10.51.67.1"]);
        var result = VpnAdapterNetworkInfoReader.Select([tunnel], "DataGate", "10.51.67.34");
        Assert.Equal("10.51.67.1", Assert.Single(result!.DnsServers));
    }

    [Fact]
    public void MissingXrayAdapter_DoesNotShowOldOpenVpnIp()
    {
        var stale = new VpnAdapterNetworkInfo("DataGate", "10.51.67.34", ["10.51.67.1"]);
        Assert.Null(VpnAdapterNetworkInfoReader.Select([stale], "xray0", null));
    }

    [Fact]
    public void PhysicalAdapter_IsNeverUsedForVpnDetails()
    {
        var physical = new VpnAdapterNetworkInfo("Ethernet", "192.168.0.10", ["192.168.0.1"]);
        Assert.Null(VpnAdapterNetworkInfoReader.Select([physical], null, null));
    }
}
