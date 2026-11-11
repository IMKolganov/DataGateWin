using DataGateWin.Services.VpnServers;
using Xunit;

namespace DataGateWin.Tests;

public sealed class RdpPeerCidrsTests
{
    [Fact]
    public void CollectEstablishedPeerCidrs_DoesNotThrow()
    {
        var peers = RdpPeerCidrs.CollectEstablishedPeerCidrs();
        Assert.NotNull(peers);
        foreach (var cidr in peers)
        {
            Assert.False(string.IsNullOrWhiteSpace(cidr));
            Assert.Contains('/', cidr);
        }
    }
}
