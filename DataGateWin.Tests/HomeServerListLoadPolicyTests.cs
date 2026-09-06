using DataGateWin.Services.VpnServers;
using Xunit;

namespace DataGateWin.Tests;

public sealed class HomeServerListLoadPolicyTests
{
    [Theory]
    [InlineData(false, true, true, false, true)]
    [InlineData(true, true, true, false, false)]  // suppressed restore
    [InlineData(false, false, true, false, false)] // not loaded
    [InlineData(false, true, false, false, false)] // auto mode
    [InlineData(false, true, true, true, false)]   // cache warm — no duplicate
    public void ShouldFetchOnManualModeSelected_Cases(
        bool suppress, bool loaded, bool manual, bool hasCache, bool expected)
    {
        Assert.Equal(
            expected,
            HomeServerListLoadPolicy.ShouldFetchOnManualModeSelected(suppress, loaded, manual, hasCache));
    }

    [Theory]
    [InlineData(true, true, false, false, true)]
    [InlineData(true, true, false, true, false)]
    [InlineData(false, true, false, false, false)]
    [InlineData(true, false, false, false, false)]
    [InlineData(true, true, true, false, false)]
    public void ShouldFetchOnBecameVisible_Cases(
        bool visible, bool loaded, bool suppress, bool hasCache, bool expected)
    {
        Assert.Equal(
            expected,
            HomeServerListLoadPolicy.ShouldFetchOnBecameVisible(visible, loaded, suppress, hasCache));
    }
}
