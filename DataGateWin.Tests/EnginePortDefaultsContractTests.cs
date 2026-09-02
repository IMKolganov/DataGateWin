using DataGateWin.Services.Ipc;
using Xunit;

namespace DataGateWin.Tests;

public sealed class EnginePortDefaultsContractTests
{
    [Fact]
    public void UiDefaults_MatchEngineHeaderContract()
    {
        Assert.Equal(1194, EnginePortDefaults.OpenVpnDefaultRemotePort);
        Assert.Equal(18080, EnginePortDefaults.LocalBridgeDefaultListenPort);
        Assert.Equal(16, EnginePortDefaults.LocalBridgeListenPortAttempts);

        Assert.Equal(
            EnginePortDefaults.OpenVpnDefaultRemotePort,
            EnginePortDefaultsContract.OpenVpnDefaultRemotePort);
        Assert.Equal(
            EnginePortDefaults.LocalBridgeDefaultListenPort,
            EnginePortDefaultsContract.LocalBridgeDefaultListenPort);
        Assert.Equal(
            EnginePortDefaults.LocalBridgeListenPortAttempts,
            EnginePortDefaultsContract.LocalBridgeListenPortAttempts);
    }
}
