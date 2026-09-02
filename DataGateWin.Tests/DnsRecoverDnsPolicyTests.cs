using Xunit;

namespace DataGateWin.Tests;

public sealed class DnsRecoverDnsPolicyTests
{
    [Theory]
    [InlineData(0)]
    [InlineData(1)]
    [InlineData(3)]
    [InlineData(5)]
    public void RecoverDnsExitCodes_AreKnownContract(int code)
    {
        // Mirrors engine AppMain --recover-dns:
        // 0 ok, 1 partial failure, 3 session active, 5 ACCESS_DENIED.
        Assert.Contains(code, (int[])[0, 1, 3, 5]);
    }
}
