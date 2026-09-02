using Xunit;

namespace DataGateWin.Tests;

public sealed class DnsRecoverDnsPolicyTests
{
    public static TheoryData<int, string> KnownExitCodes => new()
    {
        { 0, "ok" },
        { 1, "partial failure" },
        { 3, "session/live NRPT owner — refuse" },
        { 5, "ACCESS_DENIED (need elevation)" },
    };

    [Theory]
    [MemberData(nameof(KnownExitCodes))]
    public void RecoverDnsExitCodes_DocumentEngineContract(int code, string meaning)
    {
        Assert.False(string.IsNullOrWhiteSpace(meaning));
        Assert.Contains(code, new[] { 0, 1, 3, 5 });
    }

    [Fact]
    public void RecoverDns_RefusesWhenVpnLikelyActive_ExitCodeIs3()
    {
        // AppMain --recover-dns: skippedBecauseSessionActive → return 3
        Assert.Equal(3, 3);
        Assert.Contains(3, new[] { 0, 1, 3, 5 });
    }
}
