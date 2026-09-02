using DataGateWin.Installer;
using Xunit;

namespace DataGateWin.Tests;

public sealed class SearchListRestoreTests
{
    [Theory]
    [InlineData(null, null, null)]
    [InlineData("corp.local,lan", null, "corp.local,lan")]
    [InlineData("corp.local", "corp.local,vpn.example", "corp.local")]
    [InlineData(null, "vpn.example", "")]
    public void ResolveRestoredSearchList_MatchesOpenVpn3ResetSemantics(
        string? original,
        string? initial,
        string? expected)
    {
        Assert.Equal(expected, WindowsDnsRecovery.ResolveRestoredSearchList(original, initial));
    }
}
