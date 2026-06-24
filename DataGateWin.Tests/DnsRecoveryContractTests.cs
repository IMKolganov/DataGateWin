using DataGateWin.Installer;
using Xunit;

namespace DataGateWin.Tests;

public sealed class ArgParserContractTests
{
    [Fact]
    public void DnsRecoveryContract_MatchesEngineStartupSequence()
    {
        // Engine DnsStartupRecovery.cpp: NRPT delete_rules(0) then WinCmd("ipconfig /flushdns")
        Assert.Equal("ipconfig /flushdns", WindowsDnsRecovery.DnsFlushCommand);
        Assert.Equal("OpenVPNDNSRouting", WindowsDnsRecovery.OpenVpnNrptRulePrefix);
    }
}
