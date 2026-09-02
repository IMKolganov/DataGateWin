using DataGateWin.Installer;
using Microsoft.Win32;
using Xunit;

namespace DataGateWin.Tests;

public sealed class DnsRecoveryContractTests
{
    [Fact]
    public void DnsRecoveryContract_MatchesEngineStartupSequence()
    {
        // Engine DnsStartupRecovery.cpp order:
        // NRPT → SearchList → Dnscache PARAMCHANGE → ipconfig /flushdns
        Assert.Equal("ipconfig /flushdns", WindowsDnsRecovery.DnsFlushCommand);
        Assert.Equal("OpenVPNDNSRouting", WindowsDnsRecovery.OpenVpnNrptRulePrefix);
        Assert.Equal(
            ["remove_nrpt", "restore_search_list", "signal_dnscache", "flush_dns"],
            WindowsDnsRecovery.RecoveryStepOrder);
    }

    [Fact]
    public void NrptRegistryViews_IncludeBothWow64Views()
    {
        Assert.Contains(RegistryView.Registry64, WindowsDnsRecovery.NrptRegistryViews);
        Assert.Contains(RegistryView.Registry32, WindowsDnsRecovery.NrptRegistryViews);
    }
}
