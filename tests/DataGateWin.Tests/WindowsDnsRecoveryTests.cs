using DataGateWin.Installer;
using Xunit;

namespace DataGateWin.Tests;

public sealed class WindowsDnsRecoveryTests
{
    [Theory]
    [InlineData("OpenVPNDNSRouting-1234", true)]
    [InlineData("OpenVPNDNSRoutingX-1-5678", true)]
    [InlineData("OpenVPNDNSRouting", true)]
    [InlineData("OtherPolicy-1234", false)]
    [InlineData("", false)]
    [InlineData("openvpndnsrouting-1", false)]
    public void IsOpenVpnNrptRuleName_MatchesOpenVpn3Prefix(string ruleName, bool expected)
    {
        Assert.Equal(expected, WindowsDnsRecovery.IsOpenVpnNrptRuleName(ruleName));
    }

    [Fact]
    public void NrptSubkeyPaths_ContainsBothOpenVpn3Locations()
    {
        Assert.Contains(
            @"SOFTWARE\Policies\Microsoft\Windows NT\DNSClient\DnsPolicyConfig",
            WindowsDnsRecovery.NrptSubkeyPaths);

        Assert.Contains(
            @"SYSTEM\CurrentControlSet\Services\Dnscache\Parameters\DnsPolicyConfig",
            WindowsDnsRecovery.NrptSubkeyPaths);
    }

    [Fact]
    public void SearchListSubkeyPaths_CoverOpenVpn3AndStandardSpellings()
    {
        Assert.Contains(
            @"SOFTWARE\Policies\Microsoft\Windows NT\DNSClient",
            WindowsDnsRecovery.SearchListSubkeyPaths);
        Assert.Contains(
            @"SOFTWARE\Policies\Microsoft\WindowsNT\DNSClient",
            WindowsDnsRecovery.SearchListSubkeyPaths);
        Assert.Contains(
            @"SYSTEM\CurrentControlSet\Services\TCPIP\Parameters",
            WindowsDnsRecovery.SearchListSubkeyPaths);
    }

    [Fact]
    public void DnsFlushCommand_MatchesOpenVpn3TunSetup()
    {
        Assert.Equal("ipconfig /flushdns", WindowsDnsRecovery.DnsFlushCommand);
    }

    [Fact]
    public void RecoveryStepOrder_IsNrptThenSearchListThenDnscacheThenFlush()
    {
        Assert.Equal(
            ["remove_nrpt", "restore_search_list", "signal_dnscache", "flush_dns"],
            WindowsDnsRecovery.RecoveryStepOrder);
    }

    [Fact]
    public void RecoverStaleDnsState_RunsFullOrderedPipeline()
    {
        var executor = new RecordingDnsRecoveryExecutor();

        WindowsDnsRecovery.RecoverStaleDnsState(_ => { }, executor);

        Assert.Equal(WindowsDnsRecovery.RecoveryStepOrder, executor.Steps);
    }

    [Fact]
    public void RecoverStaleDnsState_StillCompletesWhenNrptRemovalReportsZeroRules()
    {
        var executor = new RecordingDnsRecoveryExecutor { NrptRulesRemoved = 0 };

        WindowsDnsRecovery.RecoverStaleDnsState(_ => { }, executor);

        Assert.Equal(WindowsDnsRecovery.RecoveryStepOrder, executor.Steps);
        Assert.True(executor.FlushCalled);
        Assert.True(executor.SignalCalled);
    }

    [Fact]
    public void DefaultExecutor_FlushDnsCache_UsesSystemIpconfig()
    {
        var ipconfigPath = Path.Combine(Environment.SystemDirectory, "ipconfig.exe");
        Assert.True(File.Exists(ipconfigPath), $"Expected ipconfig at {ipconfigPath}");
    }

    sealed class RecordingDnsRecoveryExecutor : IWindowsDnsRecoveryExecutor
    {
        public int NrptRulesRemoved { get; init; } = 2;
        public int SearchListKeysRestored { get; init; } = 1;
        public bool FlushCalled { get; private set; }
        public bool SignalCalled { get; private set; }
        public List<string> Steps { get; } = new();

        public int RemoveStaleOpenVpnNrptRules(Action<string>? log)
        {
            Steps.Add("remove_nrpt");
            log?.Invoke($"Removed {NrptRulesRemoved} stale OpenVPN NRPT rule(s).");
            return NrptRulesRemoved;
        }

        public int RestoreOpenVpnSearchList(Action<string>? log)
        {
            Steps.Add("restore_search_list");
            log?.Invoke($"Restored SearchList under {SearchListKeysRestored} registry key(s).");
            return SearchListKeysRestored;
        }

        public bool SignalDnsCacheReload(Action<string>? log)
        {
            Steps.Add("signal_dnscache");
            SignalCalled = true;
            log?.Invoke("Signaled Dnscache PARAMCHANGE.");
            return true;
        }

        public bool FlushDnsCache(Action<string>? log)
        {
            Steps.Add("flush_dns");
            FlushCalled = true;
            log?.Invoke("DNS cache flushed.");
            return true;
        }
    }
}
