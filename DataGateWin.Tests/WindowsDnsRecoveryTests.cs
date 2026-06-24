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
    public void DnsFlushCommand_MatchesOpenVpn3TunSetup()
    {
        Assert.Equal("ipconfig /flushdns", WindowsDnsRecovery.DnsFlushCommand);
    }

    [Fact]
    public void RecoverStaleDnsState_RemovesNrptBeforeFlushingCache()
    {
        var executor = new RecordingDnsRecoveryExecutor();

        WindowsDnsRecovery.RecoverStaleDnsState(_ => { }, executor);

        Assert.Equal(["remove_nrpt", "flush_dns"], executor.Steps);
    }

    [Fact]
    public void RecoverStaleDnsState_StillFlushesWhenNrptRemovalReportsZeroRules()
    {
        var executor = new RecordingDnsRecoveryExecutor { NrptRulesRemoved = 0 };

        WindowsDnsRecovery.RecoverStaleDnsState(_ => { }, executor);

        Assert.Equal(["remove_nrpt", "flush_dns"], executor.Steps);
        Assert.True(executor.FlushCalled);
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
        public bool FlushCalled { get; private set; }
        public List<string> Steps { get; } = new();

        public int RemoveStaleOpenVpnNrptRules(Action<string>? log)
        {
            Steps.Add("remove_nrpt");
            log?.Invoke($"Removed {NrptRulesRemoved} stale OpenVPN NRPT rule(s).");
            return NrptRulesRemoved;
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
