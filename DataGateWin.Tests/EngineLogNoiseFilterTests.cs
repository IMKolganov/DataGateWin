using DataGateWin.Services.Ipc;
using DataGateWin.Services.IpList;
using Xunit;

namespace DataGateWin.Tests;

public sealed class EngineLogNoiseFilterTests
{
    [Fact]
    public void Coalesces_IpHelper_Route_Spam_Into_One_Summary()
    {
        var f = new EngineLogNoiseFilter(TimeSpan.FromSeconds(10));

        Assert.Null(f.Filter("IPHelper: add route 1.2.3.0/24 5 192.168.0.1 metric=-1"));
        Assert.Null(f.Filter("cannot modify route: error 5010"));
        Assert.Null(f.Filter("IPHelper: add route 5.6.7.0/24 5 192.168.0.1 metric=-1"));
        Assert.Null(f.Filter("cannot modify route: error 5010"));

        var next = f.Filter("[ovpn] Connected via wintun");
        Assert.NotNull(next);
        Assert.Contains("IP-list routes: attempted=4", next, StringComparison.Ordinal);
        Assert.Contains("already_exist(5010)=2", next, StringComparison.Ordinal);
        Assert.Contains("[ovpn] Connected via wintun", next, StringComparison.Ordinal);
    }

    [Fact]
    public void Drops_Consecutive_Duplicate_Lines()
    {
        var f = new EngineLogNoiseFilter();
        Assert.Equal("hello", f.Filter("hello"));
        Assert.Null(f.Filter("hello"));
        Assert.Equal("world", f.Filter("world"));
    }

    [Fact]
    public void RateLimits_WssBridge_Udp_Stats()
    {
        var f = new EngineLogNoiseFilter(TimeSpan.FromHours(1));
        Assert.Equal("[wss-bridge] udp stats a", f.Filter("[wss-bridge] udp stats a"));
        Assert.Null(f.Filter("[wss-bridge] udp stats b"));
        Assert.Equal("other", f.Filter("other"));
    }

    [Fact]
    public void IsRouteNoise_Detects_OpenVpn_AlreadyExists()
    {
        Assert.True(EngineLogNoiseFilter.IsRouteNoise(
            "ROUTE: route addition failed using CreateIpForwardEntry: The object already exists. [status=5010 if_index=5]",
            out var fail,
            out var is5010));
        Assert.True(fail);
        Assert.True(is5010);
    }

    [Fact]
    public void Flush_Emits_Pending_Summary()
    {
        var f = new EngineLogNoiseFilter();
        Assert.Null(f.Filter("IPHelper: add route x"));
        Assert.Null(f.Filter("cannot modify route: error 5010"));
        var summary = f.Flush();
        Assert.NotNull(summary);
        Assert.Contains("attempted=2", summary, StringComparison.Ordinal);
        Assert.Null(f.Flush());
    }
}

public sealed class IpListRouteConfigWindowsLimitTests
{
    [Fact]
    public void Default_And_Max_Are_Potato_Safe()
    {
        Assert.Equal(200, IpListRouteConfig.DefaultAndroid12OvpnRouteLimit);
        Assert.Equal(400, IpListRouteConfig.MaxAndroid12OvpnRouteLimit);
        Assert.True(IpListRouteConfig.DefaultAndroid12OvpnRouteLimit <= 250);
    }

    [Fact]
    public void Sanitize_Clamps_Legacy_3000_Settings()
    {
        Assert.Equal(400, IpListRouteConfig.SanitizeAndroid12OvpnRouteLimit(3000));
        Assert.Equal(400, IpListRouteConfig.SanitizeAndroid12OvpnRouteLimit(800));
        Assert.Equal(50, IpListRouteConfig.SanitizeAndroid12OvpnRouteLimit(10));
        Assert.Equal(200, IpListRouteConfig.SanitizeAndroid12OvpnRouteLimit(200));
    }

    [Fact]
    public void SelectAndroid12OvpnRoutes_Respects_Limit_And_Prefers_Broader()
    {
        var routes = Enumerable.Range(0, 80)
            .Select(i => (IpCidrRoute)new Ipv4CidrRoute(
                $"{i}.0.0.0",
                i < 40 ? "255.0.0.0" : "255.255.255.0",
                i < 40 ? 8 : 24))
            .ToList();

        var selected = IpListRouteConfig.SelectAndroid12OvpnRoutes(routes, limit: 50);
        Assert.Equal(50, selected.Count);
        Assert.All(selected.Take(40), r => Assert.Equal(8, r.PrefixLength)); // broadest first
    }

    [Fact]
    public void PrepareConnectionRoutes_Windows_Appends_Limited_Bypass_Lines()
    {
        var routes = Enumerable.Range(0, 80)
            .Select(i => (IpCidrRoute)new Ipv4CidrRoute($"{i}.0.0.0", "255.0.0.0", 8))
            .ToList();

        var plan = IpListRouteConfig.PrepareConnectionRoutes(
            "client\ndev tun\n",
            routes,
            IpListCoverageMode.Full,
            android12OvpnRouteLimit: 50,
            supportsAndroidRouteExclusion: false);

        Assert.Equal(50, plan.AppliedRouteCount);
        var routeLines = plan.Config.Split('\n').Count(l => l.StartsWith("route ", StringComparison.Ordinal));
        Assert.Equal(50, routeLines);
        Assert.Contains("net_gateway", plan.Config, StringComparison.Ordinal);
    }
}
