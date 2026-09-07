using DataGateWin.Services.Xray;
using Newtonsoft.Json.Linq;
using Xunit;

namespace DataGateWin.Tests;

public sealed class XrayWindowsConfigBuilderTests
{
    private const string ProxyOutbound = """
        [{"protocol":"vless","tag":"proxy","settings":{"vnext":[{"address":"198.51.100.10","port":443,"users":[{"id":"u"}]}]},"streamSettings":{"network":"tcp"},"sendThrough":"Friendly Name"}]
        """;

    [Theory]
    [InlineData("vless://uuid@host:443?encryption=none#n", "vless://uuid@host:443?encryption=none#n")]
    [InlineData("vmess://abc", "vmess://abc")]
    [InlineData("trojan://x", "trojan://x")]
    [InlineData("ss://y", "ss://y")]
    [InlineData("hy2://z", "hy2://z")]
    [InlineData("hysteria2://z", "hysteria2://z")]
    [InlineData("# comment\r\nvmess://abc\r\n", "vmess://abc")]
    [InlineData("  VLESS://UUID@HOST:443  ", "VLESS://UUID@HOST:443")]
    public void ExtractShareLink_Schemes(string input, string expected)
    {
        Assert.Equal(expected, XrayWindowsConfigBuilder.ExtractShareLink(input));
    }

    [Fact]
    public void ExtractShareLink_FromIssuedJson_AndNullCases()
    {
        var issued = """{"vless":"vless://uuid@host:443?encryption=none#n","dnsServers":["172.20.0.1"]}""";
        Assert.Equal(
            "vless://uuid@host:443?encryption=none#n",
            XrayWindowsConfigBuilder.ExtractShareLink(issued));

        Assert.Null(XrayWindowsConfigBuilder.ExtractShareLink("not-a-link"));
        Assert.Null(XrayWindowsConfigBuilder.ExtractShareLink(""));
        Assert.Null(XrayWindowsConfigBuilder.ExtractShareLink("   "));
        Assert.Null(XrayWindowsConfigBuilder.ExtractShareLink("""{"vless":"http://nope"}"""));
        Assert.Null(XrayWindowsConfigBuilder.ExtractShareLink("{not-json"));
        Assert.Null(XrayWindowsConfigBuilder.ExtractShareLink("# only comment\n\n"));
    }

    [Fact]
    public void ExtractExplicitDnsServers_ReadsCamelAndPascal_Dedupes()
    {
        var a = XrayWindowsConfigBuilder.ExtractExplicitDnsServers(
            """{"dnsServers":["172.20.0.1","1.1.1.1","172.20.0.1"]}""");
        Assert.Equal(["172.20.0.1", "1.1.1.1"], a);

        var b = XrayWindowsConfigBuilder.ExtractExplicitDnsServers(
            """{"DnsServers":["10.0.0.53"]}""");
        Assert.Equal(["10.0.0.53"], b);

        Assert.Empty(XrayWindowsConfigBuilder.ExtractExplicitDnsServers("vless://x"));
        Assert.Empty(XrayWindowsConfigBuilder.ExtractExplicitDnsServers("""{"dnsServers":[]}"""));
        Assert.Empty(XrayWindowsConfigBuilder.ExtractExplicitDnsServers("""{"dnsServers":[1,null,""]}"""));
        Assert.Empty(XrayWindowsConfigBuilder.ExtractExplicitDnsServers("{"));
    }

    [Fact]
    public void NormalizeMux_DefaultsDisabledAndInvalidEnums()
    {
        Assert.Null(XrayWindowsConfigBuilder.NormalizeMux("""{"outbounds":[]}"""));
        Assert.Null(XrayWindowsConfigBuilder.NormalizeMux("""{"mux":{"enabled":false}}"""));
        Assert.Null(XrayWindowsConfigBuilder.NormalizeMux("""{"mux":null}"""));
        Assert.Null(XrayWindowsConfigBuilder.NormalizeMux("not-json"));
        Assert.Null(XrayWindowsConfigBuilder.NormalizeMux("[1]"));

        var mux = XrayWindowsConfigBuilder.NormalizeMux("""{"mux":{"enabled":true}}""");
        Assert.NotNull(mux);
        Assert.True(mux!.Value<bool>("enabled"));
        Assert.Equal(8, mux.Value<int>("concurrency"));
        Assert.Equal(16, mux.Value<int>("xudpConcurrency"));
        Assert.Equal("reject", mux.Value<string>("xudpProxyUDP443"));

        var noEnabledFlag = XrayWindowsConfigBuilder.NormalizeMux("""{"mux":{}}""");
        Assert.NotNull(noEnabledFlag);

        var clamped = XrayWindowsConfigBuilder.NormalizeMux(
            """{"mux":{"concurrency":999,"xudpConcurrency":0,"xudpProxyUDP443":"ALLOW"}}""");
        Assert.Equal(8, clamped!.Value<int>("concurrency"));
        Assert.Equal(16, clamped.Value<int>("xudpConcurrency"));
        Assert.Equal("allow", clamped.Value<string>("xudpProxyUDP443"));

        var badEnum = XrayWindowsConfigBuilder.NormalizeMux(
            """{"mux":{"xudpProxyUDP443":"banana"}}""");
        Assert.Equal("reject", badEnum!.Value<string>("xudpProxyUDP443"));

        var stringNums = XrayWindowsConfigBuilder.NormalizeMux(
            """{"mux":{"concurrency":"12","xudpConcurrency":"20","xudpProxyUDP443":"skip"}}""");
        Assert.Equal(12, stringNums!.Value<int>("concurrency"));
        Assert.Equal(20, stringNums.Value<int>("xudpConcurrency"));
        Assert.Equal("skip", stringNums.Value<string>("xudpProxyUDP443"));

        var garbageNums = XrayWindowsConfigBuilder.NormalizeMux(
            """{"mux":{"concurrency":"x","xudpConcurrency":"y"}}""");
        Assert.Equal(8, garbageNums!.Value<int>("concurrency"));
        Assert.Equal(16, garbageNums.Value<int>("xudpConcurrency"));
    }

    [Fact]
    public void ExtractOutbounds_ArrayObjectAndOutboundConfigs()
    {
        var fromArray = XrayWindowsConfigBuilder.ExtractOutbounds(ProxyOutbound);
        Assert.Single(fromArray);

        var wrapped = """{"outbounds":[{"protocol":"freedom","tag":"direct"}]}""";
        Assert.Equal("direct", XrayWindowsConfigBuilder.ExtractOutbounds(wrapped)[0]!.Value<string>("tag"));

        var legacy = """{"OutboundConfigs":[{"protocol":"vless","tag":"p"}]}""";
        Assert.Equal("p", XrayWindowsConfigBuilder.ExtractOutbounds(legacy)[0]!.Value<string>("tag"));

        Assert.Throws<InvalidOperationException>(() =>
            XrayWindowsConfigBuilder.ExtractOutbounds("""{"foo":1}"""));
        Assert.Throws<Newtonsoft.Json.JsonReaderException>(() =>
            XrayWindowsConfigBuilder.ExtractOutbounds("not-json"));
    }

    [Fact]
    public void Build_StripsSendThrough_AddsDirectBlock_AndPrivateRule()
    {
        var json = XrayWindowsConfigBuilder.BuildWindowsTunClientConfig(ProxyOutbound);
        var root = JObject.Parse(json);

        Assert.Equal("tun", root["inbounds"]![0]!["protocol"]!.Value<string>());
        Assert.Equal("xray0", root["inbounds"]![0]!["settings"]!["name"]!.Value<string>());
        Assert.Equal(1500, root["inbounds"]![0]!["settings"]!["mtu"]!.Value<int>());
        Assert.Equal("system", root["inbounds"]![0]!["settings"]!["stack"]!.Value<string>());
        Assert.Equal("warning", root["log"]!["loglevel"]!.Value<string>());
        Assert.Equal("AsIs", root["routing"]!["domainStrategy"]!.Value<string>());

        var dest = (JArray)root["inbounds"]![0]!["sniffing"]!["destOverride"]!;
        Assert.Equal(new[] { "http", "tls", "quic" }, dest.Select(t => t.Value<string>()!).ToArray());

        var outbounds = (JArray)root["outbounds"]!;
        Assert.DoesNotContain(outbounds.OfType<JObject>(), o => o.Property("sendThrough") != null);
        Assert.Contains(outbounds.OfType<JObject>(), o => o.Value<string>("tag") == "direct");
        Assert.Contains(outbounds.OfType<JObject>(), o => o.Value<string>("tag") == "block");

        var rules = (JArray)root["routing"]!["rules"]!;
        Assert.Contains(rules.OfType<JObject>(), r =>
            r.Value<string>("outboundTag") == "direct"
            && r["ip"] is JArray ips
            && ips.Any(i => i.Value<string>() == "10.0.0.0/8"));
        Assert.Equal("proxy", rules.Last!["outboundTag"]!.Value<string>());
        Assert.Equal("tcp,udp", rules.Last!["network"]!.Value<string>());
    }

    [Fact]
    public void Build_UsesCustomMtu_AndDefaultProxyTag()
    {
        var raw = """[{"protocol":"vless","settings":{"vnext":[{"address":"1.2.3.4","port":1,"users":[{"id":"u"}]}]}}]""";
        var root = JObject.Parse(XrayWindowsConfigBuilder.BuildWindowsTunClientConfig(raw, mtu: 1400));
        Assert.Equal(1400, root["inbounds"]![0]!["settings"]!["mtu"]!.Value<int>());
        Assert.Equal("proxy", root["outbounds"]![0]!["tag"]!.Value<string>());
        Assert.Equal("proxy", root["routing"]!["rules"]!.Last!["outboundTag"]!.Value<string>());
    }

    [Fact]
    public void Build_DoesNotDuplicateExistingDirectAndBlock()
    {
        var raw = """
            [{"protocol":"vless","tag":"proxy","settings":{"vnext":[{"address":"1.2.3.4","port":1,"users":[{"id":"u"}]}]}},
             {"protocol":"freedom","tag":"direct","settings":{}},
             {"protocol":"blackhole","tag":"block","settings":{}}]
            """;
        var outbounds = (JArray)JObject.Parse(XrayWindowsConfigBuilder.BuildWindowsTunClientConfig(raw))["outbounds"]!;
        Assert.Equal(1, outbounds.Count(o => o.Value<string>("tag") == "direct"));
        Assert.Equal(1, outbounds.Count(o => o.Value<string>("tag") == "block"));
        Assert.Equal(3, outbounds.Count);
    }

    [Fact]
    public void Build_InsertsProxyEndpointBypass_BeforeCatchAll()
    {
        var json = XrayWindowsConfigBuilder.BuildWindowsTunClientConfig(ProxyOutbound);
        var rules = (JArray)JObject.Parse(json)["routing"]!["rules"]!;

        var bypass = rules.OfType<JObject>().FirstOrDefault(r =>
            r.Value<string>("outboundTag") == "direct"
            && r["ip"] is JArray ips
            && ips.Any(i => i.Value<string>() == "198.51.100.10/32"));
        Assert.NotNull(bypass);

        var bypassIndex = rules.IndexOf(bypass!);
        var catchAllIndex = rules.Count - 1;
        Assert.True(bypassIndex < catchAllIndex);
    }

    [Fact]
    public void Build_MergesExplicitBypassCidrs()
    {
        var json = XrayWindowsConfigBuilder.BuildWindowsTunClientConfig(
            ProxyOutbound,
            directBypassCidrs: ["203.0.113.9/32", "198.51.100.10/32"]);
        var rules = (JArray)JObject.Parse(json)["routing"]!["rules"]!;
        var bypassIps = rules.OfType<JObject>()
            .Where(r => r.Value<string>("outboundTag") == "direct" && r["ip"] is JArray)
            .SelectMany(r => ((JArray)r["ip"]!).Select(i => i.Value<string>()!))
            .ToHashSet(StringComparer.OrdinalIgnoreCase);

        Assert.Contains("203.0.113.9/32", bypassIps);
        Assert.Contains("198.51.100.10/32", bypassIps);
    }

    [Fact]
    public void Build_ChunksLargeBypassLists()
    {
        var cidrs = Enumerable.Range(0, XrayWindowsConfigBuilder.DirectBypassCidrsPerRule + 5)
            .Select(i => $"10.200.{i / 256}.{i % 256}/32")
            .ToList();

        var raw = """[{"protocol":"vless","tag":"proxy","settings":{"vnext":[{"address":"example.com","port":443,"users":[{"id":"u"}]}]}}]""";
        var rules = (JArray)JObject.Parse(
            XrayWindowsConfigBuilder.BuildWindowsTunClientConfig(raw, directBypassCidrs: cidrs))["routing"]!["rules"]!;

        var bypassRules = rules.OfType<JObject>()
            .Where(r => r.Value<string>("outboundTag") == "direct"
                        && r["ip"] is JArray ips
                        && !ips.Any(i => i.Value<string>() == "10.0.0.0/8"))
            .ToList();
        Assert.True(bypassRules.Count >= 2);
        Assert.True(bypassRules.All(r => ((JArray)r["ip"]!).Count <= XrayWindowsConfigBuilder.DirectBypassCidrsPerRule));
        Assert.Equal(cidrs.Count, bypassRules.Sum(r => ((JArray)r["ip"]!).Count));
    }

    [Fact]
    public void Build_DnsServers_ProxyBeforePrivate_PreservesCidrSuffix()
    {
        var json = XrayWindowsConfigBuilder.BuildWindowsTunClientConfig(
            ProxyOutbound,
            tunnelDnsServers: ["172.20.0.1", "10.0.0.53/32", ""]);
        var rules = (JArray)JObject.Parse(json)["routing"]!["rules"]!;

        Assert.Equal("proxy", rules[0]!.Value<string>("outboundTag"));
        var dnsIps = ((JArray)rules[0]!["ip"]!).Select(t => t.Value<string>()).ToArray();
        Assert.Contains("172.20.0.1/32", dnsIps);
        Assert.Contains("10.0.0.53/32", dnsIps);
        Assert.Equal("direct", rules[1]!.Value<string>("outboundTag")); // private
    }

    [Fact]
    public void Build_AppliesMuxOntoFirstOutbound()
    {
        var withMux = """
            {"outbounds":[{"protocol":"vless","settings":{"vnext":[{"address":"1.2.3.4","port":443,"users":[{"id":"u"}]}]}}],"mux":{"enabled":true,"concurrency":4,"xudpConcurrency":9,"xudpProxyUDP443":"skip"}}
            """;
        var root = JObject.Parse(XrayWindowsConfigBuilder.BuildWindowsTunClientConfig(withMux));
        var mux = root["outbounds"]![0]!["mux"] as JObject;
        Assert.NotNull(mux);
        Assert.Equal(4, mux!.Value<int>("concurrency"));
        Assert.Equal(9, mux.Value<int>("xudpConcurrency"));
        Assert.Equal("skip", mux.Value<string>("xudpProxyUDP443"));
    }

    [Fact]
    public void Build_EmptyOutbounds_Throws()
    {
        Assert.Throws<InvalidOperationException>(() =>
            XrayWindowsConfigBuilder.BuildWindowsTunClientConfig("[]"));
    }

    [Fact]
    public void CollectProxyEndpointCidrs_SkipsHostnamesFreedomAndDedupesIpv6()
    {
        var outbounds = """
            [{"protocol":"vless","settings":{"vnext":[{"address":"example.com","port":443}]}},
             {"protocol":"shadowsocks","settings":{"servers":[{"address":"203.0.113.5","port":8388}]}},
             {"protocol":"vless","settings":{"vnext":[{"address":"203.0.113.5","port":443}]}},
             {"protocol":"vless","settings":{"vnext":[{"address":"2001:db8::1","port":443}]}},
             {"protocol":"freedom","tag":"direct","settings":{}},
             {"protocol":"blackhole","tag":"block","settings":{}}]
            """;
        var cidrs = XrayWindowsConfigBuilder.CollectProxyEndpointCidrs(
            XrayWindowsConfigBuilder.ExtractOutbounds(outbounds));
        Assert.Equal(["203.0.113.5/32", "2001:db8::1/128"], cidrs);
    }

    [Fact]
    public void PrivateDirectIps_ContainsAndroidParitySet()
    {
        foreach (var cidr in new[]
                 {
                     "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "100.64.0.0/10",
                     "fc00::/7", "fe80::/10", "::1/128"
                 })
        {
            Assert.Contains(cidr, XrayWindowsConfigBuilder.PrivateDirectIps);
        }

        var json = XrayWindowsConfigBuilder.BuildWindowsTunClientConfig(ProxyOutbound);
        var privateRule = ((JArray)JObject.Parse(json)["routing"]!["rules"]!)
            .OfType<JObject>()
            .First(r => r.Value<string>("outboundTag") == "direct"
                        && ((JArray)r["ip"]!).Any(i => i.Value<string>() == "10.0.0.0/8"));
        Assert.Equal(
            XrayWindowsConfigBuilder.PrivateDirectIps.Length,
            ((JArray)privateRule["ip"]!).Count);
    }

    [Fact]
    public void PrepareShareOrOutboundsInput_WrapsOutboundsKeepsMux_OrExtractsShare()
    {
        var raw = """
            {"outbounds":[{"protocol":"vless","tag":"p","sendThrough":"x","settings":{"vnext":[{"address":"1.1.1.1"}]}}],"mux":{"enabled":true}}
            """;
        var prepared = XrayWindowsConfigBuilder.PrepareShareOrOutboundsInput(raw);
        var obj = JObject.Parse(prepared);
        Assert.Null(obj["outbounds"]![0]!["sendThrough"]);
        Assert.NotNull(obj["mux"]);

        var issued =
            """{"vless":"vless://uuid@host:443?encryption=none#n","dnsServers":["172.20.0.1"]}""";
        Assert.Equal(
            "vless://uuid@host:443?encryption=none#n",
            XrayWindowsConfigBuilder.PrepareShareOrOutboundsInput(issued));

        Assert.Equal("plain-text", XrayWindowsConfigBuilder.PrepareShareOrOutboundsInput("plain-text"));
    }

    [Fact]
    public void PrepareShareOrOutboundsInput_OutboundConfigsKey()
    {
        var raw = """{"OutboundConfigs":[{"protocol":"vless","tag":"p","sendThrough":"n"}]}""";
        var prepared = JObject.Parse(XrayWindowsConfigBuilder.PrepareShareOrOutboundsInput(raw));
        Assert.Null(prepared["outbounds"]![0]!["sendThrough"]);
        Assert.Equal("p", prepared["outbounds"]![0]!["tag"]!.Value<string>());
    }
}
