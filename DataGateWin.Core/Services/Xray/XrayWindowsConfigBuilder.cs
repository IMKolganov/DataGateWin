using System.Globalization;
using System.Net;
using Newtonsoft.Json.Linq;

namespace DataGateWin.Services.Xray;

/// <summary>
/// Pure helpers mirroring Android <c>XrayConfigBuilder</c> / Windows engine builder.
/// Used for connect-path prep and golden unit tests (no libXray).
/// </summary>
public static class XrayWindowsConfigBuilder
{
    public const int DirectBypassCidrsPerRule = 250;
    public const int DefaultMuxConcurrency = 8;
    public const int DefaultMuxXudpConcurrency = 16;

    public static readonly string[] PrivateDirectIps =
    [
        "0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16",
        "172.16.0.0/12", "192.0.0.0/24", "192.0.2.0/24", "192.168.0.0/16", "198.18.0.0/15",
        "198.51.100.0/24", "203.0.113.0/24", "224.0.0.0/4", "240.0.0.0/4", "255.255.255.255/32",
        "::/128", "::1/128", "fc00::/7", "fe80::/10", "ff00::/8",
    ];

    /// <summary>First share URI line, or JSON field <c>vless</c>.</summary>
    public static string? ExtractShareLink(string text)
    {
        var trimmed = text.Trim();
        if (trimmed.StartsWith("{", StringComparison.Ordinal))
        {
            try
            {
                var vless = JObject.Parse(trimmed).Value<string>("vless")?.Trim();
                if (!string.IsNullOrEmpty(vless)
                    && vless.StartsWith("vless://", StringComparison.OrdinalIgnoreCase))
                    return vless;
            }
            catch
            {
                // fall through to line scan
            }
        }

        foreach (var raw in trimmed.Replace("\r\n", "\n", StringComparison.Ordinal).Split('\n'))
        {
            var line = raw.Trim();
            if (line.Length == 0 || line.StartsWith("#", StringComparison.Ordinal))
                continue;
            var lower = line.ToLowerInvariant();
            if (lower.StartsWith("vless://", StringComparison.Ordinal)
                || lower.StartsWith("vmess://", StringComparison.Ordinal)
                || lower.StartsWith("trojan://", StringComparison.Ordinal)
                || lower.StartsWith("ss://", StringComparison.Ordinal)
                || lower.StartsWith("hy2://", StringComparison.Ordinal)
                || lower.StartsWith("hysteria2://", StringComparison.Ordinal))
                return line;
        }

        return null;
    }

    public static IReadOnlyList<string> ExtractExplicitDnsServers(string profileJsonOrText)
    {
        var trimmed = profileJsonOrText.Trim();
        if (!trimmed.StartsWith("{", StringComparison.Ordinal))
            return Array.Empty<string>();

        try
        {
            var root = JObject.Parse(trimmed);
            var arr = root["dnsServers"] as JArray ?? root["DnsServers"] as JArray;
            if (arr == null)
                return Array.Empty<string>();

            return arr
                .Select(t => t.Type == JTokenType.String ? t.Value<string>()?.Trim() : null)
                .Where(s => !string.IsNullOrEmpty(s))
                .Cast<string>()
                .Distinct(StringComparer.OrdinalIgnoreCase)
                .ToList();
        }
        catch
        {
            return Array.Empty<string>();
        }
    }

    public static JObject? NormalizeMux(string raw)
    {
        var trimmed = raw.Trim();
        if (!trimmed.StartsWith("{", StringComparison.Ordinal))
            return null;

        try
        {
            var root = JObject.Parse(trimmed);
            if (root["mux"] is not JObject mux)
                return null;
            if (mux.Property("enabled") != null && mux.Value<bool?>("enabled") == false)
                return null;

            return new JObject
            {
                ["enabled"] = true,
                ["concurrency"] = ReadMuxConcurrency(mux),
                ["xudpConcurrency"] = ReadMuxXudpConcurrency(mux),
                ["xudpProxyUDP443"] = ReadMuxXudpProxyUdp443(mux)
            };
        }
        catch
        {
            return null;
        }
    }

    public static JArray ExtractOutbounds(string raw)
    {
        var trimmed = raw.Trim();
        var token = JToken.Parse(trimmed);
        if (token is JArray arr)
            return arr;
        if (token is JObject obj)
        {
            if (obj["outbounds"] is JArray o)
                return o;
            if (obj["OutboundConfigs"] is JArray o2)
                return o2;
        }

        throw new InvalidOperationException("Config has no outbounds");
    }

    public static void SanitizeOutboundsForRuntime(JArray outbounds)
    {
        foreach (var ob in outbounds.OfType<JObject>())
            ob.Remove("sendThrough");
    }

    /// <summary>
    /// Collect proxy endpoint IPs as /32 (or /128) for direct bypass before catch-all.
    /// Hostnames are skipped (caller may resolve later).
    /// </summary>
    public static IReadOnlyList<string> CollectProxyEndpointCidrs(JArray outbounds)
    {
        var result = new List<string>();
        foreach (var ob in outbounds.OfType<JObject>())
        {
            var protocol = ob.Value<string>("protocol")?.ToLowerInvariant();
            if (protocol is "freedom" or "blackhole" or "dns" or "loopback")
                continue;

            void AddHost(string? host)
            {
                if (string.IsNullOrWhiteSpace(host))
                    return;
                host = host.Trim().Trim('[', ']');
                if (IPAddress.TryParse(host, out var ip))
                {
                    var cidr = ip.AddressFamily == System.Net.Sockets.AddressFamily.InterNetworkV6
                        ? $"{host}/128"
                        : $"{host}/32";
                    if (!result.Contains(cidr, StringComparer.OrdinalIgnoreCase))
                        result.Add(cidr);
                }
            }

            if (ob["settings"]?["vnext"] is JArray vnext)
            {
                foreach (var n in vnext.OfType<JObject>())
                    AddHost(n.Value<string>("address"));
            }

            if (ob["settings"]?["servers"] is JArray servers)
            {
                foreach (var s in servers.OfType<JObject>())
                    AddHost(s.Value<string>("address"));
            }
        }

        return result;
    }

    public static string BuildWindowsTunClientConfig(
        string outboundsOrConfigJson,
        IReadOnlyList<string>? directBypassCidrs = null,
        IReadOnlyList<string>? tunnelDnsServers = null,
        int mtu = 1500)
    {
        var outbounds = ExtractOutbounds(outboundsOrConfigJson);
        if (outbounds.Count == 0)
            throw new InvalidOperationException("No Xray outbounds in config");

        SanitizeOutboundsForRuntime(outbounds);

        var first = (JObject)outbounds[0]!;
        if (string.IsNullOrWhiteSpace(first.Value<string>("tag")))
            first["tag"] = "proxy";
        var proxyTag = first.Value<string>("tag")!;

        var mux = NormalizeMux(outboundsOrConfigJson);
        if (mux != null)
            first["mux"] = mux;

        var tags = outbounds.OfType<JObject>()
            .Select(o => o.Value<string>("tag") ?? "")
            .ToHashSet(StringComparer.Ordinal);
        if (!tags.Contains("direct"))
        {
            outbounds.Add(new JObject
            {
                ["tag"] = "direct",
                ["protocol"] = "freedom",
                ["settings"] = new JObject()
            });
        }

        if (!tags.Contains("block"))
        {
            outbounds.Add(new JObject
            {
                ["tag"] = "block",
                ["protocol"] = "blackhole",
                ["settings"] = new JObject()
            });
        }

        var dnsForTun = (tunnelDnsServers != null && tunnelDnsServers.Count > 0)
            ? tunnelDnsServers.Where(s => !string.IsNullOrWhiteSpace(s)).Select(s => s.Trim()).ToList()
            : new List<string> { "1.1.1.1", "8.8.8.8" };

        var rules = new JArray();
        // Drop local NetBIOS/SMB discovery that APIPA floods into TUN on Windows.
        rules.Add(new JObject
        {
            ["type"] = "field",
            ["outboundTag"] = "block",
            ["port"] = "137,138,139",
            ["network"] = "udp"
        });
        AppendProxyDnsRules(rules, proxyTag, dnsForTun);
        rules.Add(new JObject
        {
            ["type"] = "field",
            ["outboundTag"] = "direct",
            ["ip"] = new JArray(PrivateDirectIps)
        });

        var bypass = new List<string>();
        if (directBypassCidrs != null)
            bypass.AddRange(directBypassCidrs);
        bypass.AddRange(CollectProxyEndpointCidrs(outbounds));
        AppendDirectBypassRules(rules, bypass);

        rules.Add(new JObject
        {
            ["type"] = "field",
            ["outboundTag"] = proxyTag,
            ["network"] = "tcp,udp"
        });

        var root = new JObject
        {
            ["log"] = new JObject
            {
                ["loglevel"] = "warning",
                ["access"] = "none",
            },
            ["inbounds"] = new JArray
            {
                new JObject
                {
                    ["tag"] = "tun-in",
                    ["protocol"] = "tun",
                    ["settings"] = new JObject
                    {
                        ["mtu"] = mtu,
                        ["name"] = "xray0",
                        ["stack"] = "system",
                        // Windows: steer default route into TUN (Android VpnService does this itself).
                        ["gateway"] = new JArray("172.19.0.1/30"),
                        ["dns"] = new JArray(dnsForTun),
                        ["autoSystemRoutingTable"] = new JArray("0.0.0.0/0"),
                        ["autoOutboundsInterface"] = "auto",
                    },
                    ["sniffing"] = new JObject
                    {
                        ["enabled"] = true,
                        ["destOverride"] = new JArray("http", "tls", "quic")
                    }
                }
            },
            ["outbounds"] = outbounds,
            ["routing"] = new JObject
            {
                ["domainStrategy"] = "AsIs",
                ["rules"] = rules
            }
        };

        return root.ToString(Newtonsoft.Json.Formatting.None);
    }

    /// <summary>
    /// Normalize IPC / API text into outbounds JSON for convert-or-build.
    /// Returns share link text when JSON has no outbounds (caller converts via libXray).
    /// </summary>
    public static string PrepareShareOrOutboundsInput(string raw)
    {
        var trimmed = raw.Trim();
        if (trimmed.StartsWith("{", StringComparison.Ordinal))
        {
            try
            {
                var obj = JObject.Parse(trimmed);
                if (obj["outbounds"] is JArray || obj["OutboundConfigs"] is JArray)
                {
                    var outbounds = ExtractOutbounds(trimmed);
                    SanitizeOutboundsForRuntime(outbounds);
                    var wrap = new JObject { ["outbounds"] = outbounds };
                    var mux = NormalizeMux(trimmed);
                    if (mux != null)
                        wrap["mux"] = mux;
                    var dnsFromOutbounds = ExtractExplicitDnsServers(trimmed);
                    if (dnsFromOutbounds.Count > 0)
                        wrap["dnsServers"] = new JArray(dnsFromOutbounds);
                    return wrap.ToString(Newtonsoft.Json.Formatting.None);
                }

                // Issued API: keep dnsServers + mux with the share link so the engine TUN DNS path works.
                var share = ExtractShareLink(trimmed);
                if (!string.IsNullOrEmpty(share))
                {
                    var dns = ExtractExplicitDnsServers(trimmed);
                    var mux = NormalizeMux(trimmed);
                    if (dns.Count == 0 && mux == null)
                        return share;

                    var wrap = new JObject { ["vless"] = share };
                    if (dns.Count > 0)
                        wrap["dnsServers"] = new JArray(dns);
                    if (mux != null)
                        wrap["mux"] = mux;
                    return wrap.ToString(Newtonsoft.Json.Formatting.None);
                }
            }
            catch
            {
                // fall through
            }
        }

        return ExtractShareLink(trimmed) ?? trimmed;
    }

    private static void AppendDirectBypassRules(JArray rules, IEnumerable<string> cidrs)
    {
        var cleaned = cidrs
            .Select(c => c.Trim())
            .Where(c => c.Length > 0)
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToList();
        foreach (var chunk in cleaned.Chunk(DirectBypassCidrsPerRule))
        {
            rules.Add(new JObject
            {
                ["type"] = "field",
                ["outboundTag"] = "direct",
                ["ip"] = new JArray(chunk)
            });
        }
    }

    private static void AppendProxyDnsRules(JArray rules, string proxyTag, IEnumerable<string> dnsServers)
    {
        var ips = dnsServers
            .Select(s => s.Trim())
            .Where(s => s.Length > 0)
            .Select(s => s.Contains('/') ? s : $"{s}/32")
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToList();
        if (ips.Count == 0)
            return;

        rules.Add(new JObject
        {
            ["type"] = "field",
            ["outboundTag"] = proxyTag,
            ["ip"] = new JArray(ips)
        });
    }

    private static int ReadMuxConcurrency(JObject mux)
    {
        if (mux["concurrency"] is null)
            return DefaultMuxConcurrency;
        if (!TryReadInt(mux["concurrency"], out var n) || n is < 1 or > 128)
            return DefaultMuxConcurrency;
        return n;
    }

    private static int ReadMuxXudpConcurrency(JObject mux)
    {
        if (mux["xudpConcurrency"] is null)
            return DefaultMuxXudpConcurrency;
        if (!TryReadInt(mux["xudpConcurrency"], out var n) || n is < 1 or > 1024)
            return DefaultMuxXudpConcurrency;
        return n;
    }

    private static string ReadMuxXudpProxyUdp443(JObject mux)
    {
        var raw = mux.Value<string>("xudpProxyUDP443")?.Trim().ToLowerInvariant();
        return raw is "reject" or "allow" or "skip" ? raw : "reject";
    }

    private static bool TryReadInt(JToken? token, out int value)
    {
        value = 0;
        if (token == null)
            return false;
        if (token.Type is JTokenType.Integer or JTokenType.Float)
        {
            value = token.Value<int>();
            return true;
        }

        if (token.Type == JTokenType.String
            && int.TryParse(token.Value<string>(), NumberStyles.Integer, CultureInfo.InvariantCulture, out value))
            return true;
        return false;
    }
}
