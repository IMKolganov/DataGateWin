using Xunit;

namespace DataGateWin.Tests;

/// <summary>
/// Mirrors engine <c>ovpn::TryGetDnsServersFromOvpn</c> for unit coverage without native tests.
/// </summary>
public sealed class OvpnDnsServersParserTests
{
    [Fact]
    public void ParsesDhcpOptionDnsLines_IgnoresCommentsAndOtherOptions()
    {
        const string ovpn = """
            # dhcp-option DNS 9.9.9.9
            remote vpn.example 1194 udp
            dhcp-option DNS 10.8.0.1
            dhcp-option DOMAIN example.com
            dhcp-option dns 1.1.1.1
            ; dhcp-option DNS 8.8.8.8
            """;

        var servers = OvpnDnsServersParser.TryGetDnsServers(ovpn);
        Assert.Equal(["10.8.0.1", "1.1.1.1"], servers);
    }

    [Fact]
    public void EmptyConfig_ReturnsEmptyList()
    {
        Assert.Empty(OvpnDnsServersParser.TryGetDnsServers(""));
    }
}

internal static class OvpnDnsServersParser
{
    public static IReadOnlyList<string> TryGetDnsServers(string ovpnContentUtf8)
    {
        var servers = new List<string>();
        using var reader = new StringReader(ovpnContentUtf8);
        string? line;
        while ((line = reader.ReadLine()) != null)
        {
            line = line.Trim();
            if (line.Length == 0 || line[0] is '#' or ';')
                continue;

            var parts = line.Split((char[]?)null, StringSplitOptions.RemoveEmptyEntries);
            if (parts.Length >= 3
                && parts[0].Equals("dhcp-option", StringComparison.OrdinalIgnoreCase)
                && parts[1].Equals("dns", StringComparison.OrdinalIgnoreCase))
            {
                servers.Add(parts[2].ToLowerInvariant());
            }
        }

        return servers;
    }
}
