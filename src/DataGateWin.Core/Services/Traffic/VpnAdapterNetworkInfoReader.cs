using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;

namespace DataGateWin.Services.Traffic;

public sealed record VpnAdapterNetworkInfo(string Name, string? VpnIp, IReadOnlyList<string> DnsServers);

/// <summary>Reads actual tunnel configuration; never substitutes a physical NIC or server public IP.</summary>
public static class VpnAdapterNetworkInfoReader
{
    public static VpnAdapterNetworkInfo? Read(string? preferredAdapterName, string? knownVpnIp)
    {
        var candidates = new List<VpnAdapterNetworkInfo>();
        foreach (var nic in NetworkInterface.GetAllNetworkInterfaces())
        {
            try
            {
                var name = VpnAdapterTrafficPicker.CanonicalName(nic.Name)
                    ?? VpnAdapterTrafficPicker.CanonicalName(nic.Description);
                if (name is null || nic.OperationalStatus != OperationalStatus.Up) continue;
                var properties = nic.GetIPProperties();
                var addresses = properties.UnicastAddresses.Select(a => a.Address).Where(IsTunnelAddress).ToList();
                var ip = addresses.FirstOrDefault(a => a.AddressFamily == AddressFamily.InterNetwork)
                    ?? addresses.FirstOrDefault();
                candidates.Add(new VpnAdapterNetworkInfo(name, ip?.ToString(),
                    properties.DnsAddresses.Where(a => !a.Equals(IPAddress.Any) && !a.Equals(IPAddress.IPv6Any))
                        .Select(a => a.ToString()).Distinct(StringComparer.OrdinalIgnoreCase).ToArray()));
            }
            catch (NetworkInformationException) { /* Adapter disappeared during reconnect. */ }
        }
        return Select(candidates, preferredAdapterName, knownVpnIp);
    }

    public static VpnAdapterNetworkInfo? Select(IEnumerable<VpnAdapterNetworkInfo> adapters,
        string? preferredAdapterName, string? knownVpnIp)
    {
        var known = adapters.Where(a => VpnAdapterTrafficPicker.IsKnownVpnAdapter(a.Name)).ToList();
        if (!string.IsNullOrWhiteSpace(knownVpnIp))
        {
            var matchingIp = known.FirstOrDefault(a => a.VpnIp == knownVpnIp);
            if (matchingIp is not null) return matchingIp;
        }
        if (!string.IsNullOrWhiteSpace(preferredAdapterName))
        {
            var preferred = known.FirstOrDefault(a => a.Name.Equals(preferredAdapterName, StringComparison.OrdinalIgnoreCase));
            return preferred; // Never display a leftover adapter from a different protocol.
        }
        return known.Count == 1 ? known[0] : null;
    }

    private static bool IsTunnelAddress(IPAddress ip) => !IPAddress.IsLoopback(ip)
        && !ip.Equals(IPAddress.Any) && !ip.Equals(IPAddress.IPv6Any)
        && !ip.IsIPv6LinkLocal && !(ip.AddressFamily == AddressFamily.InterNetwork
            && ip.GetAddressBytes()[0] == 169 && ip.GetAddressBytes()[1] == 254);
}
