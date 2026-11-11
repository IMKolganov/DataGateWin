using System.Net;
using System.Net.NetworkInformation;
using DataGateWin.CrashReporting;

namespace DataGateWin.Services.VpnServers;

/// <summary>
/// Active Remote Desktop peer addresses that must stay on the physical NIC
/// when a full-tunnel VPN installs a default route (otherwise RDP drops and
/// it looks like the app "closed").
/// </summary>
public static class RdpPeerCidrs
{
    public const int RdpPort = 3389;

    public static IReadOnlyList<string> CollectEstablishedPeerCidrs()
    {
        try
        {
            var set = new HashSet<string>(StringComparer.Ordinal);
            foreach (var c in IPGlobalProperties.GetIPGlobalProperties().GetActiveTcpConnections())
            {
                if (c.State != TcpState.Established)
                    continue;
                if (c.LocalEndPoint.Port != RdpPort)
                    continue;

                var remote = c.RemoteEndPoint.Address;
                if (remote is null || IPAddress.IsLoopback(remote))
                    continue;
                if (remote.AddressFamily is not System.Net.Sockets.AddressFamily.InterNetwork
                    and not System.Net.Sockets.AddressFamily.InterNetworkV6)
                    continue;

                var suffix = remote.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork
                    ? "/32"
                    : "/128";
                set.Add(remote.ToString() + suffix);
            }

            return set.Count == 0 ? Array.Empty<string>() : set.ToArray();
        }
        catch (Exception ex)
        {
            CrashReporter.ReportNonFatal(ex, "RdpPeerCidrs.Collect");
            return Array.Empty<string>();
        }
    }
}
