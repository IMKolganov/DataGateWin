using System.Globalization;
using System.Net;
using System.Net.Sockets;
using System.Text;
using Xunit;

namespace DataGateWin.Tests;

/// <summary>
/// Mirrors engine <c>OvpnTextUtils</c> + <c>EnginePortDefaults</c> for unit coverage.
/// </summary>
public sealed class OvpnTextUtilsMirrorTests
{
    [Theory]
    [InlineData("1194", true, 1194)]
    [InlineData("1", true, 1)]
    [InlineData("65535", true, 65535)]
    [InlineData("0", false, 0)]
    [InlineData("", false, 0)]
    [InlineData("65536", false, 0)]
    [InlineData("abc", false, 0)]
    [InlineData("12a", false, 0)]
    [InlineData("-1", false, 0)]
    public void TryParsePort_RejectsInvalidAndZero(string text, bool ok, int expected)
    {
        var parsed = OvpnTextUtilsMirror.TryParsePort(text, out var port);
        Assert.Equal(ok, parsed);
        if (ok)
            Assert.Equal(expected, port);
    }

    [Fact]
    public void TryGetFirstRemote_OmitsPort_UsesOpenVpnDefault1194()
    {
        Assert.True(OvpnTextUtilsMirror.TryGetFirstRemote("remote vpn.example.com\n", out var remote));
        Assert.Equal("vpn.example.com", remote.Host);
        Assert.Equal(EnginePortDefaultsContract.OpenVpnDefaultRemotePort, remote.Port);
        Assert.Equal("", remote.Proto);
    }

    [Fact]
    public void TryGetFirstRemote_InvalidPort_KeepsOpenVpnDefault()
    {
        Assert.True(OvpnTextUtilsMirror.TryGetFirstRemote("remote vpn.example.com 0 udp\n", out var remote));
        Assert.Equal(EnginePortDefaultsContract.OpenVpnDefaultRemotePort, remote.Port);
        Assert.Equal("udp", remote.Proto);
    }

    [Fact]
    public void TryGetFirstRemote_OverflowPort_KeepsOpenVpnDefault()
    {
        Assert.True(OvpnTextUtilsMirror.TryGetFirstRemote("remote vpn.example.com 99999\n", out var remote));
        Assert.Equal(EnginePortDefaultsContract.OpenVpnDefaultRemotePort, remote.Port);
    }

    [Fact]
    public void TryGetFirstRemote_ExplicitPortAndProto()
    {
        Assert.True(OvpnTextUtilsMirror.TryGetFirstRemote("remote 1.2.3.4 443 tcp\n", out var remote));
        Assert.Equal("1.2.3.4", remote.Host);
        Assert.Equal(443, remote.Port);
        Assert.Equal("tcp", remote.Proto);
    }

    [Theory]
    [InlineData("", true)]
    [InlineData("udp", true)]
    [InlineData("UDP4", true)]
    [InlineData("udp6", true)]
    [InlineData("tcp", false)]
    [InlineData("tcp4", false)]
    public void IsUdpProto_MatchesOpenVpnDefault(string proto, bool expected)
    {
        Assert.Equal(expected, OvpnTextUtilsMirror.IsUdpProto(proto));
    }

    [Fact]
    public void ResolveTransportProto_PrefersRemoteProtoOverGlobal()
    {
        const string ovpn = """
            proto tcp
            remote vpn.example.com 1194 udp
            """;
        Assert.Equal("udp", OvpnTextUtilsMirror.ResolveTransportProto(ovpn));
    }

    [Fact]
    public void ResolveTransportProto_Empty_DefaultsUdp()
    {
        Assert.Equal("udp", OvpnTextUtilsMirror.ResolveTransportProto("remote vpn.example.com 1194\n"));
    }

    [Fact]
    public void ResolveTransportProto_GlobalTcp()
    {
        Assert.Equal("tcp", OvpnTextUtilsMirror.ResolveTransportProto("proto tcp\nremote vpn.example.com\n"));
    }

    [Fact]
    public void AppendQueryParam_AddsModeUdpOnce()
    {
        var path = OvpnTextUtilsMirror.AppendQueryParam("/api/proxy", "mode", "udp");
        Assert.Equal("/api/proxy?mode=udp", path);
        Assert.Equal(path, OvpnTextUtilsMirror.AppendQueryParam(path, "mode", "udp"));
    }

    [Fact]
    public void ForceRemoteToLocalBridge_ForcesMatchingProto_Udp()
    {
        const string ovpn = """
            remote vpn.example.com 1194 tcp
            proto tcp
            """;
        var result = ForceRemoteToLocalBridgeMirror.Apply(ovpn, "127.0.0.1", 18080, useUdp: true);
        Assert.Contains("remote 127.0.0.1 18080", result);
        Assert.Contains("proto udp", result);
        Assert.DoesNotContain("proto tcp", result);
        Assert.DoesNotContain("vpn.example.com", result);
    }

    [Fact]
    public void ForceRemoteToLocalBridge_ForcesMatchingProto_Tcp()
    {
        const string ovpn = "remote vpn.example.com 1194 udp\n";
        var result = ForceRemoteToLocalBridgeMirror.Apply(ovpn, "127.0.0.1", 18081, useUdp: false);
        Assert.Contains("remote 127.0.0.1 18081", result);
        Assert.Contains("proto tcp-client", result);
    }

    [Fact]
    public void ForceRemoteToLocalBridge_InsertsProtoWhenMissing()
    {
        const string ovpn = "remote vpn.example.com\nca ca.crt\n";
        var result = ForceRemoteToLocalBridgeMirror.Apply(ovpn, "127.0.0.1", 18080, useUdp: true);
        Assert.Contains("proto udp", result);
        Assert.Contains("remote 127.0.0.1 18080", result);
    }

    [Fact]
    public void TryGetDnsServers_ParsesAndSkipsComments()
    {
        const string ovpn = """
            # dhcp-option DNS 9.9.9.9
            dhcp-option DNS 10.8.0.1
            dhcp-option dns 1.1.1.1
            """;
        Assert.Equal(["10.8.0.1", "1.1.1.1"], OvpnTextUtilsMirror.TryGetDnsServers(ovpn));
    }
}

internal static class ForceRemoteToLocalBridgeMirror
{
    public static string Apply(string ovpn, string localHost, int localPort, bool useUdp)
    {
        var protoLine = useUdp ? "proto udp" : "proto tcp-client";
        var body = new StringBuilder();
        var remoteWritten = false;
        var protoWritten = false;

        using var reader = new StringReader(ovpn.Replace("\r\n", "\n"));
        string? line;
        while ((line = reader.ReadLine()) != null)
        {
            var trimmedStart = line.TrimStart();
            if (trimmedStart.StartsWith("remote ", StringComparison.OrdinalIgnoreCase)
                || trimmedStart.Equals("remote", StringComparison.OrdinalIgnoreCase))
            {
                if (!remoteWritten)
                {
                    body.Append("remote ").Append(localHost).Append(' ').Append(localPort).Append('\n');
                    remoteWritten = true;
                }
                continue;
            }

            if (trimmedStart.StartsWith("proto ", StringComparison.OrdinalIgnoreCase)
                || trimmedStart.Equals("proto", StringComparison.OrdinalIgnoreCase))
            {
                body.Append(protoLine).Append('\n');
                protoWritten = true;
                continue;
            }

            body.Append(line).Append('\n');
        }

        var patched = new StringBuilder();
        if (!remoteWritten)
            patched.Append("remote ").Append(localHost).Append(' ').Append(localPort).Append('\n');
        if (!protoWritten)
            patched.Append(protoLine).Append('\n');
        patched.Append(body);
        return patched.ToString();
    }
}

public sealed class LocalBridgeListenPortTests
{
    [Fact]
    public void PreferredListenPort_ContractMatchesUiAndEngine()
    {
        Assert.Equal(18080, EnginePortDefaultsContract.LocalBridgeDefaultListenPort);
        Assert.Equal(64, EnginePortDefaultsContract.LocalBridgeListenPortAttempts);
        Assert.Equal(1194, EnginePortDefaultsContract.OpenVpnDefaultRemotePort);
    }

    [Fact]
    public void WhenPreferredPortBusy_NextPortInRangeIsFree()
    {
        // Use an ephemeral preferred port so a busy 18080 on the machine does not flake CI.
        int preferred;
        var blocker = new TcpListener(IPAddress.Loopback, 0);
        blocker.Start();
        preferred = ((IPEndPoint)blocker.LocalEndpoint).Port;

        try
        {
            var bound = LocalBridgePortProbe.TryBindFirstAvailable(
                preferred,
                EnginePortDefaultsContract.LocalBridgeListenPortAttempts,
                out var used);

            Assert.True(bound);
            Assert.NotEqual(preferred, used);
            Assert.InRange(
                used,
                preferred + 1,
                preferred + EnginePortDefaultsContract.LocalBridgeListenPortAttempts - 1);
        }
        finally
        {
            blocker.Stop();
        }
    }

    [Fact]
    public void WhenAllAttemptPortsBusy_BindFails()
    {
        var preferred = 45000;
        var attempts = 3;
        var blockers = new List<TcpListener>();
        try
        {
            for (var i = 0; i < attempts; i++)
            {
                var l = new TcpListener(IPAddress.Loopback, preferred + i);
                l.Start();
                blockers.Add(l);
            }

            Assert.False(LocalBridgePortProbe.TryBindFirstAvailable(preferred, attempts, out _));
        }
        finally
        {
            foreach (var l in blockers)
            {
                try { l.Stop(); } catch { /* ignore */ }
            }
        }
    }
}

/// <summary>Values must match engine EnginePortDefaults.h and UI EnginePortDefaults.cs.</summary>
internal static class EnginePortDefaultsContract
{
    public const int OpenVpnDefaultRemotePort = 1194;
    public const int LocalBridgeDefaultListenPort = 18080;
    public const int LocalBridgeListenPortAttempts = 64;
}

internal static class LocalBridgePortProbe
{
    public static bool TryBindFirstAvailable(int preferred, int attempts, out int usedPort)
    {
        usedPort = 0;
        for (var i = 0; i < attempts; i++)
        {
            var candidate = preferred + i;
            if (candidate > 65535)
                break;

            try
            {
                using var listener = new TcpListener(IPAddress.Loopback, candidate);
                listener.Start();
                usedPort = candidate;
                return true;
            }
            catch (SocketException)
            {
                // busy — try next
            }
        }

        return false;
    }
}

/// <summary>C# mirror of engine OvpnTextUtils.cpp — keep algorithms in lockstep.</summary>
internal static class OvpnTextUtilsMirror
{
    public static bool TryParsePort(string text, out int port)
    {
        port = 0;
        if (string.IsNullOrEmpty(text) || !text.All(char.IsDigit))
            return false;

        if (!ulong.TryParse(text, NumberStyles.None, CultureInfo.InvariantCulture, out var p))
            return false;

        if (p is < 1 or > 65535)
            return false;

        port = (int)p;
        return true;
    }

    public static bool TryGetFirstRemote(string ovpn, out (string Host, int Port, string Proto) remote)
    {
        remote = default;
        using var reader = new StringReader(ovpn);
        string? line;
        while ((line = reader.ReadLine()) != null)
        {
            line = line.Trim();
            if (line.Length == 0 || line[0] is '#' or ';')
                continue;

            var parts = line.Split((char[]?)null, StringSplitOptions.RemoveEmptyEntries);
            if (parts.Length < 2 || !parts[0].Equals("remote", StringComparison.OrdinalIgnoreCase))
                continue;

            var host = parts[1];
            var port = EnginePortDefaultsContract.OpenVpnDefaultRemotePort;
            var proto = "";

            if (parts.Length >= 3)
            {
                if (parts[2].All(char.IsDigit))
                {
                    if (TryParsePort(parts[2], out var parsed))
                        port = parsed;
                    if (parts.Length >= 4 && !parts[3].All(char.IsDigit))
                        proto = parts[3].ToLowerInvariant();
                }
                else
                {
                    proto = parts[2].ToLowerInvariant();
                }
            }

            remote = (host, port, proto);
            return true;
        }

        return false;
    }

    public static bool IsUdpProto(string proto)
    {
        var p = proto.Trim().ToLowerInvariant();
        if (p.Length == 0)
            return true;
        return p is "udp" or "udp4" or "udp6";
    }

    public static string TryGetProto(string ovpn)
    {
        using var reader = new StringReader(ovpn);
        string? line;
        while ((line = reader.ReadLine()) != null)
        {
            line = line.Trim();
            if (line.Length == 0 || line[0] is '#' or ';')
                continue;

            var parts = line.Split((char[]?)null, StringSplitOptions.RemoveEmptyEntries);
            if (parts.Length >= 2 && parts[0].Equals("proto", StringComparison.OrdinalIgnoreCase))
                return parts[1].ToLowerInvariant();
        }

        return "";
    }

    public static string ResolveTransportProto(string ovpn)
    {
        if (TryGetFirstRemote(ovpn, out var remote) && !string.IsNullOrEmpty(remote.Proto))
            return remote.Proto;

        var global = TryGetProto(ovpn);
        return string.IsNullOrEmpty(global) ? "udp" : global;
    }

    public static string AppendQueryParam(string path, string key, string value)
    {
        if (string.IsNullOrEmpty(path))
            path = "/";

        var needle = key + "=";
        if (path.Contains(needle, StringComparison.Ordinal))
            return path;

        if (!path.Contains('?', StringComparison.Ordinal))
            path += "?";
        else if (path[^1] is not ('?' or '&'))
            path += "&";

        return path + key + "=" + value;
    }

    public static IReadOnlyList<string> TryGetDnsServers(string ovpn)
    {
        var servers = new List<string>();
        using var reader = new StringReader(ovpn);
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
