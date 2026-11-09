namespace DataGateWin.Services.Traffic;

/// <summary>
/// Picks the local VPN NIC whose octet counters feed the Home live graph
/// (Wintun "DataGate" for OpenVPN, "xray0" for Xray). No backend involved.
/// </summary>
public static class VpnAdapterTrafficPicker
{
    public const string OpenVpnAdapterName = "DataGate";
    public const string XrayAdapterName = "xray0";

    public static bool IsKnownVpnAdapter(string? name) => CanonicalName(name) is not null;

    public static string? CanonicalName(string? name)
    {
        if (string.IsNullOrWhiteSpace(name))
            return null;

        if (name.Equals(OpenVpnAdapterName, StringComparison.OrdinalIgnoreCase))
            return OpenVpnAdapterName;
        if (name.Equals(XrayAdapterName, StringComparison.OrdinalIgnoreCase))
            return XrayAdapterName;

        return null;
    }

    /// <summary>
    /// Prefer an Up adapter that is actually moving. Blindly preferring DataGate
    /// would keep the graph on a leftover OpenVPN NIC during an Xray session.
    /// </summary>
    public static VpnAdapterCounters? Pick(
        IEnumerable<VpnAdapterCounters> adapters,
        IReadOnlyDictionary<string, VpnAdapterCounters>? previous = null,
        string? lastPickedName = null)
    {
        VpnAdapterCounters? dataGate = null;
        VpnAdapterCounters? xray = null;
        var up = new List<VpnAdapterCounters>(2);

        foreach (var a in adapters)
        {
            if (a.Name.Equals(OpenVpnAdapterName, StringComparison.OrdinalIgnoreCase))
            {
                dataGate = a;
                if (a.IsUp)
                    up.Add(a);
            }
            else if (a.Name.Equals(XrayAdapterName, StringComparison.OrdinalIgnoreCase))
            {
                xray = a;
                if (a.IsUp)
                    up.Add(a);
            }
        }

        if (up.Count == 1)
            return up[0];

        if (up.Count > 1)
        {
            var moving = PickMostActive(up, previous);
            if (moving is not null)
                return moving;

            var appeared = PickNewlyAppeared(up, previous);
            if (appeared is not null)
                return appeared;

            if (!string.IsNullOrWhiteSpace(lastPickedName))
            {
                foreach (var a in up)
                {
                    if (a.Name.Equals(lastPickedName, StringComparison.OrdinalIgnoreCase))
                        return a;
                }
            }
        }

        var fallbackUp = dataGate is { IsUp: true } ? dataGate : xray is { IsUp: true } ? xray : null;
        return fallbackUp ?? dataGate ?? xray;
    }

    private static VpnAdapterCounters? PickMostActive(
        List<VpnAdapterCounters> up,
        IReadOnlyDictionary<string, VpnAdapterCounters>? previous)
    {
        if (previous is null || previous.Count == 0)
            return null;

        VpnAdapterCounters? best = null;
        long bestDelta = 0;
        foreach (var a in up)
        {
            if (!previous.TryGetValue(a.Name, out var prior))
                continue;

            var delta = Math.Max(0, a.BytesReceived - prior.BytesReceived)
                        + Math.Max(0, a.BytesSent - prior.BytesSent);
            if (delta > bestDelta)
            {
                bestDelta = delta;
                best = a;
            }
        }

        return bestDelta > 0 ? best : null;
    }

    /// <summary>
    /// Protocol switch: leftover DataGate stays Up while xray0 appears (or the reverse).
    /// </summary>
    private static VpnAdapterCounters? PickNewlyAppeared(
        List<VpnAdapterCounters> up,
        IReadOnlyDictionary<string, VpnAdapterCounters>? previous)
    {
        if (previous is null || previous.Count == 0)
            return null;

        VpnAdapterCounters? appeared = null;
        var count = 0;
        foreach (var a in up)
        {
            if (previous.ContainsKey(a.Name))
                continue;
            appeared = a;
            count++;
        }

        return count == 1 ? appeared : null;
    }
}
