using System.Net.NetworkInformation;

namespace DataGateWin.Services.Traffic;

/// <summary>Reads IN/OUT octet counters from the local Wintun VPN adapter.</summary>
public sealed class VpnAdapterTrafficSampler
{
    private readonly Dictionary<string, VpnAdapterCounters> _previous = new(StringComparer.OrdinalIgnoreCase);
    private string? _lastPickedName;

    public VpnAdapterRead TryRead()
    {
        try
        {
            var found = new List<VpnAdapterCounters>(2);
            foreach (var nic in NetworkInterface.GetAllNetworkInterfaces())
            {
                try
                {
                    if (!TryMatchKnownAdapter(nic, out var known))
                        continue;

                    if (!TryReadOctets(nic, out var rx, out var tx))
                        continue;

                    var up = false;
                    try
                    {
                        up = nic.OperationalStatus == OperationalStatus.Up;
                    }
                    catch (Exception)
                    {
                        // Adapter can vanish between enumerate and status.
                    }

                    found.Add(new VpnAdapterCounters(known, rx, tx, up));
                }
                catch (Exception)
                {
                    // One broken NIC must not fail the whole sample.
                }
            }

            var picked = VpnAdapterTrafficPicker.Pick(found, _previous, _lastPickedName);

            _previous.Clear();
            foreach (var a in found)
                _previous[a.Name] = a;

            _lastPickedName = picked?.Name;
            return VpnAdapterRead.Ok(picked);
        }
        catch (Exception ex)
        {
            _previous.Clear();
            _lastPickedName = null;
            return VpnAdapterRead.Fail(ex);
        }
    }

    private static bool TryMatchKnownAdapter(NetworkInterface nic, out string known)
    {
        known = "";
        string? name = null;
        string? description = null;
        try { name = nic.Name; }
        catch (Exception) { /* ignore */ }
        try { description = nic.Description; }
        catch (Exception) { /* ignore */ }

        var match = VpnAdapterTrafficPicker.CanonicalName(name)
                    ?? VpnAdapterTrafficPicker.CanonicalName(description);
        if (match is null)
            return false;

        known = match;
        return true;
    }

    private static bool TryReadOctets(NetworkInterface nic, out long rx, out long tx)
    {
        rx = 0;
        tx = 0;
        try
        {
            var s = nic.GetIPStatistics();
            rx = s.BytesReceived;
            tx = s.BytesSent;
            return true;
        }
        catch (Exception)
        {
            // fall through to IPv4-only
        }

        try
        {
            var s = nic.GetIPv4Statistics();
            rx = s.BytesReceived;
            tx = s.BytesSent;
            return true;
        }
        catch (Exception)
        {
            return false;
        }
    }
}
