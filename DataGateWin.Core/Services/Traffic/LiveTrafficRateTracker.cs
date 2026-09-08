namespace DataGateWin.Services.Traffic;

/// <summary>
/// Turns cumulative NIC octet counters into IN/OUT rates, same idea as OpenVPN GUI bytecount.
/// </summary>
public sealed class LiveTrafficRateTracker
{
    /// <summary>Sleep / background gaps longer than this start a new baseline (avoids a fake spike).</summary>
    public static readonly TimeSpan MaxSampleGap = TimeSpan.FromSeconds(5);

    private string? _adapterName;
    private long _lastRx;
    private long _lastTx;
    private DateTime _lastUtc;
    private bool _hasLast;
    private long _sessionStartRx;
    private long _sessionStartTx;

    public LiveTrafficTick Push(VpnAdapterCounters? snapshot, DateTime utcNow)
    {
        if (snapshot is null)
        {
            Reset();
            return default;
        }

        var now = snapshot.Value;
        if (!_hasLast
            || !string.Equals(_adapterName, now.Name, StringComparison.OrdinalIgnoreCase)
            || utcNow - _lastUtc > MaxSampleGap
            || now.BytesReceived < _lastRx
            || now.BytesSent < _lastTx)
        {
            _adapterName = now.Name;
            _lastRx = now.BytesReceived;
            _lastTx = now.BytesSent;
            _lastUtc = utcNow;
            _hasLast = true;
            _sessionStartRx = now.BytesReceived;
            _sessionStartTx = now.BytesSent;
            return new LiveTrafficTick(0, 0, 0, 0, now.Name);
        }

        var dt = (utcNow - _lastUtc).TotalSeconds;
        if (dt <= 0)
            return new LiveTrafficTick(0, 0, SessionIn(now), SessionOut(now), now.Name);

        var inRate = (now.BytesReceived - _lastRx) / dt;
        var outRate = (now.BytesSent - _lastTx) / dt;
        _lastRx = now.BytesReceived;
        _lastTx = now.BytesSent;
        _lastUtc = utcNow;

        return new LiveTrafficTick(inRate, outRate, SessionIn(now), SessionOut(now), now.Name);
    }

    public void Reset()
    {
        _adapterName = null;
        _lastRx = 0;
        _lastTx = 0;
        _lastUtc = default;
        _hasLast = false;
        _sessionStartRx = 0;
        _sessionStartTx = 0;
    }

    private long SessionIn(VpnAdapterCounters now) => Math.Max(0, now.BytesReceived - _sessionStartRx);

    private long SessionOut(VpnAdapterCounters now) => Math.Max(0, now.BytesSent - _sessionStartTx);
}
