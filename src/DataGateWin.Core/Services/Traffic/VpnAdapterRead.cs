namespace DataGateWin.Services.Traffic;

public readonly record struct VpnAdapterRead(
    VpnAdapterCounters? Counters,
    string? ErrorLocKey,
    Exception? Error)
{
    public static VpnAdapterRead Ok(VpnAdapterCounters? counters)
        => new(counters, null, null);

    public static VpnAdapterRead Fail(Exception ex)
        => new(null, LiveTrafficError.LocKey(ex), ex);

    public bool Failed => ErrorLocKey is not null;
}
