namespace DataGateWin.Services.Traffic;

public readonly record struct LiveTrafficTick(
    double InBytesPerSec,
    double OutBytesPerSec,
    long SessionInBytes,
    long SessionOutBytes,
    string? AdapterName);
