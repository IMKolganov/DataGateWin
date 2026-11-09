namespace DataGateWin.Services.Traffic;

public readonly record struct VpnAdapterCounters(
    string Name,
    long BytesReceived,
    long BytesSent,
    bool IsUp);
