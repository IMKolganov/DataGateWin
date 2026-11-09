namespace DataGateWin.Services.Ipc;

public static class EngineState
{
    public static bool IsIdle(string? state)
    {
        if (string.IsNullOrWhiteSpace(state))
            return true;

        return state.Trim().Equals("idle", StringComparison.OrdinalIgnoreCase);
    }

    /// <summary>GetStatus failed or reply had no state — do not treat as idle or connected.</summary>
    public static bool IsUnknown(string? state) => state is null;

    public static bool EqualsIgnore(string? state, string expected) =>
        !string.IsNullOrWhiteSpace(state)
        && state.Trim().Equals(expected, StringComparison.OrdinalIgnoreCase);

    /// <summary>Tunnel is (or was) live enough that UI must not Start without Stop first when switching targets.</summary>
    public static bool IsLiveSession(string? state) =>
        EqualsIgnore(state, "connected")
        || EqualsIgnore(state, "connecting")
        || EqualsIgnore(state, "starting")
        || EqualsIgnore(state, "stopping");

    public static bool IsConnected(string? state) => EqualsIgnore(state, "connected");

    /// <summary>
    /// Terminal/broken phases that look "non-idle" but are not a usable tunnel
    /// (false Connected UI + StopSession WaitForIdle hang if ignored).
    /// </summary>
    public static bool NeedsCleanup(string? state) =>
        EqualsIgnore(state, "stopped")
        || EqualsIgnore(state, "error");
}
