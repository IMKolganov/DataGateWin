using DataGateWin.Models.Ipc;

namespace DataGateWin.Services.VpnServers;

/// <summary>Pure helpers for Home VPN session UI (unit-tested without WPF).</summary>
public static class HomeSessionUiPolicy
{
    /// <summary>
    /// After StartSession ReplyOk, wait this long for Connected/Error before forcing stop.
    /// Direct OpenVPN can otherwise sit in CONNECTING forever (no WSS bridge fail-fast).
    /// </summary>
    public static readonly TimeSpan ConnectEventWatchdog = TimeSpan.FromSeconds(75);

    /// <summary>
    /// Keep server/VPN identity across brief Idle/Disconnected while the user still wants VPN
    /// (auto-reconnect). Clearing would wipe the Home footer before StartSession rebuilds it.
    /// </summary>
    public static bool ShouldClearSessionIdentity(bool desiredConnected) => !desiredConnected;

    public static bool IsHomeConnectEnabled(UiState state) => state == UiState.Idle;

    /// <summary>
    /// Disconnect must stay clickable while Connecting (cancel hang on “waiting for events”).
    /// Tray already allows this; Home previously disabled Disconnect whenever busy.
    /// </summary>
    public static bool IsHomeDisconnectEnabled(UiState state) =>
        state is UiState.Connected or UiState.Connecting;

    /// <summary>Live traffic chart is only for an established session.</summary>
    public static bool IsHomeTrafficVisible(UiState state) => state == UiState.Connected;

    public static bool IsBareConnectionPhase(string? label) =>
        !string.IsNullOrWhiteSpace(label)
        && (label.Equals("connected", StringComparison.OrdinalIgnoreCase)
            || label.Equals("connecting", StringComparison.OrdinalIgnoreCase)
            || label.Equals("starting", StringComparison.OrdinalIgnoreCase));

    public static bool IsRawEnginePhaseStatus(string status) =>
        status.Contains("(connected)", StringComparison.OrdinalIgnoreCase)
        || status.Contains("(connecting)", StringComparison.OrdinalIgnoreCase)
        || status.Contains("(starting)", StringComparison.OrdinalIgnoreCase);

    /// <summary>
    /// Prefer server name, then VPN IP, then last rich status; never "Connected (connected)".
    /// </summary>
    public static string ComposeConnectedStatus(
        string? serverName,
        string? vpnIp,
        string? engineState,
        string? lastStatusText,
        bool lastWasConnected,
        string connectedPlain,
        string connectedServerFmt,
        string connectedIpFmt,
        string connectedFmt)
    {
        if (!string.IsNullOrWhiteSpace(serverName))
            return string.Format(connectedServerFmt, serverName);

        if (!string.IsNullOrWhiteSpace(vpnIp))
            return string.Format(connectedIpFmt, vpnIp);

        if (!string.IsNullOrWhiteSpace(lastStatusText)
            && lastWasConnected
            && !IsRawEnginePhaseStatus(lastStatusText))
            return lastStatusText;

        var label = string.IsNullOrWhiteSpace(engineState) ? null : engineState.Trim();
        if (IsBareConnectionPhase(label))
            return connectedPlain;

        if (!string.IsNullOrWhiteSpace(label))
            return string.Format(connectedFmt, label);

        return connectedPlain;
    }
}
