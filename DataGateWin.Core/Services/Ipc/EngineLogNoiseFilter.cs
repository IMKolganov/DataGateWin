using System.Text;

namespace DataGateWin.Services.Ipc;

/// <summary>
/// Collapses high-volume engine chatter (IP-list route adds, bridge stats) so a 1k-line
/// UI journal is not filled with thousands of near-identical IPC events first.
/// </summary>
public sealed class EngineLogNoiseFilter
{
    private readonly object _gate = new();
    private readonly long _wssStatsMinIntervalMs;
    private int _routeAttempts;
    private int _routeFailures5010;
    private int _routeOtherFailures;
    private string? _lastEmitted;
    private long _lastWssStatsTick;

    public EngineLogNoiseFilter(TimeSpan? wssStatsMinInterval = null)
    {
        _wssStatsMinIntervalMs = (long)(wssStatsMinInterval ?? TimeSpan.FromSeconds(10)).TotalMilliseconds;
    }

    /// <summary>
    /// Returns the line to show, a summary replacing suppressed noise, or null to drop.
    /// </summary>
    public string? Filter(string line)
    {
        if (string.IsNullOrWhiteSpace(line))
            return null;

        var trimmed = line.TrimEnd();

        lock (_gate)
        {
            if (IsXrayAccessNoise(trimmed))
                return null;

            if (IsRouteNoise(trimmed, out var isFailure, out var is5010))
            {
                _routeAttempts++;
                if (isFailure)
                {
                    if (is5010)
                        _routeFailures5010++;
                    else
                        _routeOtherFailures++;
                }

                return null;
            }

            var flushed = FlushRouteSummaryLocked();

            if (IsWssUdpStats(trimmed))
            {
                var now = Environment.TickCount64;
                if (_lastWssStatsTick != 0 && now - _lastWssStatsTick < _wssStatsMinIntervalMs)
                    return flushed;

                _lastWssStatsTick = now;
            }

            if (string.Equals(trimmed, _lastEmitted, StringComparison.Ordinal))
                return flushed;

            _lastEmitted = trimmed;

            if (flushed == null)
                return trimmed;

            return flushed + Environment.NewLine + trimmed;
        }
    }

    /// <summary>Emit any pending route summary (e.g. on disconnect).</summary>
    public string? Flush()
    {
        lock (_gate)
            return FlushRouteSummaryLocked();
    }

    private string? FlushRouteSummaryLocked()
    {
        if (_routeAttempts <= 0)
            return null;

        var sb = new StringBuilder(160);
        sb.Append("[ui] IP-list routes: attempted=").Append(_routeAttempts);
        if (_routeFailures5010 > 0)
            sb.Append(" already_exist(5010)=").Append(_routeFailures5010);
        if (_routeOtherFailures > 0)
            sb.Append(" other_fail=").Append(_routeOtherFailures);
        var ok = _routeAttempts - _routeFailures5010 - _routeOtherFailures;
        if (ok > 0)
            sb.Append(" ok≈").Append(ok);
        if (_routeFailures5010 > 0 && _routeFailures5010 >= _routeAttempts / 2)
            sb.Append(" (5010 = route already in Windows table; not fatal)");

        _routeAttempts = 0;
        _routeFailures5010 = 0;
        _routeOtherFailures = 0;

        var summary = sb.ToString();
        _lastEmitted = summary;
        return summary;
    }

    internal static bool IsRouteNoise(string line, out bool isFailure, out bool is5010)
    {
        isFailure = false;
        is5010 = false;

        if (line.Contains("IPHelper: add route", StringComparison.OrdinalIgnoreCase))
            return true;

        if (line.StartsWith("cannot modify route:", StringComparison.OrdinalIgnoreCase))
        {
            isFailure = true;
            is5010 = line.Contains("5010", StringComparison.Ordinal);
            return true;
        }

        if (line.Contains("route addition failed", StringComparison.OrdinalIgnoreCase) ||
            line.Contains("CreateIpForwardEntry", StringComparison.OrdinalIgnoreCase))
        {
            isFailure = true;
            is5010 = line.Contains("5010", StringComparison.Ordinal) ||
                     line.Contains("already exists", StringComparison.OrdinalIgnoreCase);
            return true;
        }

        return false;
    }

    /// <summary>
    /// Xray access lines for link-local NetBIOS / tun-in→direct private chatter.
    /// </summary>
    internal static bool IsXrayAccessNoise(string line)
    {
        // e.g. from udp:169.254.57.70:65187 accepted udp:169.254.255.255:137 [tun-in -> direct]
        if (!line.Contains("accepted", StringComparison.OrdinalIgnoreCase))
            return false;
        if (!line.Contains("[tun-in", StringComparison.OrdinalIgnoreCase))
            return false;

        if (line.Contains(":137 ", StringComparison.Ordinal)
            || line.Contains(":138 ", StringComparison.Ordinal)
            || line.Contains(":139 ", StringComparison.Ordinal))
            return true;

        if (line.Contains("169.254.", StringComparison.Ordinal)
            && line.Contains("-> direct]", StringComparison.OrdinalIgnoreCase))
            return true;

        return false;
    }

    private static bool IsWssUdpStats(string line) =>
        line.Contains("[wss-bridge] udp stats", StringComparison.OrdinalIgnoreCase);
}
