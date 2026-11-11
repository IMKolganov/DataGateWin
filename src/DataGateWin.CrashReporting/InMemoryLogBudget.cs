namespace DataGateWin.CrashReporting;

/// <summary>
/// Caps for log-style buffers. UI journals keep the newest
/// <see cref="MaxLines"/> lines (~1 MB for typical engine lines).
/// Crash-queue / IPC use a separate byte ceiling as a safety net.
/// </summary>
public static class InMemoryLogBudget
{
    /// <summary>UI / in-memory journal: keep only the newest N lines.</summary>
    public const int MaxLines = 1000;

    /// <summary>Disk crash-queue and native IPC control queue safety ceiling.</summary>
    public const long MaxQueueBytes = 8L * 1024 * 1024;

    /// <summary>
    /// Append a line and drop oldest entries so count stays ≤ <paramref name="maxLines"/>.
    /// Returns true when oldest lines were removed (caller should rebuild bound UI text).
    /// </summary>
    public static bool AppendLine(IList<string> lines, string line, int maxLines = MaxLines)
    {
        ArgumentNullException.ThrowIfNull(lines);
        ArgumentNullException.ThrowIfNull(line);
        if (maxLines < 1)
            throw new ArgumentOutOfRangeException(nameof(maxLines));

        lines.Add(line);
        var overflow = lines.Count - maxLines;
        if (overflow <= 0)
            return false;

        if (lines is List<string> list)
        {
            list.RemoveRange(0, overflow);
        }
        else
        {
            for (var i = 0; i < overflow; i++)
                lines.RemoveAt(0);
        }

        return true;
    }

    public static string JoinLinesForTextBox(IReadOnlyList<string> lines)
    {
        ArgumentNullException.ThrowIfNull(lines);
        if (lines.Count == 0)
            return string.Empty;

        return string.Join(Environment.NewLine, lines) + Environment.NewLine;
    }
}
