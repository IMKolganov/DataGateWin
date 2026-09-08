namespace DataGateWin.Services.Security;

public static class TorrentProcessDetector
{
    private static readonly HashSet<string> KnownTorrentProcessNames = new(StringComparer.OrdinalIgnoreCase)
    {
        "qbittorrent",
        "utorrent",
        "utorrentportable",
        "bittorrent",
        "deluge",
        "transmission-qt",
        "transmission-cli",
        "transmission-gtk",
        "transmission-daemon",
        "vuze",
        "azureus",
        "biglybt",
        "picotorrent",
        "webtorrent",
        "tribler",
        "tixati",
        "bitcomet",
        "frostwire"
    };

    public static bool IsTorrentProcessName(string? processName)
    {
        if (string.IsNullOrWhiteSpace(processName))
            return false;

        var normalized = processName.Trim();
        if (normalized.EndsWith(".exe", StringComparison.OrdinalIgnoreCase))
            normalized = normalized[..^4];

        return KnownTorrentProcessNames.Contains(normalized);
    }

    public static IReadOnlyList<string> DetectFromProcessNames(IEnumerable<string?> processNames)
    {
        return processNames
            .Where(IsTorrentProcessName)
            .Select(p => p!.Trim().EndsWith(".exe", StringComparison.OrdinalIgnoreCase) ? p.Trim()[..^4] : p!.Trim())
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .OrderBy(p => p, StringComparer.OrdinalIgnoreCase)
            .ToList();
    }
}
