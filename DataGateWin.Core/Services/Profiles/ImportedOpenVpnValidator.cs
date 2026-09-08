using System.Text.RegularExpressions;

namespace DataGateWin.Services.Profiles;

public static class ImportedOpenVpnValidator
{
    private static readonly Regex RemoteLine = new(
        @"^\s*remote\s+\S+",
        RegexOptions.IgnoreCase | RegexOptions.Multiline | RegexOptions.Compiled);

    public static bool TryValidate(string? configText, out string error)
    {
        error = "";
        if (string.IsNullOrWhiteSpace(configText))
        {
            error = "empty";
            return false;
        }

        var text = configText.Replace("\r\n", "\n");
        var remotes = RemoteLine.Matches(text);
        if (remotes.Count == 0)
        {
            error = "no_remote";
            return false;
        }

        if (remotes.Count > 1)
        {
            error = "multiple_remote";
            return false;
        }

        return true;
    }

    public static string SuggestName(string? fileName, string configText)
    {
        if (!string.IsNullOrWhiteSpace(fileName))
        {
            var bare = Path.GetFileNameWithoutExtension(fileName.Trim());
            if (!string.IsNullOrWhiteSpace(bare))
                return bare;
        }

        var m = RemoteLine.Match(configText ?? "");
        if (m.Success)
        {
            var parts = m.Value.Trim().Split((char[]?)null, StringSplitOptions.RemoveEmptyEntries);
            if (parts.Length >= 2)
                return parts[1];
        }

        return "OpenVPN profile";
    }
}
