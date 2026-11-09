using DataGateWin.Services.Xray;

namespace DataGateWin.Services.Profiles;

public static class ImportedXrayValidator
{
    public static bool TryValidate(string? configText, out string error)
    {
        error = "";
        if (string.IsNullOrWhiteSpace(configText))
        {
            error = "empty";
            return false;
        }

        if (XrayWindowsConfigBuilder.ExtractShareLink(configText) != null)
            return true;

        var trimmed = configText.Trim();
        if (trimmed.StartsWith("{", StringComparison.Ordinal))
        {
            try
            {
                var outbounds = XrayWindowsConfigBuilder.ExtractOutbounds(trimmed);
                if (outbounds.Count > 0)
                    return true;
            }
            catch
            {
                // fall through
            }
        }

        error = "no_xray_share";
        return false;
    }

    public static string SuggestName(string? fileName, string configText)
    {
        if (!string.IsNullOrWhiteSpace(fileName))
        {
            var bare = Path.GetFileNameWithoutExtension(fileName.Trim());
            if (!string.IsNullOrWhiteSpace(bare))
                return bare;
        }

        var share = XrayWindowsConfigBuilder.ExtractShareLink(configText);
        if (!string.IsNullOrEmpty(share))
        {
            var hash = share.IndexOf('#', StringComparison.Ordinal);
            if (hash >= 0 && hash < share.Length - 1)
            {
                var frag = Uri.UnescapeDataString(share[(hash + 1)..].Trim());
                if (!string.IsNullOrWhiteSpace(frag))
                    return frag;
            }
        }

        return "Xray profile";
    }
}
