using System.IO;

namespace DataGateWin.Services.Update;

public static class AppInstallerLocator
{
    public const string InstallerExeName = "DataGateWin.Installer.exe";

    public const string InstallerUpdateArgument = "update";

    /// <summary>Official download / reinstall page (full installer).</summary>
    public const string DownloadPageUrl = "https://datagateapp.com/download";

    public static string? TryFindInstallerExe()
        => TryFindInstallerExe(AppContext.BaseDirectory);

    /// <summary>
    /// Probes <c>{base}/Installer|installer|./DataGateWin.Installer.exe</c>.
    /// Returns the first existing path, or null.
    /// </summary>
    public static string? TryFindInstallerExe(string? baseDirectory)
    {
        if (string.IsNullOrWhiteSpace(baseDirectory))
            return null;

        string root;
        try
        {
            root = Path.GetFullPath(baseDirectory);
        }
        catch
        {
            return null;
        }

        foreach (var candidate in EnumerateCandidatePaths(root))
        {
            try
            {
                if (File.Exists(candidate))
                    return candidate;
            }
            catch
            {
                // ignore inaccessible candidate
            }
        }

        return null;
    }

    public static IEnumerable<string> EnumerateCandidatePaths(string baseDirectory)
    {
        yield return Path.Combine(baseDirectory, "Installer", InstallerExeName);
        yield return Path.Combine(baseDirectory, "installer", InstallerExeName);
        yield return Path.Combine(baseDirectory, InstallerExeName);
    }
}
