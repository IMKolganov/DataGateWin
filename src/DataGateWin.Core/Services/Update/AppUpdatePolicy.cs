using System.Diagnostics;
using System.IO;
using System.Reflection;

namespace DataGateWin.Services.Update;

/// <summary>
/// Update decisions. Installed app version = FileVersion of files in the install folder
/// (<c>DataGateWin.exe</c>, then <c>DataGateWin.dll</c>). The nested <c>Installer\</c> binary
/// is a helper and must not be treated as the product version.
/// </summary>
public static class AppUpdatePolicy
{
    public const string MainExeFileName = "DataGateWin.exe";
    public const string MainDllFileName = "DataGateWin.dll";

    /// <summary>
    /// True when GitHub latest is strictly newer than the running build.
    /// </summary>
    public static bool ShouldOfferUpgrade(Version? latestRelease, Version? currentApp)
    {
        if (latestRelease is null || currentApp is null)
            return false;
        if (IsZero(latestRelease) || IsZero(currentApp))
            return false;
        return ReleaseVersionParser.IsUpgradeAvailable(latestRelease, currentApp);
    }

    /// <summary>
    /// Version of the installed product from the install folder contents.
    /// Order: <c>{dir}\DataGateWin.exe</c> → <c>{dir}\DataGateWin.dll</c> → assembly fallback.
    /// Never reads <c>Installer\DataGateWin.Installer.exe</c>.
    /// </summary>
    public static Version ResolveCurrentAppVersion(
        string? entryAssemblyLocation = null,
        Version? assemblyVersion = null,
        string? installDirectory = null)
    {
        var dir = ResolveInstallDirectory(installDirectory, entryAssemblyLocation);
        if (!string.IsNullOrWhiteSpace(dir))
        {
            foreach (var name in new[] { MainExeFileName, MainDllFileName })
            {
                var fromFile = TryReadFileVersion(Path.Combine(dir, name));
                if (fromFile is not null && !IsZero(fromFile))
                    return Normalize(fromFile);
            }
        }

        if (assemblyVersion is not null && !IsZero(assemblyVersion))
            return Normalize(assemblyVersion);

        try
        {
            var asm = Assembly.GetEntryAssembly()?.GetName().Version;
            if (asm is not null && !IsZero(asm))
                return Normalize(asm);
        }
        catch
        {
            // ignore
        }

        return new Version(0, 0, 0);
    }

    /// <summary>
    /// Install root = folder that contains (or should contain) <see cref="MainExeFileName"/>.
    /// </summary>
    public static string? ResolveInstallDirectory(
        string? installDirectory = null,
        string? entryAssemblyLocation = null)
    {
        if (!string.IsNullOrWhiteSpace(installDirectory))
        {
            try { return Path.GetFullPath(installDirectory); }
            catch { /* fall through */ }
        }

        try
        {
            var baseDir = AppContext.BaseDirectory;
            if (!string.IsNullOrWhiteSpace(baseDir))
                return Path.GetFullPath(baseDir);
        }
        catch
        {
            // fall through
        }

        if (!string.IsNullOrWhiteSpace(entryAssemblyLocation))
        {
            try
            {
                var parent = Path.GetDirectoryName(Path.GetFullPath(entryAssemblyLocation));
                if (!string.IsNullOrWhiteSpace(parent))
                    return parent;
            }
            catch
            {
                // ignore
            }
        }

        return null;
    }

    /// <summary>Files in the install folder used for product version (not Installer\).</summary>
    public static IEnumerable<string> EnumerateInstallFolderVersionFiles(string? installDirectory = null)
    {
        var dir = ResolveInstallDirectory(installDirectory);
        if (string.IsNullOrWhiteSpace(dir))
            yield break;

        yield return Path.Combine(dir, MainExeFileName);
        yield return Path.Combine(dir, MainDllFileName);
    }

    public static bool IsSameBuild(Version? onDisk, Version? other)
    {
        if (onDisk is null || other is null)
            return false;
        return onDisk.Major == other.Major
            && onDisk.Minor == other.Minor
            && onDisk.Build == other.Build
            && onDisk.Revision == other.Revision;
    }

    public static Version? TryParseVersion(string? s)
    {
        if (string.IsNullOrWhiteSpace(s))
            return null;
        var trimmed = s.Trim();
        if (Version.TryParse(trimmed, out var v))
            return Normalize(v);
        try
        {
            return Normalize(new Version(trimmed));
        }
        catch
        {
            return null;
        }
    }

    public static bool IsInstallerUpdateArgument(string? argument)
        => string.Equals(
            argument?.Trim(),
            AppInstallerLocator.InstallerUpdateArgument,
            StringComparison.OrdinalIgnoreCase);

    /// <summary>
    /// Normal install layout: product exe in root, updater under <c>Installer\</c>.
    /// </summary>
    public static bool IsProgramFilesStyleUpdaterLayout(string? installRoot)
    {
        if (string.IsNullOrWhiteSpace(installRoot) || !Directory.Exists(installRoot))
            return false;

        var exe = Path.Combine(installRoot, MainExeFileName);
        var updater = Path.Combine(installRoot, "Installer", AppInstallerLocator.InstallerExeName);
        return File.Exists(exe) && File.Exists(updater);
    }

    static Version? TryReadFileVersion(string path)
    {
        try
        {
            if (string.IsNullOrWhiteSpace(path) || !File.Exists(path))
                return null;
            var fvi = FileVersionInfo.GetVersionInfo(path);
            return TryParseVersion(fvi.FileVersion) ?? TryParseVersion(fvi.ProductVersion);
        }
        catch
        {
            return null;
        }
    }

    static bool IsZero(Version v) => v.Major == 0 && v.Minor == 0 && v.Build <= 0;

    static Version Normalize(Version v)
        => new(v.Major, v.Minor, Math.Max(v.Build, 0), Math.Max(v.Revision, 0));
}
