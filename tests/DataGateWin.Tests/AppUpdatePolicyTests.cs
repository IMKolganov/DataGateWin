using System.Diagnostics;
using DataGateWin.Services.Update;
using Xunit;

namespace DataGateWin.Tests;

public sealed class AppUpdatePolicyTests
{
    [Theory]
    [InlineData("1.0.19", "1.0.18", true)]
    [InlineData("1.0.18", "1.0.18", false)]
    [InlineData("1.0.17", "1.0.18", false)]
    [InlineData("2.0.0", "1.9.9", true)]
    public void ShouldOfferUpgrade_ComparesStrictlyNewer(string latest, string current, bool expected)
    {
        Assert.Equal(
            expected,
            AppUpdatePolicy.ShouldOfferUpgrade(
                ReleaseVersionParser.ParseTag(latest),
                ReleaseVersionParser.ParseTag(current)));
    }

    [Fact]
    public void ShouldOfferUpgrade_RejectsNullAndZeroVersions()
    {
        Assert.False(AppUpdatePolicy.ShouldOfferUpgrade(null, new Version(1, 0, 0)));
        Assert.False(AppUpdatePolicy.ShouldOfferUpgrade(new Version(1, 0, 0), null));
        Assert.False(AppUpdatePolicy.ShouldOfferUpgrade(new Version(0, 0, 0), new Version(1, 0, 0)));
        Assert.False(AppUpdatePolicy.ShouldOfferUpgrade(new Version(1, 0, 0), new Version(0, 0, 0)));
    }

    [Fact]
    public void ResolveCurrentAppVersion_ReadsMainExeFromInstallFolder_IgnoresInstallerSubfolder()
    {
        var root = Path.Combine(Path.GetTempPath(), "DataGateVer_" + Guid.NewGuid().ToString("N"));
        var installerDir = Path.Combine(root, "Installer");
        Directory.CreateDirectory(installerDir);
        try
        {
            var pe = typeof(AppUpdatePolicyTests).Assembly.Location;
            File.Copy(pe, Path.Combine(root, AppUpdatePolicy.MainExeFileName));
            File.WriteAllText(Path.Combine(installerDir, AppInstallerLocator.InstallerExeName), "not-a-pe");

            var expected = ReadPeVersion(pe);
            Assert.NotNull(expected);

            var actual = AppUpdatePolicy.ResolveCurrentAppVersion(
                entryAssemblyLocation: Path.Combine(root, "ignored.dll"),
                assemblyVersion: new Version(9, 9, 9, 9),
                installDirectory: root);

            Assert.Equal(expected, actual);
            Assert.False(AppUpdatePolicy.IsSameBuild(actual, new Version(9, 9, 9, 9)));
        }
        finally
        {
            try { Directory.Delete(root, recursive: true); } catch { /* ignore */ }
        }
    }

    [Fact]
    public void ResolveCurrentAppVersion_FallsBackToDllWhenExeMissing()
    {
        var root = Path.Combine(Path.GetTempPath(), "DataGateVer_" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(root);
        try
        {
            var pe = typeof(AppUpdatePolicyTests).Assembly.Location;
            File.Copy(pe, Path.Combine(root, AppUpdatePolicy.MainDllFileName));

            var expected = ReadPeVersion(pe);
            Assert.NotNull(expected);

            var actual = AppUpdatePolicy.ResolveCurrentAppVersion(
                assemblyVersion: new Version(9, 9, 9, 9),
                installDirectory: root);

            Assert.Equal(expected, actual);
        }
        finally
        {
            try { Directory.Delete(root, recursive: true); } catch { /* ignore */ }
        }
    }

    [Fact]
    public void ResolveCurrentAppVersion_FallsBackToAssemblyWhenFolderEmpty()
    {
        var missingRoot = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString("N"));
        var v = AppUpdatePolicy.ResolveCurrentAppVersion(
            entryAssemblyLocation: Path.Combine(Path.GetTempPath(), Guid.NewGuid() + ".exe"),
            assemblyVersion: new Version(1, 2, 3, 4),
            installDirectory: missingRoot);
        Assert.Equal(new Version(1, 2, 3, 4), v);
    }

    [Fact]
    public void EnumerateInstallFolderVersionFiles_OnlyRootExeAndDll()
    {
        var root = Path.Combine(Path.GetTempPath(), "DataGateVer_" + Guid.NewGuid().ToString("N"));
        var files = AppUpdatePolicy.EnumerateInstallFolderVersionFiles(root).ToArray();
        Assert.Equal(2, files.Length);
        Assert.EndsWith(AppUpdatePolicy.MainExeFileName, files[0], StringComparison.OrdinalIgnoreCase);
        Assert.EndsWith(AppUpdatePolicy.MainDllFileName, files[1], StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain(
            files,
            f => f.Contains($"{Path.DirectorySeparatorChar}Installer{Path.DirectorySeparatorChar}", StringComparison.OrdinalIgnoreCase));
    }

    [Theory]
    [InlineData("1.0.19", "1.0.19", true)]
    [InlineData("1.0.19.0", "1.0.19", true)]
    [InlineData("1.0.18", "1.0.19", false)]
    [InlineData(null, "1.0.19", false)]
    public void IsSameBuild_MatchesFourPartIdentity(string? a, string b, bool expected)
    {
        var left = a is null ? null : AppUpdatePolicy.TryParseVersion(a);
        var right = AppUpdatePolicy.TryParseVersion(b);
        Assert.Equal(expected, AppUpdatePolicy.IsSameBuild(left, right));
    }

    [Theory]
    [InlineData("update", true)]
    [InlineData("UPDATE", true)]
    [InlineData("--update", false)]
    [InlineData("", false)]
    [InlineData(null, false)]
    public void IsInstallerUpdateArgument_MatchesAppLaunchContract(string? arg, bool expected)
        => Assert.Equal(expected, AppUpdatePolicy.IsInstallerUpdateArgument(arg));

    [Fact]
    public void IsProgramFilesStyleUpdaterLayout_RequiresExeAndInstallerSubfolder()
    {
        var root = Path.Combine(Path.GetTempPath(), "DataGateLayout_" + Guid.NewGuid().ToString("N"));
        var installerDir = Path.Combine(root, "Installer");
        Directory.CreateDirectory(installerDir);
        try
        {
            Assert.False(AppUpdatePolicy.IsProgramFilesStyleUpdaterLayout(root));

            File.WriteAllText(Path.Combine(root, AppUpdatePolicy.MainExeFileName), "app");
            Assert.False(AppUpdatePolicy.IsProgramFilesStyleUpdaterLayout(root));

            File.WriteAllText(
                Path.Combine(installerDir, AppInstallerLocator.InstallerExeName),
                "installer");
            Assert.True(AppUpdatePolicy.IsProgramFilesStyleUpdaterLayout(root));
        }
        finally
        {
            try { Directory.Delete(root, recursive: true); } catch { /* ignore */ }
        }
    }

    [Fact]
    public void PartialUpdateMismatch_ShouldStillOfferUpgrade_WhenExeOlderThanLatest()
    {
        Assert.True(AppUpdatePolicy.ShouldOfferUpgrade(
            ReleaseVersionParser.ParseTag("1.0.19"),
            ReleaseVersionParser.ParseTag("1.0.18")));
        Assert.False(AppUpdatePolicy.ShouldOfferUpgrade(
            ReleaseVersionParser.ParseTag("1.0.19"),
            ReleaseVersionParser.ParseTag("1.0.19")));
    }

    [Fact]
    public void TryParseVersion_HandlesJunk()
    {
        Assert.Null(AppUpdatePolicy.TryParseVersion(null));
        Assert.Null(AppUpdatePolicy.TryParseVersion(""));
        Assert.Null(AppUpdatePolicy.TryParseVersion("not-a-version"));
        Assert.Equal(new Version(1, 0, 19, 0), AppUpdatePolicy.TryParseVersion("1.0.19"));
    }

    [Fact]
    public void DualLayout_ProgramFilesStyle_VersionFromRoot_UpdaterUnderInstaller()
    {
        var root = Path.Combine(Path.GetTempPath(), "DataGateBoth_" + Guid.NewGuid().ToString("N"));
        var installerDir = Path.Combine(root, "Installer");
        Directory.CreateDirectory(installerDir);
        try
        {
            var pe = typeof(AppUpdatePolicyTests).Assembly.Location;
            File.Copy(pe, Path.Combine(root, AppUpdatePolicy.MainExeFileName));
            File.Copy(pe, Path.Combine(root, AppUpdatePolicy.MainDllFileName));
            File.Copy(pe, Path.Combine(installerDir, AppInstallerLocator.InstallerExeName));

            var product = AppUpdatePolicy.ResolveCurrentAppVersion(installDirectory: root);
            var expected = ReadPeVersion(pe);
            Assert.Equal(expected, product);

            Assert.True(AppUpdatePolicy.IsProgramFilesStyleUpdaterLayout(root));
            Assert.Equal(
                Path.Combine(installerDir, AppInstallerLocator.InstallerExeName),
                AppInstallerLocator.TryFindInstallerExe(root));

            // Poison leftover offline package must not change product version reading.
            var poison = Path.Combine(root, "DataGateWinBuild.v9.9.9");
            Directory.CreateDirectory(poison);
            File.Copy(pe, Path.Combine(poison, AppUpdatePolicy.MainExeFileName));
            Assert.Equal(expected, AppUpdatePolicy.ResolveCurrentAppVersion(installDirectory: root));
        }
        finally
        {
            try { Directory.Delete(root, recursive: true); } catch { /* ignore */ }
        }
    }

    [Fact]
    public void DualLayout_DevOrLoosePublish_VersionFromRoot_NoInstallerFolder()
    {
        var root = Path.Combine(Path.GetTempPath(), "DataGateDev_" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(root);
        try
        {
            var pe = typeof(AppUpdatePolicyTests).Assembly.Location;
            File.Copy(pe, Path.Combine(root, AppUpdatePolicy.MainExeFileName));

            var product = AppUpdatePolicy.ResolveCurrentAppVersion(installDirectory: root);
            Assert.Equal(ReadPeVersion(pe), product);

            Assert.False(AppUpdatePolicy.IsProgramFilesStyleUpdaterLayout(root));
            Assert.Null(AppInstallerLocator.TryFindInstallerExe(root));
        }
        finally
        {
            try { Directory.Delete(root, recursive: true); } catch { /* ignore */ }
        }
    }

    [Fact]
    public void DualLayout_OfflineSiblingBuild_FoundForFreshInstall_NotForVersion()
    {
        var root = Path.Combine(Path.GetTempPath(), "DataGateOffline_" + Guid.NewGuid().ToString("N"));
        var installerDir = Path.Combine(root, "Installer");
        var build = Path.Combine(root, "DataGateWinBuild.v1.0.20");
        Directory.CreateDirectory(installerDir);
        Directory.CreateDirectory(build);
        try
        {
            var pe = typeof(AppUpdatePolicyTests).Assembly.Location;
            // Installer sits next to offline package (publish QA layout).
            File.Copy(pe, Path.Combine(installerDir, AppInstallerLocator.InstallerExeName));
            File.Copy(pe, Path.Combine(build, AppUpdatePolicy.MainExeFileName));

            Assert.Equal(Path.GetFullPath(build), DataGateWin.Installer.LocalBuildPackage.TryFind(installerDir));

            // Install root without product exe/dll → assembly fallback; never reads DataGateWinBuild*.
            var v = AppUpdatePolicy.ResolveCurrentAppVersion(
                assemblyVersion: new Version(3, 3, 3),
                installDirectory: root);
            Assert.Equal(new Version(3, 3, 3, 0), v);
        }
        finally
        {
            try { Directory.Delete(root, recursive: true); } catch { /* ignore */ }
        }
    }

    static Version? ReadPeVersion(string path)
    {
        var fvi = FileVersionInfo.GetVersionInfo(path);
        return AppUpdatePolicy.TryParseVersion(fvi.FileVersion)
               ?? AppUpdatePolicy.TryParseVersion(fvi.ProductVersion);
    }
}
