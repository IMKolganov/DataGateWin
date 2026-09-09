using DataGateWin.Services.Update;
using Xunit;

namespace DataGateWin.Tests;

public sealed class AppInstallerLocatorTests
{
    [Fact]
    public void EnumerateCandidatePaths_CoversInstallerInstallerAndRoot()
    {
        var root = Path.Combine(Path.GetTempPath(), "DataGateLocator_" + Guid.NewGuid().ToString("N"));
        var paths = AppInstallerLocator.EnumerateCandidatePaths(root).ToArray();

        Assert.Equal(3, paths.Length);
        Assert.Equal(Path.Combine(root, "Installer", AppInstallerLocator.InstallerExeName), paths[0]);
        Assert.Equal(Path.Combine(root, "installer", AppInstallerLocator.InstallerExeName), paths[1]);
        Assert.Equal(Path.Combine(root, AppInstallerLocator.InstallerExeName), paths[2]);
    }

    [Fact]
    public void TryFindInstallerExe_ReturnsNullWhenMissing()
    {
        var root = Path.Combine(Path.GetTempPath(), "DataGateLocator_" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(root);
        try
        {
            Assert.Null(AppInstallerLocator.TryFindInstallerExe(root));
        }
        finally
        {
            try { Directory.Delete(root, recursive: true); } catch { /* ignore */ }
        }
    }

    [Fact]
    public void TryFindInstallerExe_PrefersInstallerSubfolder()
    {
        var root = Path.Combine(Path.GetTempPath(), "DataGateLocator_" + Guid.NewGuid().ToString("N"));
        var installerDir = Path.Combine(root, "Installer");
        Directory.CreateDirectory(installerDir);
        var nested = Path.Combine(installerDir, AppInstallerLocator.InstallerExeName);
        var rootExe = Path.Combine(root, AppInstallerLocator.InstallerExeName);
        File.WriteAllText(nested, "installer");
        File.WriteAllText(rootExe, "root");

        try
        {
            Assert.Equal(nested, AppInstallerLocator.TryFindInstallerExe(root));
        }
        finally
        {
            try { Directory.Delete(root, recursive: true); } catch { /* ignore */ }
        }
    }

    [Fact]
    public void TryFindInstallerExe_FindsRootWhenNoSubfolder()
    {
        var root = Path.Combine(Path.GetTempPath(), "DataGateLocator_" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(root);
        var rootExe = Path.Combine(root, AppInstallerLocator.InstallerExeName);
        File.WriteAllText(rootExe, "root");

        try
        {
            Assert.Equal(rootExe, AppInstallerLocator.TryFindInstallerExe(root));
        }
        finally
        {
            try { Directory.Delete(root, recursive: true); } catch { /* ignore */ }
        }
    }

    [Fact]
    public void TryFindInstallerExe_NullOrBlankBase_ReturnsNull()
    {
        Assert.Null(AppInstallerLocator.TryFindInstallerExe(null));
        Assert.Null(AppInstallerLocator.TryFindInstallerExe(""));
        Assert.Null(AppInstallerLocator.TryFindInstallerExe("   "));
    }

    [Fact]
    public void UpdateArgument_IsBareUpdate_ForProcessStartContract()
    {
        Assert.Equal("update", AppInstallerLocator.InstallerUpdateArgument);
        Assert.True(AppUpdatePolicy.IsInstallerUpdateArgument(AppInstallerLocator.InstallerUpdateArgument));
    }
}
