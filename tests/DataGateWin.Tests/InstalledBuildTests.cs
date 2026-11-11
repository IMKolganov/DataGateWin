using System.Diagnostics;
using DataGateWin.Installer;
using DataGateWin.Services.Update;
using Xunit;

namespace DataGateWin.Tests;

public sealed class InstalledBuildTests
{
    [Fact]
    public void IsSameAsInstaller_FalseWhenMissingFile()
    {
        Assert.False(InstalledBuild.IsSameAsInstaller(
            Path.Combine(Path.GetTempPath(), Guid.NewGuid() + ".exe"),
            new Version(1, 0, 19)));
    }

    [Fact]
    public void IsSameAsInstaller_ComparesFileVersionToProvidedInstallerVersion()
    {
        // Use the test host EXE / dll that has a real FileVersion.
        var path = typeof(InstalledBuildTests).Assembly.Location;
        Assert.True(File.Exists(path));

        var fvi = FileVersionInfo.GetVersionInfo(path);
        var onDisk = AppUpdatePolicy.TryParseVersion(fvi.FileVersion)
                     ?? AppUpdatePolicy.TryParseVersion(fvi.ProductVersion);
        Assert.NotNull(onDisk);

        Assert.True(InstalledBuild.IsSameAsInstaller(path, onDisk));
        Assert.False(InstalledBuild.IsSameAsInstaller(path, new Version(onDisk!.Major, onDisk.Minor, onDisk.Build + 1, 0)));
    }
}
