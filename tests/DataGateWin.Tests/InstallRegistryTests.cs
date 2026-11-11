using DataGateWin.Installer;
using Xunit;

namespace DataGateWin.Tests;

public sealed class InstallRegistryTests
{
    [Fact]
    public void ResolveUninstallExecutable_PrefersBundledInstallerInInstallFolder()
    {
        var installDir = Path.Combine(Path.GetTempPath(), "datagate_install_" + Guid.NewGuid().ToString("N"));
        var bundledDir = Path.Combine(installDir, "Installer");
        var bundledExe = Path.Combine(bundledDir, "DataGateWin.Installer.exe");

        try
        {
            Directory.CreateDirectory(bundledDir);
            File.WriteAllText(bundledExe, string.Empty);

            var resolved = InstallRegistry.ResolveUninstallExecutable(installDir);

            Assert.Equal(bundledExe, resolved);
        }
        finally
        {
            if (Directory.Exists(installDir))
                Directory.Delete(installDir, recursive: true);
        }
    }

    [Fact]
    public void ResolveUninstallExecutable_FallsBackToCurrentProcessPathWhenBundledMissing()
    {
        var installDir = Path.Combine(Path.GetTempPath(), "datagate_install_" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(installDir);
        try
        {
            var resolved = InstallRegistry.ResolveUninstallExecutable(installDir);

            Assert.False(string.IsNullOrWhiteSpace(resolved));
            Assert.True(File.Exists(resolved), $"Expected existing process path: {resolved}");
        }
        finally
        {
            Directory.Delete(installDir, recursive: true);
        }
    }
}
