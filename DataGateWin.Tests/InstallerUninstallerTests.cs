using DataGateWin.Installer;
using Xunit;

namespace DataGateWin.Tests;

public sealed class InstallerUninstallerTests
{
    [Fact]
    public void ResolveInstallDirectory_PrefersRegistryOverFallback()
    {
        var resolved = InstallerUninstaller.ResolveInstallDirectory(
            "  C:\\Registered  ",
            "C:\\Fallback");

        Assert.Equal("C:\\Registered", resolved);
    }

    [Fact]
    public void ResolveInstallDirectory_UsesFallbackWhenRegistryIsEmpty()
    {
        var resolved = InstallerUninstaller.ResolveInstallDirectory(
            "   ",
            "  C:\\Fallback  ");

        Assert.Equal("C:\\Fallback", resolved);
    }

    [Fact]
    public void ResolveInstallDirectory_ReturnsNullWhenNoLocationExists()
    {
        Assert.Null(InstallerUninstaller.ResolveInstallDirectory(null, " "));
    }

    [Fact]
    public async Task ExecuteAsync_UsesRegistryLocationAndRunsCleanupInOrder()
    {
        var system = new RecordingUninstallSystem
        {
            RegistryInstallLocation = "C:\\Registered"
        };

        await InstallerUninstaller.ExecuteAsync(
            system,
            quiet: true,
            fallbackInstallDirectory: "C:\\Fallback",
            system.Logs.Add);

        Assert.Equal("C:\\Registered", system.DeletedInstallDirectory);
        Assert.True(system.StopQuiet);
        Assert.Equal(
            [
                "try_get_install_location",
                "stop_processes",
                "delete_shortcuts",
                "remove_registry",
                "delete_install_directory"
            ],
            system.Calls);
        Assert.Contains(system.Logs, line => line.Contains("Uninstall completed", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public async Task ExecuteAsync_UsesFallbackLocationWhenRegistryIsMissing()
    {
        var system = new RecordingUninstallSystem();

        await InstallerUninstaller.ExecuteAsync(
            system,
            quiet: false,
            fallbackInstallDirectory: "C:\\Fallback",
            system.Logs.Add);

        Assert.Equal("C:\\Fallback", system.DeletedInstallDirectory);
        Assert.False(system.StopQuiet);
    }

    [Fact]
    public async Task ExecuteAsync_RemovesShortcutsAndRegistryEvenWhenInstallFolderIsUnknown()
    {
        var system = new RecordingUninstallSystem();

        await InstallerUninstaller.ExecuteAsync(
            system,
            quiet: false,
            fallbackInstallDirectory: null,
            system.Logs.Add);

        Assert.Null(system.DeletedInstallDirectory);
        Assert.Contains("delete_shortcuts", system.Calls);
        Assert.Contains("remove_registry", system.Calls);
        Assert.Contains(system.Logs, line => line.Contains("skipped folder deletion", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public async Task ExecuteAsync_PropagatesDeleteDirectoryFailures()
    {
        var system = new RecordingUninstallSystem
        {
            RegistryInstallLocation = "C:\\Registered",
            DeleteInstallDirectoryException = new IOException("delete failed")
        };

        var ex = await Assert.ThrowsAsync<IOException>(() =>
            InstallerUninstaller.ExecuteAsync(
                system,
                quiet: false,
                fallbackInstallDirectory: null,
                system.Logs.Add));

        Assert.Equal("delete failed", ex.Message);
        Assert.Contains("remove_registry", system.Calls);
    }

    sealed class RecordingUninstallSystem : IInstallerUninstallSystem
    {
        public string? RegistryInstallLocation { get; init; }
        public string? DeletedInstallDirectory { get; private set; }
        public bool StopQuiet { get; private set; }
        public Exception? DeleteInstallDirectoryException { get; init; }
        public List<string> Calls { get; } = new();
        public List<string> Logs { get; } = new();

        public string? TryGetInstallLocation()
        {
            Calls.Add("try_get_install_location");
            return RegistryInstallLocation;
        }

        public Task StopAppProcessesAsync(bool quiet, Action<string> log, CancellationToken cancellationToken)
        {
            Calls.Add("stop_processes");
            StopQuiet = quiet;
            return Task.CompletedTask;
        }

        public void DeleteShortcuts()
        {
            Calls.Add("delete_shortcuts");
        }

        public void RemoveRegistryEntries()
        {
            Calls.Add("remove_registry");
        }

        public void DeleteInstallDirectory(string installDirectory)
        {
            Calls.Add("delete_install_directory");
            if (DeleteInstallDirectoryException is not null)
                throw DeleteInstallDirectoryException;

            DeletedInstallDirectory = installDirectory;
        }
    }
}
