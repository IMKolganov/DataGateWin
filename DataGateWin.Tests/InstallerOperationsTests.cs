using System.Text.Json;
using System.Windows;
using System.Windows.Media;
using DataGateWin.Installer;
using DataGateWin.Installer.Services;
using Xunit;
using InstallerTheme = DataGateWin.Installer.Services.AppTheme;

namespace DataGateWin.Tests;

public sealed class InstallerOperationsTests
{
    [Fact]
    public void ResolveUpdateInstallDir_ReturnsAncestorContainingExecutable()
    {
        var root = CreateTempDirectory();
        try
        {
            var installDir = Path.Combine(root, "DataGate");
            var nestedDir = Path.Combine(installDir, "updates", "current");
            Directory.CreateDirectory(nestedDir);
            File.WriteAllText(Path.Combine(installDir, "DataGateWin.exe"), "probe");

            var logs = new List<string>();

            var resolved = InstallerOperations.ResolveUpdateInstallDir(
                nestedDir,
                "DataGateWin.exe",
                logs.Add);

            Assert.Equal(Path.GetFullPath(installDir), Path.GetFullPath(resolved));
            Assert.Contains(logs, line => line.Contains("resolved install folder", StringComparison.OrdinalIgnoreCase));
        }
        finally
        {
            DeleteDirectoryBestEffort(root);
        }
    }

    [Fact]
    public void ResolveUpdateInstallDir_ThrowsWhenExecutableIsNotFound()
    {
        var root = CreateTempDirectory();
        try
        {
            var nestedDir = Path.Combine(root, "a", "b");
            Directory.CreateDirectory(nestedDir);

            var ex = Assert.Throws<FileNotFoundException>(() =>
                InstallerOperations.ResolveUpdateInstallDir(nestedDir, "DataGateWin.exe"));

            Assert.EndsWith("DataGateWin.exe", ex.FileName, StringComparison.OrdinalIgnoreCase);
            Assert.Contains("Checked:", ex.Message, StringComparison.Ordinal);
            Assert.Contains(nestedDir, ex.Message, StringComparison.OrdinalIgnoreCase);
        }
        finally
        {
            DeleteDirectoryBestEffort(root);
        }
    }

    [Fact]
    public void CopyDirectoryWithProgress_CopiesNestedFilesAndReportsCompletion()
    {
        var root = CreateTempDirectory();
        try
        {
            var source = Path.Combine(root, "source");
            var destination = Path.Combine(root, "destination");
            Directory.CreateDirectory(Path.Combine(source, "nested"));
            File.WriteAllText(Path.Combine(source, "root.txt"), "root");
            File.WriteAllText(Path.Combine(source, "nested", "child.txt"), "child");

            var progress = new RecordingProgress();

            InstallerOperations.CopyDirectoryWithProgress(
                source,
                destination,
                skipDestination: null,
                progress,
                CancellationToken.None);

            Assert.Equal("root", File.ReadAllText(Path.Combine(destination, "root.txt")));
            Assert.Equal("child", File.ReadAllText(Path.Combine(destination, "nested", "child.txt")));
            Assert.Equal(2, progress.Values.Count);
            Assert.Equal(100, progress.Values[^1]);
        }
        finally
        {
            DeleteDirectoryBestEffort(root);
        }
    }

    [Fact]
    public void CopyDirectoryWithProgress_SkipsSelectedDestination()
    {
        var root = CreateTempDirectory();
        try
        {
            var source = Path.Combine(root, "source");
            var destination = Path.Combine(root, "destination");
            Directory.CreateDirectory(source);
            File.WriteAllText(Path.Combine(source, "keep.txt"), "keep");
            File.WriteAllText(Path.Combine(source, "skip.txt"), "skip");

            InstallerOperations.CopyDirectoryWithProgress(
                source,
                destination,
                dest => Path.GetFileName(dest).Equals("skip.txt", StringComparison.OrdinalIgnoreCase),
                new RecordingProgress(),
                CancellationToken.None);

            Assert.True(File.Exists(Path.Combine(destination, "keep.txt")));
            Assert.False(File.Exists(Path.Combine(destination, "skip.txt")));
        }
        finally
        {
            DeleteDirectoryBestEffort(root);
        }
    }

    [Fact]
    public void CopyDirectoryWithProgress_ThrowsWhenCanceledBeforeCopy()
    {
        var root = CreateTempDirectory();
        try
        {
            var source = Path.Combine(root, "source");
            var destination = Path.Combine(root, "destination");
            Directory.CreateDirectory(source);
            File.WriteAllText(Path.Combine(source, "file.txt"), "content");

            using var cts = new CancellationTokenSource();
            cts.Cancel();

            Assert.Throws<OperationCanceledException>(() =>
                InstallerOperations.CopyDirectoryWithProgress(
                    source,
                    destination,
                    skipDestination: null,
                    new RecordingProgress(),
                    cts.Token));

            Assert.False(File.Exists(Path.Combine(destination, "file.txt")));
        }
        finally
        {
            DeleteDirectoryBestEffort(root);
        }
    }

    [Fact]
    public void SelectZipDownloadUrl_ReturnsMatchingDataGateZipAsset()
    {
        using var doc = JsonDocument.Parse(
            """
            {
              "assets": [
                { "name": "DataGateWin.v1.0.7.txt", "browser_download_url": "https://example.invalid/readme.txt" },
                { "name": "DataGateWin.v1.0.7.zip", "browser_download_url": "https://example.invalid/DataGateWin.v1.0.7.zip" }
              ]
            }
            """);

        var url = InstallerReleaseAssetResolver.SelectZipDownloadUrl(
            doc.RootElement,
            "DataGateWin.v",
            ".zip");

        Assert.Equal("https://example.invalid/DataGateWin.v1.0.7.zip", url);
    }

    [Fact]
    public void SelectZipDownloadUrl_ThrowsWhenAssetsAreMissing()
    {
        using var doc = JsonDocument.Parse("""{ "tag_name": "v1.0.7" }""");

        var ex = Assert.Throws<InvalidOperationException>(() =>
            InstallerReleaseAssetResolver.SelectZipDownloadUrl(
                doc.RootElement,
                "DataGateWin.v",
                ".zip"));

        Assert.Contains("does not contain assets", ex.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void ThemeService_ApplyTheme_ReplacesFrozenBrushesAndSetsDarkPalette()
    {
        var resources = new ResourceDictionary();
        var frozen = new SolidColorBrush(Colors.White);
        frozen.Freeze();
        resources["WindowBackgroundBrush"] = frozen;

        new ThemeService().ApplyTheme(resources, InstallerTheme.Dark);

        var background = Assert.IsType<SolidColorBrush>(resources["WindowBackgroundBrush"]);
        var accent = Assert.IsType<SolidColorBrush>(resources["AccentBrush"]);
        Assert.Equal(Color.FromRgb(17, 24, 39), background.Color);
        Assert.Equal(Color.FromRgb(59, 130, 246), accent.Color);
        Assert.False(background.IsFrozen);
    }

    static string CreateTempDirectory()
    {
        var dir = Path.Combine(Path.GetTempPath(), "datagate_installer_tests_" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(dir);
        return dir;
    }

    static void DeleteDirectoryBestEffort(string dir)
    {
        try
        {
            if (Directory.Exists(dir))
                Directory.Delete(dir, recursive: true);
        }
        catch
        {
        }
    }

    sealed class RecordingProgress : IProgress<double>
    {
        public List<double> Values { get; } = new();

        public void Report(double value)
            => Values.Add(value);
    }
}
