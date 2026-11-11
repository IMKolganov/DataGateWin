using System.Text.Json;
using DataGateWin.Installer;
using DataGateWin.Services.Update;
using Xunit;

namespace DataGateWin.Tests;

public sealed class InstallerRecoveryTests : IDisposable
{
    private readonly string _root = Path.Combine(Path.GetTempPath(), "DataGateRecovery_" + Guid.NewGuid().ToString("N"));
    private string Source => Path.Combine(_root, "package");
    private string Destination => Path.Combine(_root, "installed");

    public InstallerRecoveryTests()
    {
        Directory.CreateDirectory(Source);
        Directory.CreateDirectory(Destination);
    }

    [Fact]
    public void FailedDeployment_RestoresReplacedFilesAndRemovesNewFiles()
    {
        File.WriteAllText(Path.Combine(Source, "a.txt"), "replacement");
        File.WriteAllText(Path.Combine(Source, "b.txt"), "new file");
        File.WriteAllText(Path.Combine(Source, "c.txt"), "locked replacement");
        File.WriteAllText(Path.Combine(Destination, "a.txt"), "original");
        File.WriteAllText(Path.Combine(Destination, "c.txt"), "locked original");
        File.WriteAllText(Path.Combine(Destination, "settings.json"), "user settings");
        using var locked = File.Open(Path.Combine(Destination, "c.txt"), FileMode.Open, FileAccess.ReadWrite, FileShare.None);
        var progress = new InlineProgress(_ => { });

        Assert.ThrowsAny<IOException>(() => Copy(progress));

        Assert.Equal("original", File.ReadAllText(Path.Combine(Destination, "a.txt")));
        Assert.False(File.Exists(Path.Combine(Destination, "b.txt")));
        Assert.Equal("user settings", File.ReadAllText(Path.Combine(Destination, "settings.json")));
        Assert.Empty(Directory.GetFiles(Destination, "*.pending", SearchOption.AllDirectories));
    }

    [Fact]
    public void CancellationAfterFirstReplacement_RollsBackAndAllowsRetry()
    {
        File.WriteAllText(Path.Combine(Source, "a.txt"), "new");
        File.WriteAllText(Path.Combine(Source, "b.txt"), "new");
        File.WriteAllText(Path.Combine(Destination, "a.txt"), "old");
        using var cts = new CancellationTokenSource();
        Assert.ThrowsAny<OperationCanceledException>(() => Copy(new InlineProgress(_ => cts.Cancel()), cts.Token));
        Assert.Equal("old", File.ReadAllText(Path.Combine(Destination, "a.txt")));
        Assert.False(File.Exists(Path.Combine(Destination, "b.txt")));

        Copy(new InlineProgress(_ => { }));
        Assert.Equal("new", File.ReadAllText(Path.Combine(Destination, "a.txt")));
        Assert.Equal("new", File.ReadAllText(Path.Combine(Destination, "b.txt")));
    }

    [Theory]
    [InlineData("same")]
    [InlineData("child")]
    [InlineData("parent")]
    public void Deployment_RejectsOverlappingDirectoriesBeforeChangingFiles(string layout)
    {
        File.WriteAllText(Path.Combine(Source, "file.txt"), "original");
        var destination = layout switch
        {
            "same" => Source,
            "child" => Path.Combine(Source, "installed"),
            _ => _root
        };
        Assert.Throws<InvalidOperationException>(() => InstallerOperations.CopyDirectoryWithProgress(
            Source, destination, null, new InlineProgress(_ => { }), default));
        Assert.Equal("original", File.ReadAllText(Path.Combine(Source, "file.txt")));
    }

    [Fact]
    public void Update_RejectsSameBuildRegardlessOfInstallerVersion()
    {
        var binary = typeof(AppUpdatePolicy).Assembly.Location;
        File.Copy(binary, Path.Combine(Source, InstallerConstants.ExeName));
        File.Copy(binary, Path.Combine(Destination, InstallerConstants.ExeName));
        Assert.Throws<InvalidOperationException>(() => InstalledBuild.RequireNewerUpdate(Source, Destination));
    }

    [Fact]
    public void Update_RejectsUnreadablePackageVersion()
    {
        File.WriteAllText(Path.Combine(Source, InstallerConstants.ExeName), "invalid executable");
        File.Copy(typeof(AppUpdatePolicy).Assembly.Location, Path.Combine(Destination, InstallerConstants.ExeName));
        Assert.Throws<InvalidOperationException>(() => InstalledBuild.RequireNewerUpdate(Source, Destination));
    }

    [Fact]
    public void FailedWizard_CanRetry_ButRunningWizardCannotAdvance()
    {
        Assert.False(InstallerWizardRules.IsNextEnabled(InstallerWizardStep.Install, true, Destination, false));
        Assert.True(InstallerWizardRules.IsNextEnabled(InstallerWizardStep.Install, true, Destination, false, installFailed: true));
    }

    [Fact]
    public void ProcessSelection_DoesNotIncludeAnotherApplicationsEngine()
    {
        Assert.True(ProcessStopCoordinator.IsTargetProcessPath(Path.Combine(Destination, "engine", "engine.exe"), Destination, "engine.exe"));
        Assert.False(ProcessStopCoordinator.IsTargetProcessPath(Path.Combine(Source, "engine", "engine.exe"), Destination, "engine.exe"));
        Assert.False(ProcessStopCoordinator.IsTargetProcessPath(null, Destination, "engine.exe"));
    }

    [Theory]
    [InlineData("http://example.invalid/package.zip")]
    [InlineData("file:///C:/package.zip")]
    [InlineData("relative.zip")]
    public void ReleaseAsset_RejectsNonHttpsUrls(string url)
    {
        using var document = JsonDocument.Parse(JsonSerializer.Serialize(new
        {
            assets = new[] { new { name = "DataGateWin.v1.0.25.zip", browser_download_url = url } }
        }));
        Assert.Throws<InvalidOperationException>(() => InstallerReleaseAssetResolver.SelectZipDownloadUrl(
            document.RootElement, "DataGateWin.v", ".zip"));
    }

    [Fact]
    public void RegistryDisplayVersion_UsesInstalledProductInsteadOfUpdater()
    {
        var product = typeof(string).Assembly.Location;
        var expected = ReleaseVersionParser.FormatForDisplay(InstalledBuild.TryReadVersion(product)!);
        File.Copy(product, Path.Combine(Destination, InstallerConstants.ExeName));
        Directory.CreateDirectory(Path.Combine(Destination, "Installer"));
        File.Copy(typeof(InstallerRecoveryTests).Assembly.Location,
            Path.Combine(Destination, InstallerConstants.BundledInstallerRelativePath));
        Assert.Equal(expected, InstallRegistry.ResolveDisplayVersion(Destination));
    }

    [Fact]
    public void Update_AllowsNewerPackageAndRejectsDowngrade()
    {
        File.Copy(typeof(string).Assembly.Location, Path.Combine(Source, InstallerConstants.ExeName));
        File.Copy(typeof(AppUpdatePolicy).Assembly.Location, Path.Combine(Destination, InstallerConstants.ExeName));
        InstalledBuild.RequireNewerUpdate(Source, Destination);
        Assert.Throws<InvalidOperationException>(() => InstalledBuild.RequireNewerUpdate(Destination, Source));
    }

    [Fact]
    public void SameBuild_NormalizesMissingRevision()
    {
        Assert.True(AppUpdatePolicy.IsSameBuild(new Version(1, 0, 23), new Version(1, 0, 23, 0)));
        Assert.False(AppUpdatePolicy.IsSameBuild(new Version(1, 0, 23), new Version(1, 0, 23, 1)));
    }

    private void Copy(IProgress<double> progress, CancellationToken ct = default)
        => InstallerOperations.CopyDirectoryWithProgress(Source, Destination, null, progress, ct);

    public void Dispose() { Directory.Delete(_root, recursive: true); }
    private sealed class InlineProgress(Action<double> report) : IProgress<double>
    {
        public void Report(double value) => report(value);
    }
}
