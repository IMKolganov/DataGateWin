using Xunit;

namespace DataGateWin.Tests;

/// <summary>
/// Guards the installer/zip cutover contract: release scripts must publish WinUI unpackaged layout.
/// </summary>
public sealed class WinUiPublishLayoutContractTests
{
    [Fact]
    public void BuildRelease_PublishesWinUi_AndRequiresPriEngineInstaller()
    {
        var script = File.ReadAllText(FindRepoFile(Path.Combine("DataGateWin.UI", "Build-Release.ps1")));

        Assert.Contains("DataGateWin.WinUI", script, StringComparison.Ordinal);
        Assert.Contains("DataGateWin.pri", script, StringComparison.Ordinal);
        Assert.Contains("engine.exe", script, StringComparison.Ordinal);
        Assert.Contains("Microsoft.ui.xaml.dll.mui", script, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("Remove-Item -Recurse -Force $EngineOut", script, StringComparison.Ordinal);
        Assert.Contains("DataGateWin.Installer.exe", script, StringComparison.Ordinal);
        Assert.Contains("libXray.dll", script, StringComparison.Ordinal);
    }

    [Fact]
    public void PublishLayoutDoc_ListsLibXrayRuntime()
    {
        var doc = File.ReadAllText(FindRepoFile(Path.Combine("docs", "WINUI3_PUBLISH_LAYOUT.md")));
        Assert.Contains("libXray.dll", doc, StringComparison.Ordinal);
    }

    [Fact]
    public void InstallerConstants_StillExpectDataGateWinExe()
    {
        Assert.Equal("DataGateWin.exe", Installer.InstallerConstants.ExeName);
        Assert.Equal(@"Installer\DataGateWin.Installer.exe", Installer.InstallerConstants.BundledInstallerRelativePath);
    }

    [Fact]
    public void BuildRelease_ZipMustPackFullTree_AndRefuseMissingWinUiMui()
    {
        // 1.0.20 regression: ZIP packed only root files + Images/Assets/… and omitted
        // en-us\Microsoft.ui.xaml.dll.mui → install-from-GitHub FailFast after ShowMain,
        // while the same publish folder still launched fine.
        var script = File.ReadAllText(FindRepoFile(Path.Combine("DataGateWin.UI", "Build-Release.ps1")));

        Assert.Contains("Microsoft.ui.xaml.dll.mui", script, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("*.mui", script, StringComparison.Ordinal);
        Assert.Contains("refuse to ship a broken ZIP", script, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("Release ZIP missing *.mui", script, StringComparison.Ordinal);

        // Must NOT go back to the narrow allow-list that dropped locale folders.
        Assert.DoesNotContain(
            @"foreach ($dir in @(""Images"", ""Assets"", ""Localization"", ""engine"", ""Installer""))",
            script,
            StringComparison.Ordinal);
    }

    [Fact]
    public void PublishLayoutDoc_ListsRequiredWinUiArtifacts()
    {
        var doc = File.ReadAllText(FindRepoFile(Path.Combine("docs", "WINUI3_PUBLISH_LAYOUT.md")));
        foreach (var token in new[]
                 {
                     "DataGateWin.exe",
                     "DataGateWin.pri",
                     @"Images\favicon.ico",
                     @"Assets\Flags",
                     @"engine\engine.exe",
                     @"Installer\DataGateWin.Installer.exe",
                     @"en-us\Microsoft.ui.xaml.dll.mui",
                 })
        {
            Assert.Contains(token, doc, StringComparison.Ordinal);
        }
    }

    private static string FindRepoRoot()
    {
        var dir = new DirectoryInfo(AppContext.BaseDirectory);
        while (dir is not null)
        {
            if (File.Exists(Path.Combine(dir.FullName, "DataGateWin.sln")))
                return dir.FullName;
            dir = dir.Parent;
        }

        throw new DirectoryNotFoundException("repo root");
    }

    private static string FindRepoFile(string relative)
    {
        var candidate = Path.Combine(FindRepoRoot(), relative);
        if (!File.Exists(candidate))
            throw new FileNotFoundException(relative);
        return candidate;
    }
}
