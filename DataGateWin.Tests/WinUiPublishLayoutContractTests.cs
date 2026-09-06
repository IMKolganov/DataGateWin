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
        Assert.Contains("Images", script, StringComparison.Ordinal);
        Assert.Contains("Remove-Item -Recurse -Force $EngineOut", script, StringComparison.Ordinal);
        Assert.Contains("DataGateWin.Installer.exe", script, StringComparison.Ordinal);
    }

    [Fact]
    public void InstallerConstants_StillExpectDataGateWinExe()
    {
        Assert.Equal("DataGateWin.exe", Installer.InstallerConstants.ExeName);
        Assert.Equal(@"Installer\DataGateWin.Installer.exe", Installer.InstallerConstants.BundledInstallerRelativePath);
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
                     @"engine\engine.exe",
                     @"Installer\DataGateWin.Installer.exe",
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
