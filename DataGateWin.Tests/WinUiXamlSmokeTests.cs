using Xunit;

namespace DataGateWin.Tests;

/// <summary>
/// Unpackaged WinUI: avoid known-bad XAML patterns that broke LoadComponent during migration.
/// </summary>
public sealed class WinUiXamlSmokeTests
{
    [Fact]
    public void MainWindow_xaml_exists_and_loads_via_InitializeComponent()
    {
        var xaml = FindRepoFile(Path.Combine("DataGateWin.WinUI", "MainWindow.xaml"));
        var cs = FindRepoFile(Path.Combine("DataGateWin.WinUI", "MainWindow.xaml.cs"));
        Assert.True(File.Exists(xaml));
        var text = File.ReadAllText(cs);
        Assert.Contains("InitializeComponent", text, StringComparison.Ordinal);
        Assert.DoesNotContain("ImageIconSource", File.ReadAllText(xaml), StringComparison.Ordinal);
    }

    [Fact]
    public void Login_and_pages_avoid_ico_IconSource()
    {
        foreach (var rel in new[]
                 {
                     Path.Combine("DataGateWin.WinUI", "MainWindow.xaml"),
                     Path.Combine("DataGateWin.WinUI", "Views", "LoginWindow.xaml"),
                     Path.Combine("DataGateWin.WinUI", "Views", "FirstRunConfigurationWindow.xaml"),
                     Path.Combine("DataGateWin.WinUI", "Views", "IpListSettingsWindow.xaml"),
                     Path.Combine("DataGateWin.WinUI", "Pages", "Home", "HomePage.xaml"),
                     Path.Combine("DataGateWin.WinUI", "Pages", "AccessPage.xaml"),
                     Path.Combine("DataGateWin.WinUI", "Pages", "ImportPage.xaml"),
                     Path.Combine("DataGateWin.WinUI", "Pages", "SettingsPage.xaml"),
                     Path.Combine("DataGateWin.WinUI", "Pages", "StatisticsPage.xaml"),
                 })
        {
            var path = FindRepoFile(rel);
            Assert.True(File.Exists(path), "missing " + rel);
            var xaml = File.ReadAllText(path);
            Assert.False(xaml.Contains("ImageIconSource", StringComparison.Ordinal), rel);
            Assert.False(
                xaml.Contains("ImageSource=\"Assets/AppIcon.ico\"", StringComparison.OrdinalIgnoreCase)
                || xaml.Contains("ImageSource=\"Assets\\AppIcon.ico\"", StringComparison.OrdinalIgnoreCase),
                rel + " must not bind TitleBar/Image to .ico via ImageSource in XAML");
        }
    }

    [Fact]
    public void MainWindow_has_Import_nav_item()
    {
        var xaml = File.ReadAllText(FindRepoFile(Path.Combine("DataGateWin.WinUI", "MainWindow.xaml")));
        Assert.Contains("x:Name=\"NavImport\"", xaml, StringComparison.Ordinal);
        Assert.Contains("Tag=\"import\"", xaml, StringComparison.Ordinal);
    }

    [Fact]
    public void ImportPage_xaml_and_codebehind_exist()
    {
        var xaml = FindRepoFile(Path.Combine("DataGateWin.WinUI", "Pages", "ImportPage.xaml"));
        var cs = FindRepoFile(Path.Combine("DataGateWin.WinUI", "Pages", "ImportPage.xaml.cs"));
        Assert.Contains("InitializeComponent", File.ReadAllText(cs), StringComparison.Ordinal);
        Assert.DoesNotContain("ImageIconSource", File.ReadAllText(xaml), StringComparison.Ordinal);
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
        if (File.Exists(candidate))
            return candidate;
        throw new FileNotFoundException(relative);
    }
}
