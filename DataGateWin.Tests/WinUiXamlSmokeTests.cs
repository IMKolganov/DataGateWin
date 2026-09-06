using Xunit;

namespace DataGateWin.Tests;

/// <summary>
/// While MainWindow is code-only smoke, assert XAML pages still avoid known bad patterns.
/// </summary>
public sealed class WinUiXamlSmokeTests
{
    [Fact]
    public void MainWindow_is_code_only_smoke()
    {
        var xaml = Path.Combine("DataGateWin.WinUI", "MainWindow.xaml");
        var cs = FindRepoFile(Path.Combine("DataGateWin.WinUI", "MainWindow.xaml.cs"));
        Assert.False(File.Exists(Path.Combine(FindRepoRoot(), xaml)), "MainWindow.xaml must be removed during smoke");
        var text = File.ReadAllText(cs);
        Assert.Contains("DataGate WinUI OK", text, StringComparison.Ordinal);
        Assert.DoesNotContain("InitializeComponent", text, StringComparison.Ordinal);
    }

    [Fact]
    public void Login_and_pages_avoid_ico_IconSource()
    {
        foreach (var rel in new[]
                 {
                     Path.Combine("DataGateWin.WinUI", "Views", "LoginWindow.xaml"),
                     Path.Combine("DataGateWin.WinUI", "Views", "FirstRunConfigurationWindow.xaml"),
                     Path.Combine("DataGateWin.WinUI", "Views", "IpListSettingsWindow.xaml"),
                     Path.Combine("DataGateWin.WinUI", "Pages", "Home", "HomePage.xaml"),
                     Path.Combine("DataGateWin.WinUI", "Pages", "AccessPage.xaml"),
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
