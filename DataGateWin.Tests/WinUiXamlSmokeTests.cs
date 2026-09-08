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

    [Fact]
    public void HomePage_connected_server_row_has_flag_image_above_vpn_ip()
    {
        var xaml = File.ReadAllText(FindRepoFile(Path.Combine("DataGateWin.WinUI", "Pages", "Home", "HomePage.xaml")));
        Assert.Contains("x:Name=\"NetworkServerFlag\"", xaml, StringComparison.Ordinal);
        Assert.Contains("x:Name=\"NetworkVpnIpText\"", xaml, StringComparison.Ordinal);
        var flagAt = xaml.IndexOf("x:Name=\"NetworkServerFlag\"", StringComparison.Ordinal);
        var ipAt = xaml.IndexOf("x:Name=\"NetworkVpnIpText\"", StringComparison.Ordinal);
        Assert.True(flagAt >= 0 && ipAt > flagAt, "flag must sit above VPN IP in the connected card");
        Assert.DoesNotContain("x:Name=\"NetworkServerText\"", xaml, StringComparison.Ordinal);
    }

    [Fact]
    public void HomePage_has_scroll_and_fixed_engine_log_height()
    {
        var xaml = File.ReadAllText(FindRepoFile(Path.Combine("DataGateWin.WinUI", "Pages", "Home", "HomePage.xaml")));
        Assert.Contains("<ScrollViewer", xaml, StringComparison.Ordinal);
        Assert.Contains("x:Name=\"HomeScroll\"", xaml, StringComparison.Ordinal);
        Assert.Contains("x:Name=\"LogTextBox\"", xaml, StringComparison.Ordinal);
        Assert.Contains("Height=\"240\"", xaml, StringComparison.Ordinal);
        Assert.DoesNotContain("Height=\"*\"", xaml, StringComparison.Ordinal);
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
