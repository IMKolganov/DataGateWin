using System.Xml.Linq;
using Xunit;

namespace DataGateWin.Tests;

/// <summary>UI wiring checks complement behavior tests without loading unpackaged WinUI in xUnit.</summary>
public sealed class HomeMapContractTests
{
    [Fact]
    public void UserMarker_IsDrawnBeforeEmptyServerListExit()
    {
        var source = Read("Pages/Home/HomePage.ServerMap.cs");
        var clear = source.IndexOf("ServerMapMarkers.Children.Clear();", StringComparison.Ordinal);
        var user = source.IndexOf("AddUserLocationMarker();", StringComparison.Ordinal);
        var empty = source.IndexOf("if (rows is not { Count: > 0 })", StringComparison.Ordinal);
        Assert.True(clear >= 0 && user > clear && empty > user,
            "The user marker must survive rebuilding the map and render even without servers.");
    }

    [Fact]
    public void LocationRequest_IsStartedWithoutAwait_AndCancelledOnUnload()
    {
        var source = Read("Pages/Home/HomePage.xaml.cs");
        var loaded = source.IndexOf("private async void HomePage_OnLoaded", StringComparison.Ordinal);
        var start = source.IndexOf("_ = LoadUserLocationAsync();", loaded, StringComparison.Ordinal);
        var unload = source.IndexOf("private void HomePage_OnUnloaded", StringComparison.Ordinal);
        var cancel = source.IndexOf("CancelUserLocationRequest();", unload, StringComparison.Ordinal);
        Assert.True(start > loaded && start < unload);
        Assert.True(cancel > unload);
        var location = Read("Pages/Home/HomePage.UserLocation.cs");
        Assert.Contains("if (await _userLocationSession.TryLoadAsync() && IsLoaded)", location);
        Assert.DoesNotContain("AuthedApiHttp", location);
    }

    [Fact]
    public void UserMarker_IsClickable_AndHasAccessibleExplanation()
    {
        var source = Read("Pages/Home/HomePage.UserLocation.cs");
        Assert.Contains("var marker = new Button", source);
        Assert.Contains("Flyout = new Flyout", source);
        Assert.Contains("Text = label", source);
        Assert.Contains("AutomationProperties.SetName(marker, label)", source);
        Assert.Contains("RenderTransform = new ScaleTransform()", source);
    }

    [Theory]
    [InlineData("MapLegendServers", "DodgerBlue", "Home_Map_LegendServers")]
    [InlineData("MapLegendYou", "MediumOrchid", "Home_Map_LegendYou")]
    [InlineData("MapLegendConnected", "YellowGreen", "Home_Map_LegendConnected")]
    public void Legend_HasMatchingColor_SmallText_AndTranslations(string name, string color, string key)
    {
        XNamespace x = "http://schemas.microsoft.com/winfx/2006/xaml";
        var document = XDocument.Parse(Read("Pages/Home/HomePage.xaml"));
        var label = document.Descendants().Single(e => (string?)e.Attribute(x + "Name") == name);
        Assert.Equal("11", (string?)label.Attribute("FontSize"));
        Assert.Contains(label.Parent!.Elements(), e => e.Name.LocalName == "Ellipse" && (string?)e.Attribute("Fill") == color);
        Assert.Contains($"{name}.Text = Loc.T(\"{key}\")", Read("Pages/Home/HomePage.ServerMap.cs"));
        foreach (var path in Directory.EnumerateFiles(Path.Combine(UiRoot(), "Localization"), "Strings.*.xaml"))
        {
            var strings = XDocument.Load(path);
            Assert.False(string.IsNullOrWhiteSpace(strings.Descendants().Single(e => (string?)e.Attribute(x + "Key") == key).Value));
            var hint = strings.Descendants().Single(e => (string?)e.Attribute(x + "Key") == "Home_Map_YourIpLocation").Value;
            Assert.Contains("IP", hint);
            Assert.Contains("VPN", hint);
        }
    }

    [Fact]
    public void LocationChips_UseImageFlags_AndBundleRequiredAssets()
    {
        Assert.Contains("ServerNameUi.CreateRow(flaggedLocationLabel)", Read("Pages/Home/HomePage.ServerMap.cs"));
        foreach (var iso in new[] { "fi", "de", "se" })
        {
            var bytes = File.ReadAllBytes(Path.Combine(UiRoot(), "Assets", "Flags", iso + ".png"));
            Assert.Equal(new byte[] { 137, 80, 78, 71, 13, 10, 26, 10 }, bytes.Take(8).ToArray());
        }
    }

    private static string Read(string relative) => File.ReadAllText(Path.Combine(UiRoot(), relative));

    private static string UiRoot()
    {
        for (var directory = new DirectoryInfo(AppContext.BaseDirectory); directory is not null; directory = directory.Parent)
        {
            var root = Path.Combine(directory.FullName, "src", "DataGateWin.UI");
            if (Directory.Exists(root)) return root;
        }
        throw new DirectoryNotFoundException("Repository UI directory not found.");
    }
}
