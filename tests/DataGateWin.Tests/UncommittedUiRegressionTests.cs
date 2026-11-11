using System.Xml.Linq;
using Xunit;

namespace DataGateWin.Tests;

// WinUI cannot be hosted in the WPF test process. These guard the binding/layout boundary;
// calculation, API and chart view-model behavior are exercised by separate runtime tests.
public sealed class UncommittedUiRegressionTests
{
    private static readonly XNamespace X = "http://schemas.microsoft.com/winfx/2006/xaml";

    [Fact]
    public void ConnectionCard_WidthDoesNotFollowSelectedServerText()
    {
        var card = Named("Pages/Home/HomePage.xaml", "ConnectionCard");
        Assert.Equal("Stretch", (string?)card.Attribute("HorizontalAlignment"));
        Assert.True(double.Parse(card.Attribute("MaxWidth")!.Value) > 320);
    }

    [Theory]
    [InlineData("GroupingCombo")]
    [InlineData("MetricCombo")]
    public void FilterPickers_HaveAVisibleHitArea_AndSeparateLabels(string name)
    {
        var picker = Named("Pages/StatisticsPage.xaml", name);
        Assert.True(double.Parse(picker.Attribute("MinHeight")!.Value) >= 32);
        Assert.Null(picker.Attribute("Header"));
        Assert.NotNull(picker.Attribute("SelectionChanged"));
        Assert.Contains(picker.Parent!.Elements(), element => element.Name.LocalName == "TextBlock");
    }

    [Fact]
    public void FilterSelection_UsesStringTagsAcrossTheWinRtBoundary()
    {
        var source = Read("Pages/StatisticsPage.xaml.cs");
        Assert.Contains("Tag = grouping.ToString()", source);
        Assert.Contains("Tag = metric.ToString()", source);
        Assert.Contains("Enum.TryParse<OverviewGrouping>", source);
        Assert.Contains("Enum.TryParse<StatisticsMetric>", source);
        Assert.DoesNotContain("Tag: OverviewGrouping", source);
        Assert.DoesNotContain("Tag: StatisticsMetric", source);
    }

    [Fact]
    public void PresetScrollBar_HasSpaceBelowButtons()
    {
        var buttons = Named("Pages/StatisticsPage.xaml", "PresetButtons");
        var margins = buttons.Attribute("Margin")!.Value.Split(',').Select(double.Parse).ToArray();
        Assert.True(margins[3] >= 16);
        Assert.Equal("Auto", (string?)buttons.Parent!.Attribute("HorizontalScrollBarVisibility"));
    }

    [Fact]
    public void ServerMarkers_HoverDoesNotReplaceStatusColor_AndIdentityUsesId()
    {
        var source = Read("Pages/Home/HomePage.ServerMap.cs");
        Assert.Contains("button.Content = new Microsoft.UI.Xaml.Shapes.Ellipse", source);
        Assert.Contains("Fill = new SolidColorBrush(color)", source);
        Assert.Contains("row.Id == _heroServerId", source);
        Assert.Contains("row.Online && _controller.LastUiState == UiState.Idle", source);
        Assert.Contains("MapViewportMath.Project(latitude, longitude)", source);
        Assert.Contains("Latitude = srv.Latitude", Read("Pages/Home/HomePage.xaml.cs"));
        Assert.Contains("Longitude = srv.Longitude", Read("Pages/Home/HomePage.xaml.cs"));
    }

    [Fact]
    public void AllWindowSizingRetries_GoThroughTheCancellationGuard()
    {
        var source = Read("Services/Ui/WindowChrome.cs");
        Assert.Contains("new StartupWindowSizingGuard", source);
        Assert.Contains("reentry || !CanApplyStartupSize()", source);
        Assert.Contains("startupSizing.Cancel()", source);
    }

    [Fact]
    public void DebugAndRelease_UseTheSameAdministratorManifest()
    {
        var project = XDocument.Parse(Read("DataGateWin.UI.csproj"));
        var manifest = Assert.Single(project.Descendants("ApplicationManifest"));
        Assert.Null(manifest.Attribute("Condition"));
        Assert.Equal("app.manifest", manifest.Value);
        var document = XDocument.Parse(Read(manifest.Value));
        var execution = Assert.Single(document.Descendants(), e => e.Name.LocalName == "requestedExecutionLevel");
        Assert.Equal("requireAdministrator", (string?)execution.Attribute("level"));
    }

    private static XElement Named(string path, string name)
        => XDocument.Parse(Read(path)).Descendants().Single(element => (string?)element.Attribute(X + "Name") == name);

    private static string Read(string path)
    {
        for (var directory = new DirectoryInfo(AppContext.BaseDirectory); directory is not null; directory = directory.Parent)
        {
            var target = Path.Combine(directory.FullName, "src", "DataGateWin.UI", path);
            if (File.Exists(target)) return File.ReadAllText(target);
        }
        throw new FileNotFoundException(path);
    }
}
