using System.Diagnostics;
using System.Reflection;
using DataGateWin.Localization;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;

namespace DataGateWin.Views;

public sealed class AboutDialog
{
    public async Task ShowAsync(XamlRoot xamlRoot)
    {
        var version = Assembly.GetExecutingAssembly().GetName().Version;
        var v = version?.ToString();
        var versionText = string.IsNullOrEmpty(v)
            ? Loc.T("About_VersionFmt", Loc.T("Settings_UnknownVersion"))
            : Loc.T("About_VersionFmt", v);

        var panel = new StackPanel { Spacing = 8 };
        panel.Children.Add(new TextBlock
        {
            Text = Loc.T("About_ProductName"),
            FontSize = 20,
            FontWeight = Microsoft.UI.Text.FontWeights.SemiBold,
        });
        panel.Children.Add(new TextBlock { Text = versionText, Opacity = 0.75 });
        panel.Children.Add(new TextBlock
        {
            Text = Loc.T("About_Description"),
            TextWrapping = TextWrapping.Wrap,
            Opacity = 0.75,
        });
        var website = new HyperlinkButton
        {
            Content = Loc.T("About_WebsiteUrl"),
            NavigateUri = new Uri(Loc.T("About_WebsiteUrl")),
        };
        panel.Children.Add(website);

        var dlg = new ContentDialog
        {
            Title = Loc.T("About_Title"),
            Content = panel,
            CloseButtonText = Loc.T("About_Close"),
            XamlRoot = xamlRoot,
        };
        await dlg.ShowAsync();
    }
}
