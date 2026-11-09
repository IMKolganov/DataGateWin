using System.Reflection;
using DataGateWin.Localization;
using DataGateWin.Services.Ui;
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

        var panel = new StackPanel { Spacing = 14, MaxWidth = 400 };
        var header = new Grid { ColumnSpacing = 12 };
        header.ColumnDefinitions.Add(new ColumnDefinition { Width = GridLength.Auto });
        header.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });
        var logo = new Image
        {
            Width = 48,
            Height = 48,
            VerticalAlignment = VerticalAlignment.Center,
        };
        AppIcon.TryAssignBrandMark(logo, 96);
        header.Children.Add(logo);

        var identity = new StackPanel { Spacing = 4, VerticalAlignment = VerticalAlignment.Center };
        Grid.SetColumn(identity, 1);
        identity.Children.Add(new TextBlock
        {
            Text = Loc.T("About_ProductName"),
            FontSize = 20,
            FontWeight = Microsoft.UI.Text.FontWeights.SemiBold,
            TextWrapping = TextWrapping.Wrap,
        });
        identity.Children.Add(new TextBlock
        {
            Text = versionText,
            FontSize = 12,
            Opacity = 0.65,
        });
        header.Children.Add(identity);
        panel.Children.Add(header);
        var product = new StackPanel { Spacing = 4 };
        product.Children.Add(new TextBlock
        {
            Text = Loc.T("About_Description"),
            FontSize = 14,
            LineHeight = 21,
            TextWrapping = TextWrapping.Wrap,
            Opacity = 0.75,
        });
        var website = new HyperlinkButton
        {
            Content = IconButtonContent.Create(IconButtonContent.OpenExternal, Loc.T("About_WebsiteUrl")),
            NavigateUri = new Uri(Loc.T("About_WebsiteUrl")),
            HorizontalAlignment = HorizontalAlignment.Left,
            Padding = new Thickness(0, 6, 0, 6),
        };
        product.Children.Add(website);
        panel.Children.Add(product);

        var developer = new StackPanel { Spacing = 4 };
        developer.Children.Add(new TextBlock
        {
            Text = "Ivan Kolganov",
            FontSize = 16,
            FontWeight = Microsoft.UI.Text.FontWeights.SemiBold,
        });
        developer.Children.Add(new TextBlock
        {
            Text = Loc.T("About_DeveloperRole"),
            FontSize = 13,
            TextWrapping = TextWrapping.Wrap,
            Opacity = 0.75,
        });
        developer.Children.Add(new TextBlock { Text = Loc.T("About_DeveloperLocation"), FontSize = 12, Opacity = 0.6 });

        var links = new Grid { ColumnSpacing = 16, Margin = new Thickness(0, 4, 0, 0) };
        links.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });
        links.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });
        links.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });
        links.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });
        links.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });
        links.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });
        AddLink("GitHub", "https://github.com/IMKolganov", 0, 0);
        AddLink("LinkedIn", "https://www.linkedin.com/in/imkolganov", 0, 1);
        AddLink("Instagram", "https://www.instagram.com/imkolganov/", 1, 0);
        AddLink("X (Twitter)", "https://x.com/imkolganov", 1, 1);
        AddLink("Facebook", "https://www.facebook.com/IMKolganov", 2, 0);
        AddLink("@KolganovIvan", "https://t.me/KolganovIvan", 2, 1);
        AddLink("rackot.ru", "https://rackot.ru/", 3, 0);
        AddLink("Buy Me a Coffee", "https://buymeacoffee.com/imkolganov", 3, 1);

        var contacts = new StackPanel { Spacing = 8 };
        contacts.Children.Add(new TextBlock
        {
            Text = Loc.T("About_ContactDescription"),
            FontSize = 13,
            TextWrapping = TextWrapping.Wrap,
            Opacity = 0.75,
        });
        contacts.Children.Add(links);
        developer.Children.Add(new TextBlock
        {
            Text = Loc.T("About_ContactTitle"),
            FontSize = 14,
            FontWeight = Microsoft.UI.Text.FontWeights.SemiBold,
            Margin = new Thickness(0, 8, 0, 0),
        });
        developer.Children.Add(contacts);
        panel.Children.Add(new Border
        {
            BorderBrush = UiThemeBrushes.CardStroke(),
            BorderThickness = new Thickness(0, 1, 0, 0),
            Padding = new Thickness(0, 14, 0, 0),
            Child = developer,
        });

        void AddLink(string label, string url, int row, int column)
        {
            var link = new HyperlinkButton
            {
                Content = label,
                NavigateUri = new Uri(url),
                HorizontalAlignment = HorizontalAlignment.Left,
                Padding = new Thickness(0, 6, 0, 6),
            };
            Grid.SetRow(link, row);
            Grid.SetColumn(link, column);
            links.Children.Add(link);
        }

        var dlg = new ContentDialog
        {
            Title = Loc.T("About_Title"),
            Content = panel,
            CloseButtonText = Loc.T("About_Close"),
            XamlRoot = xamlRoot,
            // Dialogs live in a popup and must explicitly follow the app's selected theme.
            RequestedTheme = App.ResolveElementTheme(),
            DefaultButton = ContentDialogButton.Close,
        };
        await dlg.ShowAsync();
    }
}
