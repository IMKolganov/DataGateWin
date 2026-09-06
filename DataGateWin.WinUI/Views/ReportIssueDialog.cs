using System.Diagnostics;
using DataGateWin.CrashReporting;
using DataGateWin.Localization;
using DataGateWin.Services.Support;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;

namespace DataGateWin.Views;

public sealed class ReportIssueDialog
{
    public async Task ShowAsync(XamlRoot xamlRoot)
    {
        var panel = new StackPanel { Spacing = 8 };
        panel.Children.Add(new TextBlock
        {
            Text = Loc.T("Home_ReportIssueHint"),
            TextWrapping = TextWrapping.Wrap,
            Opacity = 0.8,
            Margin = new Thickness(0, 0, 0, 8),
        });

        var telegram = new Button { Content = Loc.T("Home_ReportTelegram"), HorizontalAlignment = HorizontalAlignment.Stretch };
        var email = new Button { Content = Loc.T("Home_ReportEmail"), HorizontalAlignment = HorizontalAlignment.Stretch };
        var github = new Button { Content = Loc.T("Home_ReportGithub"), HorizontalAlignment = HorizontalAlignment.Stretch };
        panel.Children.Add(telegram);
        panel.Children.Add(email);
        panel.Children.Add(github);

        var dlg = new ContentDialog
        {
            Title = Loc.T("Home_ReportIssueTitle"),
            Content = panel,
            CloseButtonText = Loc.T("Action_Ok"),
            XamlRoot = xamlRoot,
        };

        telegram.Click += (_, _) => { OpenUrl(SupportLinks.TelegramBotUrl); dlg.Hide(); };
        email.Click += (_, _) =>
        {
            var subject = Uri.EscapeDataString(Loc.T("Home_ReportEmailSubject"));
            OpenUrl($"mailto:{SupportLinks.ContactEmail}?subject={subject}");
            dlg.Hide();
        };
        github.Click += (_, _) => { OpenUrl(SupportLinks.GitHubIssuesUrl); dlg.Hide(); };

        await dlg.ShowAsync();
    }

    private static void OpenUrl(string url)
    {
        try
        {
            Process.Start(new ProcessStartInfo { FileName = url, UseShellExecute = true });
        }
        catch (Exception ex)
        {
            CrashReporter.ReportNonFatal(ex, "ReportIssueDialog.OpenUrl");
        }
    }
}
