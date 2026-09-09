using DataGateWin.CrashReporting;
using DataGateWin.Localization;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;

namespace DataGateWin.Services.Ui;

/// <summary>
/// User-visible error surface. Navigation / page failures must land here — never silent
/// no-op and never an unhandled path that can FailFast the process.
/// </summary>
public static class UiErrorPanel
{
    public static UIElement Create(string context, Exception? error = null)
    {
        string detail;
        try
        {
            detail = error is null
                ? Loc.T("Msg_ErrorTitle")
                : error.Message;
        }
        catch
        {
            detail = error?.Message ?? "Unexpected error";
        }

        string title;
        try { title = Loc.T("Msg_ErrorTitle"); }
        catch { title = "Error"; }

        string heading;
        try { heading = string.IsNullOrWhiteSpace(context) ? title : context; }
        catch { heading = title; }

        return new ScrollViewer
        {
            Content = new StackPanel
            {
                Margin = new Thickness(24),
                Spacing = 12,
                Children =
                {
                    new TextBlock
                    {
                        Text = heading,
                        FontSize = 20,
                        FontWeight = Microsoft.UI.Text.FontWeights.SemiBold,
                        TextWrapping = TextWrapping.Wrap,
                    },
                    new TextBlock
                    {
                        Text = title,
                        FontWeight = Microsoft.UI.Text.FontWeights.SemiBold,
                    },
                    new TextBlock
                    {
                        Text = detail,
                        TextWrapping = TextWrapping.Wrap,
                        Opacity = 0.85,
                    },
                },
            },
        };
    }

    public static UIElement FromException(string context, Exception ex)
    {
        CrashReporter.ReportNonFatal(ex, context);
        return Create(context, ex);
    }
}
