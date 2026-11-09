using DataGateWin.CrashReporting;
using DataGateWin.Localization;
using DataGateWin.Services.Ipc;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;

namespace DataGateWin.Services.Ui;

/// <summary>
/// Shows "update the app" once per run when the backend refuses this build's client identity.
/// The session is left alone: only a newer build fixes this, so there is nothing to retry.
/// </summary>
public static class ClientOutdatedUi
{
    private static int _shown;

    public static void Install() => ClientIdentity.Rejected += OnRejected;

    private static void OnRejected(string code)
    {
        if (Interlocked.Exchange(ref _shown, 1) == 1)
            return;

        var dispatcher = App.UiDispatcher;
        if (dispatcher is null)
            return;

        _ = dispatcher.TryEnqueue(() => _ = ShowDialogAsync(App.GetActiveXamlRoot()));
    }

    private static async Task ShowDialogAsync(XamlRoot? xamlRoot)
    {
        if (xamlRoot is null)
            return;

        try
        {
            var dlg = new ContentDialog
            {
                Title = Loc.T("Msg_ClientOutdatedTitle"),
                Content = Loc.T("Msg_ClientOutdatedBody"),
                PrimaryButtonText = Loc.T("Msg_ClientOutdatedDownload"),
                CloseButtonText = Loc.T("Action_Ok"),
                DefaultButton = ContentDialogButton.Primary,
                XamlRoot = xamlRoot,
            };
            if (await dlg.ShowAsync() == ContentDialogResult.Primary)
                EngineMissingUi.OpenDownloadPage();
        }
        catch (Exception ex)
        {
            CrashReporter.ReportNonFatal(ex, "ClientOutdatedUi.ShowDialog");
        }
    }
}
