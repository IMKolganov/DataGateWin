using System.Diagnostics;
using DataGateWin.CrashReporting;
using DataGateWin.Localization;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;

namespace DataGateWin.Services.Update;

/// <summary>WinUI side of the update flow: ContentDialog prompt and installer handoff.</summary>
public sealed class WinUiUpdatePrompter : IUpdatePrompter
{
    public async Task<bool> PromptAsync(CancellationToken ct)
    {
        var dispatcher = App.UiDispatcher;
        if (dispatcher is null)
            return false;

        var completed = false;

        var tcs = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var enqueued = dispatcher.TryEnqueue(async () =>
        {
            try
            {
                ct.ThrowIfCancellationRequested();
                var xamlRoot = App.GetActiveXamlRoot();
                if (xamlRoot is null)
                    return;

                if (!await ConfirmUpdateAsync(xamlRoot).ConfigureAwait(true))
                {
                    // Declined: never re-prompt this process lifetime (breaks Yes→relaunch→Yes loops).
                    completed = true;
                    return;
                }

                ct.ThrowIfCancellationRequested();

                // Mark completed before launching so a failed/partial update cannot re-open the dialog
                // if this process somehow stays alive or a second check races.
                completed = true;

                var updaterPath = AppInstallerLocator.TryFindInstallerExe();
                if (string.IsNullOrWhiteSpace(updaterPath))
                {
                    await ShowUpdaterMissingAsync(xamlRoot).ConfigureAwait(true);
                    return;
                }

                if (!TryLaunchUpdater(updaterPath))
                {
                    await ShowUpdaterMissingAsync(xamlRoot).ConfigureAwait(true);
                    return;
                }

                App.RequestExit();
            }
            catch (Exception ex)
            {
                completed = true;
                CrashReporter.ReportNonFatal(ex, "WinUiUpdatePrompter.Prompt");
            }
            finally
            {
                tcs.TrySetResult();
            }
        });

        if (!enqueued)
            return false;
        await tcs.Task.WaitAsync(ct).ConfigureAwait(false);
        return completed;
    }

    private static async Task<bool> ConfirmUpdateAsync(XamlRoot xamlRoot)
    {
        var dlg = new ContentDialog
        {
            Title = Loc.T("Msg_UpdateAvailableTitle"),
            Content = Loc.T("Msg_UpdateAvailableBody"),
            PrimaryButtonText = Loc.T("Action_Yes"),
            SecondaryButtonText = Loc.T("Action_No"),
            DefaultButton = ContentDialogButton.Primary,
            XamlRoot = xamlRoot,
        };
        var result = await dlg.ShowAsync();
        return result == ContentDialogResult.Primary;
    }

    private static async Task ShowUpdaterMissingAsync(XamlRoot xamlRoot)
    {
        var dlg = new ContentDialog
        {
            Title = Loc.T("Msg_UpdateErrorTitle"),
            Content = Loc.T("Msg_UpdateErrorBody"),
            CloseButtonText = Loc.T("Action_Ok"),
            XamlRoot = xamlRoot,
        };
        await dlg.ShowAsync();
    }

    private static bool TryLaunchUpdater(string updaterPath)
    {
        try
        {
            Process.Start(new ProcessStartInfo
            {
                FileName = updaterPath,
                Arguments = AppInstallerLocator.InstallerUpdateArgument,
                UseShellExecute = true,
                WorkingDirectory = AppContext.BaseDirectory
            });
            return true;
        }
        catch (Exception ex)
        {
            CrashReporter.ReportNonFatal(ex, "WinUiUpdatePrompter.LaunchUpdater");
            return false;
        }
    }

}
