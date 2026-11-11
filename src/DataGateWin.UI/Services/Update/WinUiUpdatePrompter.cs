using System.Diagnostics;
using System.IO;
using DataGateWin.CrashReporting;
using DataGateWin.Localization;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;

namespace DataGateWin.Services.Update;

/// <summary>WinUI side of the update flow: ContentDialog prompt, stop engine, launch installer.</summary>
public sealed class WinUiUpdatePrompter : IUpdatePrompter
{
    private const string EngineExeRelativePath = "engine";

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
                var xamlRoot = App.GetActiveXamlRoot();
                if (xamlRoot is null)
                    return;

                if (!await ConfirmUpdateAsync(xamlRoot).ConfigureAwait(true))
                {
                    // Declined: never re-prompt this process lifetime (breaks Yes→relaunch→Yes loops).
                    completed = true;
                    return;
                }

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

    private static void StopEngineIfRunning()
    {
        var enginePath = Path.Combine(AppContext.BaseDirectory, EngineExeRelativePath, "engine.exe");
        if (File.Exists(enginePath))
            KillEngineProcessesByExactPathOnce(enginePath);
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

    private static void KillEngineProcessesByExactPathOnce(string engineExePath)
    {
        var targetPath = Path.GetFullPath(engineExePath).TrimEnd(Path.DirectorySeparatorChar);
        foreach (var p in Process.GetProcessesByName(Path.GetFileNameWithoutExtension(targetPath)))
        {
            try
            {
                var procPath = p.MainModule?.FileName;
                if (string.IsNullOrWhiteSpace(procPath))
                    continue;
                procPath = Path.GetFullPath(procPath).TrimEnd(Path.DirectorySeparatorChar);
                if (!string.Equals(procPath, targetPath, StringComparison.OrdinalIgnoreCase))
                    continue;

                try
                {
                    if (!p.HasExited)
                    {
                        p.CloseMainWindow();
                        p.WaitForExit(500);
                    }
                }
                catch (Exception ex)
                {
                    CrashReporter.ReportNonFatal(ex, "WinUiUpdatePrompter.KillEngine.CloseMainWindow");
                }

                if (!p.HasExited)
                {
                    p.Kill(entireProcessTree: true);
                    p.WaitForExit(1500);
                }
            }
            catch (Exception ex)
            {
                CrashReporter.ReportNonFatal(ex, "WinUiUpdatePrompter.KillEngine");
            }
            finally
            {
                try { p.Dispose(); } catch (Exception ex) { CrashReporter.ReportNonFatal(ex, "WinUiUpdatePrompter.KillEngine.Dispose"); }
            }
        }
    }
}
