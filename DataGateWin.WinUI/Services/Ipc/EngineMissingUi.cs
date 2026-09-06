using System.Diagnostics;
using System.IO;
using DataGateWin.Localization;
using DataGateWin.Services.Update;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;

namespace DataGateWin.Services.Ipc;

public static class EngineMissingUi
{
    public static bool IsEngineMissingException(Exception ex)
    {
        if (ex is not FileNotFoundException fn)
            return false;

        if (fn.FileName != null &&
            fn.FileName.EndsWith("engine.exe", StringComparison.OrdinalIgnoreCase))
            return true;

        return fn.Message.Contains("Engine executable not found", StringComparison.OrdinalIgnoreCase);
    }

    public static void ShowDialog(XamlRoot? xamlRoot)
    {
        var dispatcher = App.UiDispatcher;
        if (dispatcher is null)
            return;

        if (!dispatcher.HasThreadAccess)
        {
            _ = dispatcher.TryEnqueue(() => ShowDialog(xamlRoot ?? App.GetActiveXamlRoot()));
            return;
        }

        _ = ShowDialogAsync(xamlRoot ?? App.GetActiveXamlRoot());
    }

    private static async Task ShowDialogAsync(XamlRoot? xamlRoot)
    {
        if (xamlRoot is null)
            return;

        try
        {
            var installerPath = AppInstallerLocator.TryFindInstallerExe();
            if (!string.IsNullOrEmpty(installerPath))
            {
                var dlg = new ContentDialog
                {
                    Title = Loc.T("Msg_EngineMissingTitle"),
                    Content = Loc.T("Msg_EngineMissingBodyWithInstaller", AppInstallerLocator.DownloadPageUrl),
                    PrimaryButtonText = "Yes",
                    SecondaryButtonText = "No",
                    CloseButtonText = Loc.T("Login_Cancel"),
                    DefaultButton = ContentDialogButton.Primary,
                    XamlRoot = xamlRoot,
                };
                var r = await dlg.ShowAsync();
                if (r == ContentDialogResult.Primary)
                {
                    TryLaunchInstaller(installerPath);
                    App.RequestExit();
                }
                else if (r == ContentDialogResult.Secondary)
                {
                    OpenDownloadPage();
                }
            }
            else
            {
                var dlg = new ContentDialog
                {
                    Title = Loc.T("Msg_EngineMissingTitle"),
                    Content = Loc.T("Msg_EngineMissingBodyNoInstaller", AppInstallerLocator.DownloadPageUrl),
                    PrimaryButtonText = "Yes",
                    CloseButtonText = "No",
                    DefaultButton = ContentDialogButton.Primary,
                    XamlRoot = xamlRoot,
                };
                var r = await dlg.ShowAsync();
                if (r == ContentDialogResult.Primary)
                    OpenDownloadPage();
            }
        }
        catch (Exception ex)
        {
            CrashReporting.CrashReporter.ReportNonFatal(ex, "EngineMissingUi.ShowDialog");
        }
    }

    private static void TryLaunchInstaller(string installerPath)
    {
        Process.Start(new ProcessStartInfo
        {
            FileName = installerPath,
            Arguments = AppInstallerLocator.InstallerUpdateArgument,
            UseShellExecute = true,
            WorkingDirectory = AppContext.BaseDirectory
        });
    }

    private static void OpenDownloadPage()
    {
        Process.Start(new ProcessStartInfo
        {
            FileName = AppInstallerLocator.DownloadPageUrl,
            UseShellExecute = true
        });
    }
}
