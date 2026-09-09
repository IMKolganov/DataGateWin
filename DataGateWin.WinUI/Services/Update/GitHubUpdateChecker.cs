using System.Diagnostics;
using System.IO;
using System.Net.Http;
using System.Reflection;
using System.Text.Json;
using DataGateWin.CrashReporting;
using DataGateWin.Localization;
using Microsoft.UI.Dispatching;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;

namespace DataGateWin.Services.Update;

/// <summary>WinUI update check — uses ContentDialog instead of WPF MessageBox.</summary>
public sealed class GitHubUpdateChecker
{
    private const string EngineExeRelativePath = "engine";

    private static int _checkInFlight;
    private static bool _updatePromptCompletedThisSession;

    private readonly HttpClient _http;
    private readonly string _owner;
    private readonly string _repo;

    public GitHubUpdateChecker(HttpClient http, string owner, string repo)
    {
        _http = http;
        _owner = owner;
        _repo = repo;
        _http.DefaultRequestHeaders.UserAgent.ParseAdd("DataGateWin");
    }

    /// <summary>Test seam: clear single-flight + "already prompted" session gates.</summary>
    internal static void ResetSessionStateForTests()
    {
        _updatePromptCompletedThisSession = false;
        Interlocked.Exchange(ref _checkInFlight, 0);
    }

    public async Task CheckForUpdateAsync(CancellationToken ct)
    {
        if (_updatePromptCompletedThisSession)
            return;

        if (Interlocked.CompareExchange(ref _checkInFlight, 1, 0) != 0)
            return;

        try
        {
            var currentVersion = AppUpdatePolicy.ResolveCurrentAppVersion(
                Assembly.GetEntryAssembly()?.Location,
                Assembly.GetEntryAssembly()?.GetName().Version,
                AppContext.BaseDirectory);
            var latest = await GetLatestReleaseAsync(ct).ConfigureAwait(false);

            if (latest == null || !AppUpdatePolicy.ShouldOfferUpgrade(latest.Version, currentVersion))
                return;

            await StartUpdaterAsync().ConfigureAwait(false);
        }
        catch (Exception ex)
        {
            CrashReporter.ReportNonFatal(ex, "GitHubUpdateChecker.CheckForUpdate");
        }
        finally
        {
            Interlocked.Exchange(ref _checkInFlight, 0);
        }
    }

    public async Task<string?> TryGetLatestReleaseVersionForDisplayAsync(CancellationToken ct)
    {
        try
        {
            var latest = await GetLatestReleaseAsync(ct);
            return latest == null ? null : ReleaseVersionParser.FormatForDisplay(latest.Version);
        }
        catch (Exception ex)
        {
            CrashReporter.ReportNonFatal(ex, "GitHubUpdateChecker.GetLatestReleaseVersion");
            return null;
        }
    }

    private async Task<GitHubRelease?> GetLatestReleaseAsync(CancellationToken ct)
    {
        var url = $"https://api.github.com/repos/{_owner}/{_repo}/releases/latest";
        using var resp = await _http.GetAsync(url, ct);
        if (!resp.IsSuccessStatusCode)
            return null;

        var json = await resp.Content.ReadAsStringAsync(ct);
        using var doc = JsonDocument.Parse(json);
        if (!doc.RootElement.TryGetProperty("tag_name", out var tagEl))
            return null;
        var tag = tagEl.GetString();
        if (string.IsNullOrWhiteSpace(tag))
            return null;

        return new GitHubRelease { Version = ReleaseVersionParser.ParseTag(tag) };
    }

    private sealed class GitHubRelease
    {
        public Version Version { get; init; } = null!;
    }

    private static async Task StartUpdaterAsync()
    {
        if (_updatePromptCompletedThisSession)
            return;

        var dispatcher = App.UiDispatcher;
        if (dispatcher is null)
            return;

        var tcs = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        _ = dispatcher.TryEnqueue(async () =>
        {
            try
            {
                if (_updatePromptCompletedThisSession)
                    return;

                var xamlRoot = App.GetActiveXamlRoot();
                if (xamlRoot is null)
                    return;

                if (!await ConfirmUpdateAsync(xamlRoot).ConfigureAwait(true))
                {
                    // Declined: never re-prompt this process lifetime (breaks Yes→relaunch→Yes loops).
                    _updatePromptCompletedThisSession = true;
                    return;
                }

                // Mark completed before launching so a failed/partial update cannot re-open the dialog
                // if this process somehow stays alive or a second check races.
                _updatePromptCompletedThisSession = true;

                var updaterPath = AppInstallerLocator.TryFindInstallerExe();
                if (string.IsNullOrWhiteSpace(updaterPath))
                {
                    await ShowUpdaterMissingAsync(xamlRoot).ConfigureAwait(true);
                    return;
                }

                StopEngineIfRunning();
                if (!TryLaunchUpdater(updaterPath))
                {
                    await ShowUpdaterMissingAsync(xamlRoot).ConfigureAwait(true);
                    return;
                }

                App.RequestExit();
            }
            catch (Exception ex)
            {
                _updatePromptCompletedThisSession = true;
                CrashReporter.ReportNonFatal(ex, "GitHubUpdateChecker.StartUpdater");
            }
            finally
            {
                tcs.TrySetResult();
            }
        });

        await tcs.Task.ConfigureAwait(false);
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
            CrashReporter.ReportNonFatal(ex, "GitHubUpdateChecker.LaunchUpdater");
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
                    CrashReporter.ReportNonFatal(ex, "GitHubUpdateChecker.KillEngine.CloseMainWindow");
                }

                if (!p.HasExited)
                {
                    p.Kill(entireProcessTree: true);
                    p.WaitForExit(1500);
                }
            }
            catch (Exception ex)
            {
                CrashReporter.ReportNonFatal(ex, "GitHubUpdateChecker.KillEngine");
            }
            finally
            {
                try { p.Dispose(); } catch (Exception ex) { CrashReporter.ReportNonFatal(ex, "GitHubUpdateChecker.KillEngine.Dispose"); }
            }
        }
    }
}
