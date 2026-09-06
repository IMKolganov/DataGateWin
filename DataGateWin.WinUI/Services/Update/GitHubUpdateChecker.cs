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

    public async Task CheckForUpdateAsync(CancellationToken ct)
    {
        if (_updatePromptCompletedThisSession)
            return;

        if (Interlocked.CompareExchange(ref _checkInFlight, 1, 0) != 0)
            return;

        try
        {
            var currentVersion = GetCurrentVersion();
            var latest = await GetLatestReleaseAsync(ct).ConfigureAwait(false);

            if (latest == null || !ReleaseVersionParser.IsUpgradeAvailable(latest.Version, currentVersion))
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
        var tag = doc.RootElement.GetProperty("tag_name").GetString();
        if (string.IsNullOrWhiteSpace(tag))
            return null;

        return new GitHubRelease { Version = ReleaseVersionParser.ParseTag(tag) };
    }

    private static Version GetCurrentVersion() =>
        Assembly.GetEntryAssembly()?.GetName().Version ?? new Version(0, 0, 0);

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
                    _updatePromptCompletedThisSession = true;
                    return;
                }

                var updaterPath = AppInstallerLocator.TryFindInstallerExe();
                if (string.IsNullOrWhiteSpace(updaterPath))
                {
                    _updatePromptCompletedThisSession = true;
                    await ShowUpdaterMissingAsync(xamlRoot).ConfigureAwait(true);
                    return;
                }

                _updatePromptCompletedThisSession = true;
                StopEngineIfRunning();
                LaunchUpdater(updaterPath);
                App.RequestExit();
            }
            catch (Exception ex)
            {
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
            PrimaryButtonText = Loc.T("Action_Ok"),
            SecondaryButtonText = Loc.T("Login_Cancel"),
            DefaultButton = ContentDialogButton.Primary,
            XamlRoot = xamlRoot,
        };
        // Prefer Yes/No semantics via Primary=Yes
        dlg.PrimaryButtonText = "Yes";
        dlg.SecondaryButtonText = "No";
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

    private static void LaunchUpdater(string updaterPath)
    {
        Process.Start(new ProcessStartInfo
        {
            FileName = updaterPath,
            Arguments = AppInstallerLocator.InstallerUpdateArgument,
            UseShellExecute = true,
            WorkingDirectory = AppContext.BaseDirectory
        });
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
