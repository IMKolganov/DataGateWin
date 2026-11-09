using System.Net.Http;
using System.Reflection;
using System.Text.Json;
using DataGateWin.CrashReporting;

namespace DataGateWin.Services.Update;

/// <summary>Shows the "update available" flow. Returns true once the flow finished (accepted or declined)
/// and must not be offered again this session; false when the UI was unavailable.</summary>
public interface IUpdatePrompter
{
    Task<bool> PromptAsync(CancellationToken ct);
}

/// <summary>Looks up the latest GitHub release and asks <see cref="IUpdatePrompter"/> to offer it. UI-free.</summary>
public sealed class GitHubUpdateChecker
{
    private static int _checkInFlight;
    private static bool _updatePromptCompletedThisSession;

    private readonly HttpClient _http;
    private readonly string _owner;
    private readonly string _repo;
    private readonly IUpdatePrompter? _prompter;

    public GitHubUpdateChecker(HttpClient http, string owner, string repo, IUpdatePrompter? prompter = null)
    {
        _http = http;
        _owner = owner;
        _repo = repo;
        _prompter = prompter;
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

            if (_prompter is null)
                return;

            if (await _prompter.PromptAsync(ct).ConfigureAwait(false))
                _updatePromptCompletedThisSession = true;
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
}
