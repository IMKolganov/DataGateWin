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
public enum UpdateCheckStatus { Unavailable, UpToDate, UpdateAvailable, Busy }

public sealed record UpdateCheckResult(UpdateCheckStatus Status, Version? LatestVersion = null);

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

    public async Task<UpdateCheckResult> CheckForUpdateAsync(CancellationToken ct, bool manual = false)
    {
        ct.ThrowIfCancellationRequested();
        if (!manual && _updatePromptCompletedThisSession)
            return new(UpdateCheckStatus.Busy);

        if (Interlocked.CompareExchange(ref _checkInFlight, 1, 0) != 0)
            return new(UpdateCheckStatus.Busy);

        try
        {
            var currentVersion = AppUpdatePolicy.ResolveCurrentAppVersion(
                Assembly.GetEntryAssembly()?.Location,
                Assembly.GetEntryAssembly()?.GetName().Version,
                AppContext.BaseDirectory);
            var latest = await GetLatestReleaseAsync(ct).ConfigureAwait(false);

            if (latest == null)
                return new(UpdateCheckStatus.Unavailable);
            if (!AppUpdatePolicy.ShouldOfferUpgrade(latest.Version, currentVersion))
                return new(UpdateCheckStatus.UpToDate, latest.Version);

            if (_prompter is null)
                return new(UpdateCheckStatus.UpdateAvailable, latest.Version);

            if (await _prompter.PromptAsync(ct).ConfigureAwait(false))
                _updatePromptCompletedThisSession = true;
            return new(UpdateCheckStatus.UpdateAvailable, latest.Version);
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested) { throw; }
        catch (Exception ex)
        {
            CrashReporter.ReportNonFatal(ex, "GitHubUpdateChecker.CheckForUpdate");
            return new(UpdateCheckStatus.Unavailable);
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
        catch (OperationCanceledException) when (ct.IsCancellationRequested) { throw; }
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
        if (doc.RootElement.ValueKind != JsonValueKind.Object ||
            !doc.RootElement.TryGetProperty("tag_name", out var tagEl) || tagEl.ValueKind != JsonValueKind.String)
            return null;
        var tag = tagEl.GetString();
        if (string.IsNullOrWhiteSpace(tag))
            return null;

        var version = ReleaseVersionParser.ParseTag(tag);
        if (version == new Version(0, 0, 0))
            return null;
        foreach (var flag in new[] { "draft", "prerelease" })
            if (doc.RootElement.TryGetProperty(flag, out var value) && value.ValueKind != JsonValueKind.False)
                return null;
        return new GitHubRelease { Version = version };
    }

    private sealed class GitHubRelease
    {
        public Version Version { get; init; } = null!;
    }
}
