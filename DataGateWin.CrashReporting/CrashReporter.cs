using System.Diagnostics;
using System.Net.Http;
using System.Text;

namespace DataGateWin.CrashReporting;

/// <summary>
/// Global crash / non-fatal reporter: formats payloads, POSTs to DataGate, persists failures to disk.
/// Install handlers once per process via <see cref="InstallDomainHandlers"/>.
/// </summary>
public static class CrashReporter
{
    public const string DefaultProcessName = "com.imkolganov.datagate.win";

    static readonly CrashReportQueue Queue = new();
    static readonly HttpClient Http = CreateHttpClient();
    static readonly object Gate = new();

    static CrashReportingConfiguration Config = new();
    static volatile bool HandlersInstalled;
    static volatile bool SuppressNextAppDomainFatal;

    static CrashReporter()
    {
    }

    static HttpClient CreateHttpClient()
    {
        var handler = new HttpClientHandler();
        return new HttpClient(handler)
        {
            Timeout = TimeSpan.FromSeconds(30),
        };
    }

    /// <summary>Merge appsettings; safe to call multiple times.</summary>
    public static void Configure(CrashReportingConfiguration configuration)
    {
        ArgumentNullException.ThrowIfNull(configuration);
        lock (Gate)
        {
            Config = new CrashReportingConfiguration
            {
                Enabled = configuration.Enabled,
                BaseUrl = configuration.BaseUrl,
                ProcessName = configuration.ProcessName,
                CrashToken = configuration.CrashToken,
            };
        }

        LogStructured(
            "crash_configure",
            ("enabled", configuration.Enabled.ToString()),
            ("base_url_configured", (!string.IsNullOrWhiteSpace(configuration.BaseUrl)).ToString()),
            ("process_name", configuration.ProcessName),
            ("token_configured", (!string.IsNullOrWhiteSpace(configuration.CrashToken)).ToString()));
    }

    /// <summary>Current configuration snapshot.</summary>
    public static CrashReportingConfiguration GetConfiguration()
    {
        lock (Gate)
            return Config;
    }

    /// <summary>Register <see cref="AppDomain.UnhandledException"/> and <see cref="TaskScheduler.UnobservedTaskException"/>.</summary>
    public static void InstallDomainHandlers()
    {
        if (HandlersInstalled)
            return;

        lock (Gate)
        {
            if (HandlersInstalled)
                return;

            AppDomain.CurrentDomain.UnhandledException += OnAppDomainUnhandled;
            TaskScheduler.UnobservedTaskException += OnUnobservedTaskException;
            HandlersInstalled = true;
        }

        LogStructured("crash_handlers_installed", ("domain", "true"), ("unobserved_task", "true"));
    }

    /// <summary>WPF: call from <c>Application.DispatcherUnhandledException</c> before other logic.</summary>
    public static void HandleDispatcherUnhandled(Exception exception)
    {
        if (!IsEnabled())
            return;

        SuppressNextAppDomainFatal = true;
        ScheduleReport(exception, CrashReportKind.Fatal, "UI Thread", tag: null);
    }

    /// <summary>Manual non-fatal report (same endpoint, kind=nonfatal).</summary>
    public static void ReportNonFatal(Exception exception, string? tag = null)
    {
        ArgumentNullException.ThrowIfNull(exception);
        if (!IsEnabled())
            return;

        ScheduleReport(exception, CrashReportKind.NonFatal, GetThreadLabel(), tag);
    }

    /// <summary>Flush persisted queue; safe to call from startup on a background thread.</summary>
    public static Task FlushPendingAsync(CancellationToken cancellationToken = default)
        => Task.Run(() => FlushPendingCoreAsync(cancellationToken), cancellationToken);

    static async Task FlushPendingCoreAsync(CancellationToken cancellationToken)
    {
        var cfg = GetConfiguration();
        if (!cfg.Enabled)
            return;

        var baseUrl = cfg.BaseUrl;
        if (string.IsNullOrWhiteSpace(baseUrl))
            return;

        var pending = Queue.ReadPending();
        if (pending.Count == 0)
            return;

        foreach (var item in pending)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var ok = await TrySendAsync(
                    cfg,
                    item.CrashFilename,
                    item.Payload,
                    cancellationToken)
                .ConfigureAwait(false);

            if (ok)
                Queue.TryRemove(item.AbsolutePath);
        }
    }

    static void OnAppDomainUnhandled(object sender, UnhandledExceptionEventArgs e)
    {
        if (!IsEnabled())
            return;

        if (SuppressNextAppDomainFatal)
        {
            SuppressNextAppDomainFatal = false;
            return;
        }

        if (e.ExceptionObject is not Exception ex)
            return;

        ScheduleReport(ex, CrashReportKind.Fatal, GetThreadLabel(), tag: null);
    }

    static void OnUnobservedTaskException(object? sender, UnobservedTaskExceptionEventArgs e)
    {
        try
        {
            e.SetObserved();
        }
        catch
        {
            // ignore
        }

        if (!IsEnabled())
            return;

        ScheduleReport(e.Exception, CrashReportKind.NonFatal, GetThreadLabel(), tag: "UnobservedTask");
    }

    static bool IsEnabled()
    {
        lock (Gate)
            return Config.Enabled;
    }

    static void ScheduleReport(Exception ex, CrashReportKind kind, string threadLabel, string? tag)
    {
        _ = Task.Run(async () =>
        {
            try
            {
                await ReportCoreAsync(ex, kind, threadLabel, tag, CancellationToken.None)
                    .ConfigureAwait(false);
            }
            catch (Exception inner)
            {
                LogStructured(
                    "crash_report_failed",
                    ("stage", "ScheduleReport"),
                    ("error_type", inner.GetType().FullName ?? inner.GetType().Name));
            }
        });
    }

    static async Task ReportCoreAsync(Exception ex, CrashReportKind kind, string threadLabel, string? tag, CancellationToken ct)
    {
        var cfg = GetConfiguration();
        if (!cfg.Enabled)
            return;

        var filename = BuildCrashFilenameUtc();
        var payload = BuildPayload(ex, kind, threadLabel, tag, cfg);

        if (string.IsNullOrWhiteSpace(cfg.BaseUrl))
        {
            Queue.Enqueue(filename, payload);
            LogStructured(
                "crash_send_skipped",
                ("reason", "base_url_missing"),
                ("queued", "true"),
                ("filename", filename));
            return;
        }

        var sent = await TrySendAsync(cfg, filename, payload, ct).ConfigureAwait(false);
        if (!sent)
            Queue.Enqueue(filename, payload);
    }

    static async Task<bool> TrySendAsync(
        CrashReportingConfiguration cfg,
        string filename,
        string payload,
        CancellationToken cancellationToken)
    {
        var baseUrl = cfg.BaseUrl!.Trim();
        var sw = Stopwatch.StartNew();
        try
        {
            using var response = await CrashIngestClient.PostCrashAsync(
                    Http,
                    baseUrl,
                    filename,
                    string.IsNullOrWhiteSpace(cfg.ProcessName) ? DefaultProcessName : cfg.ProcessName.Trim(),
                    cfg.CrashToken,
                    payload,
                    cancellationToken)
                .ConfigureAwait(false);

            var code = (int)response.StatusCode;
            var outcome = response.IsSuccessStatusCode ? "success" : "http_error";
            LogStructured(
                "crash_send_complete",
                ("outcome", outcome),
                ("http_status", code.ToString()),
                ("elapsed_ms", sw.ElapsedMilliseconds.ToString()),
                ("filename", filename));

            return response.IsSuccessStatusCode;
        }
        catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
        {
            LogStructured(
                "crash_send_complete",
                ("outcome", "timeout_or_canceled"),
                ("http_status", "0"),
                ("elapsed_ms", sw.ElapsedMilliseconds.ToString()),
                ("filename", filename));
            return false;
        }
        catch (Exception ex)
        {
            LogStructured(
                "crash_send_complete",
                ("outcome", "transport_error"),
                ("http_status", "0"),
                ("error_type", ex.GetType().Name),
                ("elapsed_ms", sw.ElapsedMilliseconds.ToString()),
                ("filename", filename));
            return false;
        }
    }

    internal static string BuildPayload(
        Exception ex,
        CrashReportKind kind,
        string threadLabel,
        string? tag,
        CrashReportingConfiguration cfg)
    {
        var utc = DateTime.UtcNow;
        var process = string.IsNullOrWhiteSpace(cfg.ProcessName) ? DefaultProcessName : cfg.ProcessName.Trim();

        var meta = new Dictionary<string, string>
        {
            ["timestamp_utc"] = CrashPayloadFormatter.FormatTimestampUtcIso(utc),
            ["process"] = process,
            ["thread"] = threadLabel,
            ["sdk"] = CrashPayloadFormatter.GetDefaultSdkLabel(),
            ["device"] = CrashPayloadFormatter.GetDefaultDeviceLabel(),
            ["kind"] = kind == CrashReportKind.Fatal ? "fatal" : "nonfatal",
            ["exception"] = ex.GetType().FullName ?? ex.GetType().Name,
            ["message"] = ex.Message ?? string.Empty,
        };

        var ver = CrashPayloadFormatter.TryGetAppAssemblyVersion();
        if (!string.IsNullOrEmpty(ver))
            meta["app_version"] = ver;

        if (!string.IsNullOrWhiteSpace(tag))
            meta["tag"] = tag!;

        var stack = ex.ToString();
        var body = CrashPayloadFormatter.BuildBody(meta, stack);
        return CrashPayloadFormatter.EnforceMaxUtf8Size(body, CrashPayloadFormatter.MaxPayloadUtf8Bytes);
    }

    internal static string BuildCrashFilenameUtc()
    {
        var ts = DateTime.UtcNow;
        return $"win_crash_{ts:yyyy-MM-ddTHH-mm-ss.fff}Z.txt";
    }

    static string GetThreadLabel()
    {
        var name = Thread.CurrentThread.Name;
        if (!string.IsNullOrEmpty(name))
            return name;

        return $"ManagedThread-{Thread.CurrentThread.ManagedThreadId}";
    }

    static void LogStructured(string eventName, params (string Key, string Value)[] pairs)
    {
        var sb = new StringBuilder();
        sb.Append("[CrashReporting] event=");
        sb.Append(eventName);
        foreach (var (k, v) in pairs)
        {
            sb.Append(' ');
            sb.Append(k);
            sb.Append('=');
            sb.Append(v);
        }

        Trace.TraceInformation(sb.ToString());
    }

}
