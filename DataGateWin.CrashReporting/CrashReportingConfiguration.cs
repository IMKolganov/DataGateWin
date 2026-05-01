namespace DataGateWin.CrashReporting;

/// <summary>Maps from appsettings.json section "CrashReporting".</summary>
public sealed class CrashReportingConfiguration
{
    /// <summary>When false, handlers stay registered but reports are not sent or enqueued.</summary>
    public bool Enabled { get; set; } = true;

    /// <summary>Backend base URL (scheme + host, optional path prefix). Falls back to Api:BaseUrl when empty.</summary>
    public string? BaseUrl { get; set; }

    /// <summary>Value for X-Crash-Process (e.g. com.imkolganov.datagate.win).</summary>
    public string ProcessName { get; set; } = CrashReporter.DefaultProcessName;

    /// <summary>Optional shared secret for X-Crash-Token. Never log this value.</summary>
    public string? CrashToken { get; set; }
}
