using DataGateWin.CrashReporting;
using Xunit;

namespace DataGateWin.Tests;

public sealed class CrashReporterBuildTests
{
    [Fact]
    public void BuildCrashFilenameUtc_MatchesPattern()
    {
        var name = CrashReporter.BuildCrashFilenameUtc();
        Assert.Matches(@"^win_crash_\d{4}-\d{2}-\d{2}T\d{2}-\d{2}-\d{2}\.\d{3}Z\.txt$", name);
    }

    [Fact]
    public void BuildPayload_Fatal_IncludesKindFatalAndTag()
    {
        var cfg = new CrashReportingConfiguration
        {
            Enabled = true,
            ProcessName = "test.process",
            BaseUrl = "https://example.invalid/",
        };

        var ex = new InvalidOperationException("failure");
        var body = CrashReporter.BuildPayload(ex, CrashReportKind.Fatal, "Worker", "ui-dispatcher", cfg);

        Assert.Contains("kind=fatal", body, StringComparison.Ordinal);
        Assert.Contains("thread=Worker", body, StringComparison.Ordinal);
        Assert.Contains("tag=ui-dispatcher", body, StringComparison.Ordinal);
        Assert.Contains("process=test.process", body, StringComparison.Ordinal);
        Assert.Contains("exception=", body, StringComparison.Ordinal);
        Assert.Contains("message=failure", body, StringComparison.Ordinal);
        Assert.Contains("\n\n", body, StringComparison.Ordinal);
    }

    [Fact]
    public void BuildPayload_NonFatal_UsesNonfatalKindAndOmitsEmptyTag()
    {
        var cfg = new CrashReportingConfiguration
        {
            Enabled = true,
            ProcessName = "p",
            BaseUrl = "https://example.invalid/",
        };

        var ex = new IOException("io");
        var body = CrashReporter.BuildPayload(ex, CrashReportKind.NonFatal, "Pool", tag: null, cfg);

        Assert.Contains("kind=nonfatal", body, StringComparison.Ordinal);
        Assert.DoesNotContain("tag=", body, StringComparison.Ordinal);
    }

    [Fact]
    public void Configure_ThrowsWhenNull()
    {
        Assert.Throws<ArgumentNullException>(() => CrashReporter.Configure(null!));
    }

    [Fact]
    public void ReportNonFatal_ThrowsWhenExceptionNull()
    {
        Assert.Throws<ArgumentNullException>(() => CrashReporter.ReportNonFatal(null!));
    }
}
