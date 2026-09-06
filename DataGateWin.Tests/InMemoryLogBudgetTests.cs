using DataGateWin.CrashReporting;
using DataGateWin.Pages.Home;
using Xunit;

namespace DataGateWin.Tests;

public sealed class InMemoryLogBudgetTests
{
    [Fact]
    public void MaxLines_Is1000()
    {
        Assert.Equal(1000, InMemoryLogBudget.MaxLines);
    }

    [Fact]
    public void AppendLine_KeepsOnlyNewestMaxLines()
    {
        var lines = new List<string>();
        for (var i = 0; i < 1005; i++)
            InMemoryLogBudget.AppendLine(lines, $"L{i}", maxLines: 1000);

        Assert.Equal(1000, lines.Count);
        Assert.Equal("L5", lines[0]);
        Assert.Equal("L1004", lines[^1]);
    }

    [Fact]
    public void AppendLine_ReturnsTrueOnlyWhenDropping()
    {
        var lines = new List<string>();
        Assert.False(InMemoryLogBudget.AppendLine(lines, "a", maxLines: 2));
        Assert.False(InMemoryLogBudget.AppendLine(lines, "b", maxLines: 2));
        Assert.True(InMemoryLogBudget.AppendLine(lines, "c", maxLines: 2));
        Assert.Equal(new[] { "b", "c" }, lines);
    }

    [Fact]
    public void JoinLinesForTextBox_AddsTrailingNewline()
    {
        Assert.Equal(string.Empty, InMemoryLogBudget.JoinLinesForTextBox(Array.Empty<string>()));
        Assert.Equal("a" + Environment.NewLine, InMemoryLogBudget.JoinLinesForTextBox(new[] { "a" }));
        Assert.Equal(
            "a" + Environment.NewLine + "b" + Environment.NewLine,
            InMemoryLogBudget.JoinLinesForTextBox(new[] { "a", "b" }));
    }

    [Fact]
    public void HomeStateStore_AppendLog_KeepsLast1000()
    {
        var store = new HomeStateStore();
        for (var i = 0; i < 1200; i++)
            store.AppendLog($"line-{i}");

        var snap = store.GetLogSnapshot();
        Assert.Equal(1000, snap.Count);
        Assert.Equal("line-200", snap[0]);
        Assert.Equal("line-1199", snap[^1]);
    }
}

public sealed class CrashReportQueueBudgetTests
{
    [Fact]
    public void Enqueue_TrimsOldestWhenOverDirectoryBudget()
    {
        var dir = Path.Combine(Path.GetTempPath(), "datagate_crash_budget_" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(dir);

        try
        {
            var q = new CrashReportQueue(dir, maxDirectoryBytes: 400);
            for (var i = 0; i < 20; i++)
                q.Enqueue($"crash_{i}.txt", new string('p', 80), "proc");

            var files = Directory.GetFiles(dir, "*.queued.json");
            long total = files.Sum(f => new FileInfo(f).Length);
            Assert.True(total <= 400, $"total={total}");
            Assert.NotEmpty(files);
            Assert.True(files.Length < 20);
        }
        finally
        {
            try
            {
                if (Directory.Exists(dir))
                    Directory.Delete(dir, recursive: true);
            }
            catch
            {
            }
        }
    }
}
