using DataGateWin.CrashReporting;
using Xunit;

namespace DataGateWin.Tests;

public sealed class CrashReportQueueTests
{
    [Fact]
    public void Enqueue_ReadPending_Remove_RoundTrip()
    {
        var dir = Path.Combine(Path.GetTempPath(), "datagate_crash_test_" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(dir);

        try
        {
            var q = new CrashReportQueue(dir);
            var fn = "win_crash_2026-05-01T12-34-56.789Z.txt";
            var payload = "timestamp_utc=x\n\nstack";

            q.Enqueue(fn, payload);

            var pending = q.ReadPending();
            Assert.Single(pending);
            var item = pending[0];
            Assert.Equal(fn, item.CrashFilename);
            Assert.Equal(payload, item.Payload);
            Assert.Null(item.ProcessName);

            Assert.True(q.TryRemove(item.AbsolutePath));
            Assert.False(File.Exists(item.AbsolutePath));
            Assert.Empty(q.ReadPending());
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
                // best-effort cleanup in tests
            }
        }
    }

    [Fact]
    public void ReadPending_SkipsCorruptedQueueFiles()
    {
        var dir = Path.Combine(Path.GetTempPath(), "datagate_crash_corrupt_" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(dir);

        try
        {
            var goodPath = Path.Combine(dir, "good.queued.json");
            File.WriteAllText(
                goodPath,
                """{"Filename":"win_crash.txt","Payload":"ok"}""");

            var badPath = Path.Combine(dir, "bad.queued.json");
            File.WriteAllText(badPath, "{ not json");

            var q = new CrashReportQueue(dir);
            var pending = q.ReadPending();

            Assert.Single(pending);
            Assert.Equal("win_crash.txt", pending[0].CrashFilename);
            Assert.Equal("ok", pending[0].Payload);
            Assert.Null(pending[0].ProcessName);
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

    [Fact]
    public void TryRemove_MissingFile_ReturnsFalse()
    {
        var dir = Path.Combine(Path.GetTempPath(), "datagate_crash_remove_" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(dir);

        try
        {
            var q = new CrashReportQueue(dir);
            Assert.False(q.TryRemove(Path.Combine(dir, "nope.queued.json")));
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

    [Fact]
    public void Enqueue_ReadPending_PreservesProcessName()
    {
        var dir = Path.Combine(Path.GetTempPath(), "datagate_crash_process_" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(dir);

        try
        {
            var q = new CrashReportQueue(dir);

            q.Enqueue("win_engine_crash.txt", "payload", "com.imkolganov.datagate.win.engine");

            var pending = q.ReadPending();
            Assert.Single(pending);
            Assert.Equal("com.imkolganov.datagate.win.engine", pending[0].ProcessName);
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
