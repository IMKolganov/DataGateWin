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
}
