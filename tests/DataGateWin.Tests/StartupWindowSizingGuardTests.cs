using DataGateWin.Services.Ui;
using Xunit;
namespace DataGateWin.Tests;
public sealed class StartupWindowSizingGuardTests
{
    private static readonly DateTimeOffset Start = DateTimeOffset.Parse("2026-11-11T00:00:00Z");

    [Fact]
    public void StartupRetries_RunOnlyInsideStartupWindow()
    {
        var guard = new StartupWindowSizingGuard(Start.AddSeconds(6));
        Assert.True(guard.CanResize(true, Start));
        Assert.True(guard.CanResize(true, Start.AddSeconds(5)));
        Assert.False(guard.CanResize(true, Start.AddSeconds(7)));
    }

    [Fact]
    public void MaximizeThenRestore_CancelsAlreadyScheduledRetries()
    {
        var guard = new StartupWindowSizingGuard(Start.AddSeconds(6));
        Assert.True(guard.CanResize(true, Start));
        Assert.False(guard.CanResize(false, Start.AddSeconds(1)));
        Assert.False(guard.CanResize(true, Start.AddSeconds(2)));
    }

    [Fact]
    public void ClosedWindow_NeverGetsResizedByLateTimer()
    {
        var guard = new StartupWindowSizingGuard(Start.AddSeconds(6));
        guard.Cancel();
        Assert.False(guard.CanResize(true, Start.AddSeconds(1)));
    }
}
