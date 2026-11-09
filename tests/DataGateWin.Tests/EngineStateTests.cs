using DataGateWin.Services.Ipc;
using Xunit;

namespace DataGateWin.Tests;

public sealed class EngineStateTests
{
    [Theory]
    [InlineData(null, true)]
    [InlineData("", true)]
    [InlineData("  ", true)]
    [InlineData("idle", true)]
    [InlineData("IDLE", true)]
    [InlineData("connected", false)]
    [InlineData("stopped", false)]
    public void IsIdle(string? state, bool expected)
        => Assert.Equal(expected, EngineState.IsIdle(state));

    [Fact]
    public void IsUnknown_OnlyNull()
    {
        Assert.True(EngineState.IsUnknown(null));
        Assert.False(EngineState.IsUnknown(""));
        Assert.False(EngineState.IsUnknown("idle"));
    }

    [Theory]
    [InlineData("stopped", true)]
    [InlineData("error", true)]
    [InlineData("ERROR", true)]
    [InlineData("connected", false)]
    [InlineData("idle", false)]
    [InlineData(null, false)]
    public void NeedsCleanup(string? state, bool expected)
        => Assert.Equal(expected, EngineState.NeedsCleanup(state));

    [Theory]
    [InlineData("connected", true)]
    [InlineData("connecting", true)]
    [InlineData("starting", true)]
    [InlineData("stopping", true)]
    [InlineData("stopped", false)]
    [InlineData("error", false)]
    [InlineData("idle", false)]
    public void IsLiveSession(string? state, bool expected)
        => Assert.Equal(expected, EngineState.IsLiveSession(state));

    [Fact]
    public void IsConnected_OnlyConnected()
    {
        Assert.True(EngineState.IsConnected("connected"));
        Assert.False(EngineState.IsConnected("connecting"));
        Assert.False(EngineState.IsConnected("stopped"));
    }
}
