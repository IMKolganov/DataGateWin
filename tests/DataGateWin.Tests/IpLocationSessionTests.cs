using DataGateWin.Services.VpnServers;
using Xunit;

namespace DataGateWin.Tests;

public sealed class IpLocationSessionTests
{
    private static readonly IpLocation Position = new(35, 33);

    [Fact]
    public async Task Success_IsCachedForSession()
    {
        var calls = 0;
        var clock = new Clock();
        var session = new IpLocationSession(_ => { calls++; return Task.FromResult<IpLocation?>(Position); }, clock);
        Assert.True(await session.TryLoadAsync());
        clock.Advance(TimeSpan.FromDays(1));
        Assert.False(await session.TryLoadAsync());
        Assert.Equal(Position, session.Location);
        Assert.Equal(1, calls);
    }

    [Fact]
    public async Task Failure_ThrottlesRetriesForFiveMinutes_ThenAllowsSuccess()
    {
        var calls = 0;
        var clock = new Clock();
        var session = new IpLocationSession(_ => Task.FromResult(++calls == 1 ? null : Position), clock);
        Assert.False(await session.TryLoadAsync());
        Assert.Null(session.Location);
        clock.Advance(TimeSpan.FromMinutes(5) - TimeSpan.FromTicks(1));
        Assert.False(await session.TryLoadAsync());
        Assert.Equal(1, calls);
        clock.Advance(TimeSpan.FromTicks(1));
        Assert.True(await session.TryLoadAsync());
        Assert.Equal(2, calls);
    }

    [Fact]
    public async Task PendingRequest_DoesNotBlockCaller_OrStartDuplicate()
    {
        var pending = new TaskCompletionSource<IpLocation?>(TaskCreationOptions.RunContinuationsAsynchronously);
        var calls = 0;
        var clock = new Clock();
        var session = new IpLocationSession(_ => { calls++; return pending.Task; }, clock);
        var first = session.TryLoadAsync();
        Assert.False(first.IsCompleted);
        clock.Advance(TimeSpan.FromMinutes(10));
        Assert.False(await session.TryLoadAsync());
        Assert.Equal(1, calls);
        pending.SetResult(Position);
        Assert.True(await first);
    }

    [Fact]
    public async Task UnloadCancellation_DiscardsLateResult_EvenIfProviderIgnoresToken()
    {
        var pending = new TaskCompletionSource<IpLocation?>(TaskCreationOptions.RunContinuationsAsynchronously);
        CancellationToken observed = default;
        var session = new IpLocationSession(token => { observed = token; return pending.Task; });
        var task = session.TryLoadAsync();
        session.Cancel();
        session.Cancel();
        Assert.True(observed.IsCancellationRequested);
        pending.SetResult(Position);
        Assert.False(await task);
        Assert.Null(session.Location);
    }

    [Fact]
    public async Task OldCompletion_CannotOverwriteNewRequest_OrClearItsPendingState()
    {
        var old = new TaskCompletionSource<IpLocation?>(TaskCreationOptions.RunContinuationsAsynchronously);
        var current = new TaskCompletionSource<IpLocation?>(TaskCreationOptions.RunContinuationsAsynchronously);
        var clock = new Clock();
        var calls = 0;
        var session = new IpLocationSession(_ => ++calls == 1 ? old.Task : current.Task, clock);
        var first = session.TryLoadAsync();
        session.Cancel();
        clock.Advance(TimeSpan.FromMinutes(5));
        var second = session.TryLoadAsync();
        old.SetResult(new IpLocation(0, 0));
        Assert.False(await first);
        Assert.False(await session.TryLoadAsync());
        Assert.Null(session.Location);
        current.SetResult(Position);
        Assert.True(await second);
        Assert.Equal(Position, session.Location);
        Assert.Equal(2, calls);
    }

    [Fact]
    public async Task ProviderException_IsIsolated_AndRetryCanRecover()
    {
        var clock = new Clock();
        var calls = 0;
        var session = new IpLocationSession(_ => ++calls == 1
            ? throw new InvalidOperationException("provider failed") : Task.FromResult<IpLocation?>(Position), clock);
        Assert.False(await session.TryLoadAsync());
        Assert.False(await session.TryLoadAsync());
        clock.Advance(TimeSpan.FromMinutes(5));
        Assert.True(await session.TryLoadAsync());
    }

    private sealed class Clock : TimeProvider
    {
        private DateTimeOffset _now = new(2026, 1, 1, 0, 0, 0, TimeSpan.Zero);
        public override DateTimeOffset GetUtcNow() => _now;
        public void Advance(TimeSpan interval) => _now += interval;
    }
}
