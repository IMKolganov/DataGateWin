using Microsoft.UI.Dispatching;

namespace DataGateWin.Services.Ui;

/// <summary>
/// WinUI unpackaged does not install a <see cref="SynchronizationContext"/>,
/// so <c>await</c> resumes on the thread pool and XAML updates FailFast the process.
/// </summary>
internal sealed class DispatcherQueueSyncContext : SynchronizationContext
{
    private readonly DispatcherQueue _queue;

    public DispatcherQueueSyncContext(DispatcherQueue queue)
        => _queue = queue ?? throw new ArgumentNullException(nameof(queue));

    public override void Post(SendOrPostCallback d, object? state)
    {
        ArgumentNullException.ThrowIfNull(d);
        _ = _queue.TryEnqueue(() => d(state));
    }

    public override void Send(SendOrPostCallback d, object? state)
    {
        ArgumentNullException.ThrowIfNull(d);
        if (_queue.HasThreadAccess)
        {
            d(state);
            return;
        }

        using var done = new ManualResetEventSlim(false);
        Exception? error = null;
        if (!_queue.TryEnqueue(() =>
            {
                try { d(state); }
                catch (Exception ex) { error = ex; }
                finally { done.Set(); }
            }))
        {
            throw new InvalidOperationException("DispatcherQueue.TryEnqueue failed.");
        }

        done.Wait();
        if (error is not null)
            throw error;
    }

    public override SynchronizationContext CreateCopy() => new DispatcherQueueSyncContext(_queue);
}
