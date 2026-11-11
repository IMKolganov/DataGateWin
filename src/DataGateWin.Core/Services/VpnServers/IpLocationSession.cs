namespace DataGateWin.Services.VpnServers;

/// <summary>Page-scoped cache, retry throttle and cancellation for optional geolocation.</summary>
public sealed class IpLocationSession(
    Func<CancellationToken, Task<IpLocation?>> fetch,
    TimeProvider? timeProvider = null)
{
    private readonly object _gate = new();
    private readonly TimeProvider _clock = timeProvider ?? TimeProvider.System;
    private CancellationTokenSource? _request;
    private DateTimeOffset _nextAttempt;
    public IpLocation? Location { get; private set; }

    public async Task<bool> TryLoadAsync()
    {
        CancellationTokenSource request;
        lock (_gate)
        {
            if (_request is not null || Location is not null || _clock.GetUtcNow() < _nextAttempt)
                return false;
            request = new CancellationTokenSource();
            _request = request;
            _nextAttempt = _clock.GetUtcNow().AddMinutes(5);
        }
        try
        {
            var location = await fetch(request.Token).ConfigureAwait(false);
            lock (_gate)
            {
                if (!ReferenceEquals(_request, request) || request.IsCancellationRequested || location is null)
                    return false;
                Location = location;
                return true;
            }
        }
        catch (Exception)
        {
            return false;
        }
        finally
        {
            lock (_gate)
            {
                if (ReferenceEquals(_request, request)) _request = null;
                request.Dispose();
            }
        }
    }

    public void Cancel()
    {
        lock (_gate)
        {
            _request?.Cancel();
            _request = null;
        }
    }
}
