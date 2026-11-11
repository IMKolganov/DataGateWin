namespace DataGateWin.Services.Ui;

public sealed class StartupWindowSizingGuard(DateTimeOffset deadline)
{
    private bool _cancelled;
    public void Cancel() => _cancelled = true;
    public bool CanResize(bool restored, DateTimeOffset now)
    {
        if (_cancelled) return false;
        if (!restored || now > deadline) { Cancel(); return false; }
        return true;
    }
}
