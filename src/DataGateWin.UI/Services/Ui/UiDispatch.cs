using DataGateWin.CrashReporting;
using Microsoft.UI.Dispatching;

namespace DataGateWin.Services.Ui;

/// <summary>
/// WinUI 3 unpackaged has no <see cref="SynchronizationContext"/> unless installed at launch.
/// Touching XAML off-thread FailFasts the process (Access page after VPN connect).
/// </summary>
internal static class UiDispatch
{
    public static void Run(DispatcherQueue? queue, Action action, string tag)
    {
        ArgumentNullException.ThrowIfNull(action);

        void Safe()
        {
            try
            {
                action();
            }
            catch (Exception ex)
            {
                CrashReporter.ReportNonFatal(ex, tag);
            }
        }

        var dq = queue ?? App.UiDispatcher;
        if (dq is null)
        {
            CrashReporter.ReportNonFatal(
                new InvalidOperationException("No DispatcherQueue; skipped UI mutate."),
                tag + ".NoQueue");
            return;
        }

        try
        {
            if (dq.HasThreadAccess)
            {
                Safe();
                return;
            }

            if (!dq.TryEnqueue(Safe))
            {
                CrashReporter.ReportNonFatal(
                    new InvalidOperationException("DispatcherQueue.TryEnqueue returned false."),
                    tag + ".Enqueue");
            }
        }
        catch (Exception ex)
        {
            CrashReporter.ReportNonFatal(ex, tag + ".Enqueue");
        }
    }
}
