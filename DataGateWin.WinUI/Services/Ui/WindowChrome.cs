using System.Runtime.InteropServices;
using Microsoft.UI.Dispatching;
using Microsoft.UI.Windowing;
using Microsoft.UI.Xaml;
using WinRT.Interop;

namespace DataGateWin.Services.Ui;

internal static class WindowChrome
{
    private const uint SwpNoZOrder = 0x0004;
    private const uint SwpNoActivate = 0x0010;
    private const uint SwpNoMove = 0x0002;
    private const uint MonitorDefaultToNearest = 2;

    public static void ApplyDefault(
        Window window,
        double width = 980,
        double height = 620,
        int? minWidth = 900,
        int? minHeight = 560,
        bool centerOnScreen = true)
    {
        try
        {
            var hwnd = WindowNative.GetWindowHandle(window);
            var appWindow = window.AppWindow;

            if (appWindow.Presenter is OverlappedPresenter overlapped)
            {
                overlapped.IsResizable = true;
                overlapped.IsMaximizable = true;
                overlapped.IsMinimizable = true;
                if (minWidth is int mw)
                    overlapped.PreferredMinimumWidth = mw;
                if (minHeight is int mh)
                    overlapped.PreferredMinimumHeight = mh;
            }

            ApplyIcon(window, hwnd, appWindow);

            var guardUntil = DateTime.UtcNow.AddSeconds(6);
            var reentry = false;

          void Reapply(bool center)
            {
                if (reentry)
                    return;
                reentry = true;
                try
                {
                    ForcePhysicalSize(hwnd, width, height, center);
                }
                finally
                {
                    reentry = false;
                }
            }

            Reapply(centerOnScreen);

            void OnAppWindowChanged(AppWindow sender, AppWindowChangedEventArgs args)
            {
                if (!args.DidSizeChange)
                    return;

                if (DateTime.UtcNow > guardUntil)
                {
                    appWindow.Changed -= OnAppWindowChanged;
                    return;
                }

                if (!TryGetCurrentSize(hwnd, out var curW, out var curH))
                    return;

                var scale = GetScale(hwnd);
                var wantW = DipToPx(width, scale);
                var wantH = DipToPx(height, scale);
                // WinUI sometimes reverts to DIP values as if they were physical px (~half at 200% DPI).
                if (curW < wantW * 0.85 || curH < wantH * 0.85)
                    ScheduleRetries(window, () => Reapply(center: false), 0, 50);
            }

            appWindow.Changed += OnAppWindowChanged;

            void OnActivated(object sender, WindowActivatedEventArgs args)
            {
                if (args.WindowActivationState == WindowActivationState.Deactivated)
                    return;

                window.Activated -= OnActivated;
                ScheduleRetries(window, () => Reapply(center: false), 0, 100, 300, 800, 1600, 3000, 5000);
            }

            window.Activated += OnActivated;

            if (window.Content is FrameworkElement root)
            {
                void OnLoaded(object sender, RoutedEventArgs e)
                {
                    root.Loaded -= OnLoaded;
                    ScheduleRetries(window, () => Reapply(center: false), 0, 150, 400);
                }

                if (root.IsLoaded)
                    ScheduleRetries(window, () => Reapply(center: false), 0, 150, 400);
                else
                    root.Loaded += OnLoaded;
            }
        }
        catch
        {
            /* chrome is best-effort */
        }
    }

    private static void ScheduleRetries(Window window, Action action, params int[] delaysMs)
    {
        foreach (var delay in delaysMs)
        {
            if (delay <= 0)
            {
                try { action(); } catch { /* ignore */ }
                continue;
            }

            var timer = window.DispatcherQueue.CreateTimer();
            timer.Interval = TimeSpan.FromMilliseconds(delay);
            timer.IsRepeating = false;
            timer.Tick += (_, _) =>
            {
                timer.Stop();
                try { action(); } catch { /* ignore */ }
            };
            timer.Start();
        }
    }

    private static void ForcePhysicalSize(IntPtr hwnd, double widthDip, double heightDip, bool center)
    {
        var scale = GetScale(hwnd);
        var widthPx = DipToPx(widthDip, scale);
        var heightPx = DipToPx(heightDip, scale);

        var flags = SwpNoZOrder | SwpNoActivate;
        if (center && TryGetMonitorWorkArea(hwnd, out var work))
        {
            var workW = work.Right - work.Left;
            var workH = work.Bottom - work.Top;
            widthPx = Math.Min(widthPx, Math.Max(1, workW - 16));
            heightPx = Math.Min(heightPx, Math.Max(1, workH - 16));
            var x = work.Left + Math.Max(0, (workW - widthPx) / 2);
            var y = work.Top + Math.Max(0, (workH - heightPx) / 2);
            SetWindowPos(hwnd, IntPtr.Zero, x, y, widthPx, heightPx, flags);
        }
        else
        {
            SetWindowPos(hwnd, IntPtr.Zero, 0, 0, widthPx, heightPx, flags | SwpNoMove);
        }

        try
        {
            GetWindowRect(hwnd, out var rect);
            var boot = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
                "DataGateWin",
                "startup-error.log");
            File.AppendAllText(
                boot,
                $"WindowChrome scale={scale:0.###} want={widthPx}x{heightPx} got={(rect.Right - rect.Left)}x{(rect.Bottom - rect.Top)} dpi={GetDpiForWindow(hwnd)}\n");
        }
        catch { /* ignore */ }
    }

    private static bool TryGetCurrentSize(IntPtr hwnd, out int w, out int h)
    {
        w = h = 0;
        if (!GetWindowRect(hwnd, out var rect))
            return false;
        w = rect.Right - rect.Left;
        h = rect.Bottom - rect.Top;
        return w > 0 && h > 0;
    }

    private static bool TryGetMonitorWorkArea(IntPtr hwnd, out RECT work)
    {
        work = default;
        var mon = MonitorFromWindow(hwnd, MonitorDefaultToNearest);
        if (mon == IntPtr.Zero)
            return false;

        var info = new MONITORINFO { cbSize = (uint)Marshal.SizeOf<MONITORINFO>() };
        if (!GetMonitorInfo(mon, ref info))
            return false;

        work = info.rcWork;
        return true;
    }

    private static int DipToPx(double dip, double scale)
        => Math.Max(1, (int)Math.Round(dip * scale));

    private static void ApplyIcon(Window window, IntPtr hwnd, AppWindow appWindow)
    {
        AppIcon.ApplyToWindow(window);

        void OnActivated(object sender, WindowActivatedEventArgs args)
        {
            if (args.WindowActivationState == WindowActivationState.Deactivated)
                return;
            window.Activated -= OnActivated;
            AppIcon.ApplyToWindow(appWindow, hwnd);
        }

        window.Activated += OnActivated;
    }

    private static double GetScale(IntPtr hwnd)
    {
        try
        {
            var dpi = GetDpiForWindow(hwnd);
            if (dpi > 96)
                return dpi / 96.0;
        }
        catch { /* ignore */ }

        try
        {
            var dpi = GetDpiForSystem();
            if (dpi > 96)
                return dpi / 96.0;
        }
        catch { /* ignore */ }

        return 1.0;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct RECT
    {
        public int Left, Top, Right, Bottom;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct MONITORINFO
    {
        public uint cbSize;
        public RECT rcMonitor;
        public RECT rcWork;
        public uint dwFlags;
    }

    [DllImport("user32.dll")]
    private static extern uint GetDpiForWindow(IntPtr hwnd);

    [DllImport("user32.dll")]
    private static extern uint GetDpiForSystem();

    [DllImport("user32.dll", SetLastError = true)]
    private static extern bool SetWindowPos(IntPtr hWnd, IntPtr hWndInsertAfter, int x, int y, int cx, int cy, uint uFlags);

    [DllImport("user32.dll")]
    private static extern bool GetWindowRect(IntPtr hWnd, out RECT lpRect);

    [DllImport("user32.dll")]
    private static extern IntPtr MonitorFromWindow(IntPtr hwnd, uint dwFlags);

    [DllImport("user32.dll", CharSet = CharSet.Auto)]
    private static extern bool GetMonitorInfo(IntPtr hMonitor, ref MONITORINFO lpmi);
}
