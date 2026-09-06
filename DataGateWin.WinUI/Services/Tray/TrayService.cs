using System.Runtime.InteropServices;
using DataGateWin.Localization;
using Microsoft.UI.Xaml;
using WinRT.Interop;

namespace DataGateWin.Services.Tray;

/// <summary>Minimal Win32 NotifyIcon tray: Open / Exit. Close of main window hides to tray.</summary>
public sealed class TrayService : IDisposable
{
    private const uint WmTray = 0x8001;
    private const uint WmLButtonDblClk = 0x0203;
    private const uint WmRButtonUp = 0x0205;
    private const uint NimAdd = 0x00000000;
    private const uint NimDelete = 0x00000002;
    private const uint NifMessage = 0x00000001;
    private const uint NifIcon = 0x00000002;
    private const uint NifTip = 0x00000004;

    private Window? _mainWindow;
    private bool _isRegistered;
    private bool _explicitExit;
    private IntPtr _hwnd;
    private NativeWindowProc? _wndProc;
    private IntPtr _prevWndProc;
    private NOTIFYICONDATA _nid;
    private IntPtr _hIcon;

    public void AttachMainWindow(Window mainWindow)
    {
        _mainWindow = mainWindow ?? throw new ArgumentNullException(nameof(mainWindow));
    }

    public void Register()
    {
        if (_mainWindow == null)
            throw new InvalidOperationException("Main window is not attached.");

        if (_isRegistered)
            return;

        _hwnd = WindowNative.GetWindowHandle(_mainWindow);
        if (_hwnd == IntPtr.Zero)
            return;

        _mainWindow.Closed += OnMainWindowClosed;
        if (_mainWindow.AppWindow != null)
            _mainWindow.AppWindow.Closing += OnAppWindowClosing;

        _wndProc = WndProc;
        _prevWndProc = SetWindowLongPtr(_hwnd, -4, Marshal.GetFunctionPointerForDelegate(_wndProc));

        var iconPath = Path.Combine(AppContext.BaseDirectory, "Images", "favicon.ico");
        if (!File.Exists(iconPath))
            iconPath = Path.Combine(AppContext.BaseDirectory, "Assets", "favicon.ico");
        if (File.Exists(iconPath))
            _hIcon = LoadImage(IntPtr.Zero, iconPath, 1, 0, 0, 0x00000010);

        _nid = new NOTIFYICONDATA
        {
            cbSize = (uint)Marshal.SizeOf<NOTIFYICONDATA>(),
            hWnd = _hwnd,
            uID = 1,
            uFlags = NifMessage | NifIcon | NifTip,
            uCallbackMessage = WmTray,
            hIcon = _hIcon,
            szTip = Loc.T("Tray_Tooltip"),
        };

        Shell_NotifyIcon(NimAdd, ref _nid);
        _isRegistered = true;
    }

    public void Unregister()
    {
        _explicitExit = true;

        if (_mainWindow != null)
        {
            _mainWindow.Closed -= OnMainWindowClosed;
            if (_mainWindow.AppWindow != null)
                _mainWindow.AppWindow.Closing -= OnAppWindowClosing;
        }

        if (_isRegistered)
        {
            Shell_NotifyIcon(NimDelete, ref _nid);
            _isRegistered = false;
        }

        if (_prevWndProc != IntPtr.Zero && _hwnd != IntPtr.Zero)
        {
            SetWindowLongPtr(_hwnd, -4, _prevWndProc);
            _prevWndProc = IntPtr.Zero;
        }

        if (_hIcon != IntPtr.Zero)
        {
            DestroyIcon(_hIcon);
            _hIcon = IntPtr.Zero;
        }
    }

    public void RequestExplicitExit()
    {
        _explicitExit = true;
        Unregister();
        App.RequestExit();
    }

    private void OnAppWindowClosing(Microsoft.UI.Windowing.AppWindow sender, Microsoft.UI.Windowing.AppWindowClosingEventArgs args)
    {
        if (_explicitExit || !_isRegistered)
            return;

        args.Cancel = true;
        _mainWindow?.AppWindow.Hide();
    }

    private void OnMainWindowClosed(object sender, WindowEventArgs args)
    {
        // Closed after explicit exit path.
    }

    private void ShowMainWindow()
    {
        if (_mainWindow is null)
            return;

        _mainWindow.AppWindow.Show();
        _mainWindow.Activate();
    }

    private IntPtr WndProc(IntPtr hWnd, uint msg, IntPtr wParam, IntPtr lParam)
    {
        if (msg == WmTray)
        {
            var mouseMsg = (uint)lParam.ToInt64() & 0xFFFF;
            if (mouseMsg == WmLButtonDblClk)
            {
                ShowMainWindow();
                return IntPtr.Zero;
            }

            if (mouseMsg == WmRButtonUp)
            {
                ShowContextMenu();
                return IntPtr.Zero;
            }
        }

        return CallWindowProc(_prevWndProc, hWnd, msg, wParam, lParam);
    }

    private void ShowContextMenu()
    {
        var hMenu = CreatePopupMenu();
        AppendMenu(hMenu, 0, 1, Loc.T("Tray_Open"));
        AppendMenu(hMenu, 0, 2, Loc.T("Tray_Exit"));

        GetCursorPos(out var pt);
        SetForegroundWindow(_hwnd);
        var cmd = TrackPopupMenu(hMenu, 0x0100, pt.X, pt.Y, 0, _hwnd, IntPtr.Zero);
        DestroyMenu(hMenu);

        if (cmd == 1)
            ShowMainWindow();
        else if (cmd == 2)
            RequestExplicitExit();
    }

    public void Dispose() => Unregister();

    private delegate IntPtr NativeWindowProc(IntPtr hWnd, uint msg, IntPtr wParam, IntPtr lParam);

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct NOTIFYICONDATA
    {
        public uint cbSize;
        public IntPtr hWnd;
        public uint uID;
        public uint uFlags;
        public uint uCallbackMessage;
        public IntPtr hIcon;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 128)]
        public string szTip;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct POINT
    {
        public int X;
        public int Y;
    }

    [DllImport("shell32.dll", CharSet = CharSet.Unicode)]
    private static extern bool Shell_NotifyIcon(uint dwMessage, ref NOTIFYICONDATA lpData);

    [DllImport("user32.dll", CharSet = CharSet.Unicode)]
    private static extern IntPtr LoadImage(IntPtr hInst, string name, uint type, int cx, int cy, uint fuLoad);

    [DllImport("user32.dll")]
    private static extern bool DestroyIcon(IntPtr hIcon);

    [DllImport("user32.dll")]
    private static extern IntPtr SetWindowLongPtr(IntPtr hWnd, int nIndex, IntPtr dwNewLong);

    [DllImport("user32.dll")]
    private static extern IntPtr CallWindowProc(IntPtr lpPrevWndFunc, IntPtr hWnd, uint msg, IntPtr wParam, IntPtr lParam);

    [DllImport("user32.dll")]
    private static extern IntPtr CreatePopupMenu();

    [DllImport("user32.dll", CharSet = CharSet.Unicode)]
    private static extern bool AppendMenu(IntPtr hMenu, uint uFlags, uint uIDNewItem, string lpNewItem);

    [DllImport("user32.dll")]
    private static extern bool DestroyMenu(IntPtr hMenu);

    [DllImport("user32.dll")]
    private static extern bool GetCursorPos(out POINT lpPoint);

    [DllImport("user32.dll")]
    private static extern bool SetForegroundWindow(IntPtr hWnd);

    [DllImport("user32.dll")]
    private static extern int TrackPopupMenu(IntPtr hMenu, uint uFlags, int x, int y, int nReserved, IntPtr hWnd, IntPtr prcRect);
}
