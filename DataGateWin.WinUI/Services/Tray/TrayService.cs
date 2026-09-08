using System.Runtime.InteropServices;
using DataGateWin.CrashReporting;
using DataGateWin.Localization;
using DataGateWin.Models.Ipc;
using Microsoft.UI.Xaml;
using WinRT.Interop;

namespace DataGateWin.Services.Tray;

/// <summary>Win32 NotifyIcon: Open / Connect / Disconnect / Exit, balloons, menu icons.</summary>
public sealed class TrayService : IDisposable
{
    private const uint WmTray = 0x8001;
    private const uint WmLButtonDblClk = 0x0203;
    private const uint WmLButtonUp = 0x0202;
    private const uint WmRButtonUp = 0x0205;
    private const uint NimAdd = 0x00000000;
    private const uint NimModify = 0x00000001;
    private const uint NimDelete = 0x00000002;
    private const uint NimSetVersion = 0x00000004;
    private const uint NotifyIconVersion4 = 4;
    private const uint NifMessage = 0x00000001;
    private const uint NifIcon = 0x00000002;
    private const uint NifTip = 0x00000004;
    private const uint NifInfo = 0x00000010;
    private const uint NiifUser = 0x00000004;
    private const uint NiifLargeIcon = 0x00000020;
    private const uint MiimId = 0x00000002;
    private const uint MiimState = 0x00000001;
    private const uint MiimString = 0x00000040;
    private const uint MiimBitmap = 0x00000080;
    private const uint MiimFtype = 0x00000100;
    private const uint MftString = 0x00000000;
    private const uint MftSeparator = 0x00000800;
    private const uint MfsEnabled = 0x00000000;
    private const uint MfsDisabled = 0x00000003;
    private const uint MimStyle = 0x00000010;
    private const uint MnsCheckOrBmp = 0x04000000;
    private const uint ShgsiIcon = 0x000000100;
    private const uint ShgsiSmallIcon = 0x000000001;
    private const uint SiidApplication = 2;
    private const uint SiidShield = 77;
    private const uint SiidDriveDisconnect = 10;
    private const uint SiidError = 80;
    private const uint ImageBitmap = 0;

    private Window? _mainWindow;
    private bool _isRegistered;
    private bool _explicitExit;
    private IntPtr _hwnd;
    private NativeWindowProc? _wndProc;
    private IntPtr _prevWndProc;
    private NOTIFYICONDATA _nid;
    private IntPtr _hIcon;
    private IntPtr _bmpOpen;
    private IntPtr _bmpConnect;
    private IntPtr _bmpDisconnect;
    private IntPtr _bmpExit;
    private UiState _vpnState = UiState.Idle;
    private bool _sessionWasUp;
    private bool _languageHooked;

    public Action? ConnectRequested { get; set; }
    public Action? DisconnectRequested { get; set; }

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

        var iconPath = DataGateWin.Services.Ui.AppIcon.ResolveIconPath()
            ?? Path.Combine(AppContext.BaseDirectory, "Images", "favicon.ico");
        if (!File.Exists(iconPath))
            iconPath = Path.Combine(AppContext.BaseDirectory, "Assets", "favicon.ico");
        if (File.Exists(iconPath))
            _hIcon = LoadImage(IntPtr.Zero, iconPath, 1, 0, 0, 0x00000010);

        _bmpOpen = StockIconToBitmap(SiidApplication);
        _bmpConnect = StockIconToBitmap(SiidShield);
        _bmpDisconnect = StockIconToBitmap(SiidDriveDisconnect);
        _bmpExit = StockIconToBitmap(SiidError);

        _nid = CreateNotifyData();
        Shell_NotifyIcon(NimAdd, ref _nid);
        _nid.uVersion = NotifyIconVersion4;
        Shell_NotifyIcon(NimSetVersion, ref _nid);
        _isRegistered = true;

        if (!_languageHooked)
        {
            WinUiLanguageService.LanguageChanged += OnLanguageChanged;
            _languageHooked = true;
        }
    }

    public void OnVpnUiState(UiState state, string statusText)
    {
        var window = _mainWindow;
        if (window is null)
            return;

        void Apply()
        {
            _vpnState = state;
            UpdateTip();

            if (!_isRegistered)
                return;

            if (state == UiState.Connected && !_sessionWasUp)
            {
                _sessionWasUp = true;
                ShowBalloon(
                    Loc.T("Tray_Notify_ConnectedTitle"),
                    string.IsNullOrWhiteSpace(statusText) ? Loc.T("Tray_Notify_ConnectedBody") : statusText);
            }
            else if (_sessionWasUp && state is UiState.Idle or UiState.Disconnecting)
            {
                _sessionWasUp = false;
                ShowBalloon(Loc.T("Tray_Notify_DisconnectedTitle"), Loc.T("Tray_Notify_DisconnectedBody"));
            }
        }

        if (window.DispatcherQueue.HasThreadAccess)
            Apply();
        else
            window.DispatcherQueue.TryEnqueue(Apply);
    }

    public void Unregister()
    {
        _explicitExit = true;

        if (_languageHooked)
        {
            WinUiLanguageService.LanguageChanged -= OnLanguageChanged;
            _languageHooked = false;
        }

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

        DestroyIconSafe(ref _hIcon);
        DeleteObjectSafe(ref _bmpOpen);
        DeleteObjectSafe(ref _bmpConnect);
        DeleteObjectSafe(ref _bmpDisconnect);
        DeleteObjectSafe(ref _bmpExit);
    }

    public void RequestExplicitExit()
    {
        _explicitExit = true;
        Unregister();
        App.RequestExit();
    }

    public void Dispose() => Unregister();

    private void OnLanguageChanged(object? sender, EventArgs e)
    {
        var window = _mainWindow;
        if (window is null)
            return;
        window.DispatcherQueue.TryEnqueue(UpdateTip);
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
            if (mouseMsg is WmLButtonDblClk or WmLButtonUp)
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
        var info = new MENUINFO
        {
            cbSize = (uint)Marshal.SizeOf<MENUINFO>(),
            fMask = MimStyle,
            dwStyle = MnsCheckOrBmp,
        };
        SetMenuInfo(hMenu, ref info);

        var canConnect = _vpnState is UiState.Idle;
        var canDisconnect = _vpnState is UiState.Connected or UiState.Connecting;

        AppendItem(hMenu, 1, Loc.T("Tray_Open"), _bmpOpen, enabled: true);
        AppendItem(hMenu, 2, Loc.T("Tray_Connect"), _bmpConnect, enabled: canConnect);
        AppendItem(hMenu, 3, Loc.T("Tray_Disconnect"), _bmpDisconnect, enabled: canDisconnect);
        AppendSeparator(hMenu);
        AppendItem(hMenu, 4, Loc.T("Tray_Exit"), _bmpExit, enabled: true);

        GetCursorPos(out var pt);
        SetForegroundWindow(_hwnd);
        var cmd = TrackPopupMenu(hMenu, 0x0100, pt.X, pt.Y, 0, _hwnd, IntPtr.Zero);
        DestroyMenu(hMenu);

        switch (cmd)
        {
            case 1:
                ShowMainWindow();
                break;
            case 2:
                ConnectRequested?.Invoke();
                break;
            case 3:
                DisconnectRequested?.Invoke();
                break;
            case 4:
                RequestExplicitExit();
                break;
        }
    }

    private void AppendItem(IntPtr hMenu, uint id, string text, IntPtr bitmap, bool enabled)
    {
        var item = new MENUITEMINFO
        {
            cbSize = (uint)Marshal.SizeOf<MENUITEMINFO>(),
            fMask = MiimId | MiimString | MiimBitmap | MiimState | MiimFtype,
            fType = MftString,
            fState = enabled ? MfsEnabled : MfsDisabled,
            wID = id,
            dwTypeData = text,
            hbmpItem = bitmap,
        };
        InsertMenuItem(hMenu, (uint)Math.Max(0, GetMenuItemCount(hMenu)), true, ref item);
    }

    private static void AppendSeparator(IntPtr hMenu)
    {
        var item = new MENUITEMINFO
        {
            cbSize = (uint)Marshal.SizeOf<MENUITEMINFO>(),
            fMask = MiimFtype,
            fType = MftSeparator,
        };
        InsertMenuItem(hMenu, (uint)Math.Max(0, GetMenuItemCount(hMenu)), true, ref item);
    }

    private NOTIFYICONDATA CreateNotifyData() => new()
    {
        cbSize = (uint)Marshal.SizeOf<NOTIFYICONDATA>(),
        hWnd = _hwnd,
        uID = 1,
        uFlags = NifMessage | NifIcon | NifTip,
        uCallbackMessage = WmTray,
        hIcon = _hIcon,
        szTip = CurrentTip(),
        szInfo = "",
        szInfoTitle = "",
    };

    private void UpdateTip()
    {
        if (!_isRegistered)
            return;
        _nid.uFlags = NifMessage | NifIcon | NifTip;
        _nid.hIcon = _hIcon;
        _nid.szTip = CurrentTip();
        _nid.szInfo = "";
        _nid.szInfoTitle = "";
        Shell_NotifyIcon(NimModify, ref _nid);
    }

    private string CurrentTip()
        => _sessionWasUp || _vpnState == UiState.Connected
            ? Loc.T("Tray_Tooltip_Connected")
            : Loc.T("Tray_Tooltip");

    private void ShowBalloon(string title, string body)
    {
        if (!_isRegistered)
            return;
        try
        {
            _nid.uFlags = NifMessage | NifIcon | NifTip | NifInfo;
            _nid.hIcon = _hIcon;
            _nid.hBalloonIcon = _hIcon;
            _nid.szTip = CurrentTip();
            _nid.szInfoTitle = Truncate(title, 63);
            _nid.szInfo = Truncate(body, 255);
            _nid.dwInfoFlags = NiifUser | NiifLargeIcon;
            Shell_NotifyIcon(NimModify, ref _nid);
        }
        catch (Exception ex)
        {
            CrashReporter.ReportNonFatal(ex, "TrayService.ShowBalloon");
        }
    }

    private static string Truncate(string text, int max)
    {
        if (string.IsNullOrEmpty(text))
            return "";
        return text.Length <= max ? text : text[..max];
    }

    private static IntPtr StockIconToBitmap(uint siid)
    {
        var info = new SHSTOCKICONINFO { cbSize = (uint)Marshal.SizeOf<SHSTOCKICONINFO>() };
        if (SHGetStockIconInfo(siid, ShgsiIcon | ShgsiSmallIcon, ref info) != 0 || info.hIcon == IntPtr.Zero)
            return IntPtr.Zero;

        try
        {
            if (!GetIconInfo(info.hIcon, out var iconInfo))
                return IntPtr.Zero;
            if (iconInfo.hbmMask != IntPtr.Zero)
                DeleteObject(iconInfo.hbmMask);
            if (iconInfo.hbmColor == IntPtr.Zero)
                return IntPtr.Zero;
            var copy = CopyImage(iconInfo.hbmColor, ImageBitmap, 0, 0, 0x00002000);
            DeleteObject(iconInfo.hbmColor);
            return copy;
        }
        finally
        {
            DestroyIcon(info.hIcon);
        }
    }

    private static void DestroyIconSafe(ref IntPtr h)
    {
        if (h == IntPtr.Zero)
            return;
        DestroyIcon(h);
        h = IntPtr.Zero;
    }

    private static void DeleteObjectSafe(ref IntPtr h)
    {
        if (h == IntPtr.Zero)
            return;
        DeleteObject(h);
        h = IntPtr.Zero;
    }

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
        public uint dwState;
        public uint dwStateMask;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 256)]
        public string szInfo;
        public uint uVersion;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 64)]
        public string szInfoTitle;
        public uint dwInfoFlags;
        public Guid guidItem;
        public IntPtr hBalloonIcon;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct MENUITEMINFO
    {
        public uint cbSize;
        public uint fMask;
        public uint fType;
        public uint fState;
        public uint wID;
        public IntPtr hSubMenu;
        public IntPtr hbmpChecked;
        public IntPtr hbmpUnchecked;
        public IntPtr dwItemData;
        [MarshalAs(UnmanagedType.LPWStr)]
        public string dwTypeData;
        public uint cch;
        public IntPtr hbmpItem;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct MENUINFO
    {
        public uint cbSize;
        public uint fMask;
        public uint dwStyle;
        public uint cyMax;
        public IntPtr hbrBack;
        public uint dwContextHelpID;
        public IntPtr dwMenuData;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct SHSTOCKICONINFO
    {
        public uint cbSize;
        public IntPtr hIcon;
        public int iSysImageIndex;
        public int iIcon;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 260)]
        public string szPath;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct ICONINFO
    {
        public bool fIcon;
        public int xHotspot;
        public int yHotspot;
        public IntPtr hbmMask;
        public IntPtr hbmColor;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct POINT
    {
        public int X;
        public int Y;
    }

    [DllImport("shell32.dll", CharSet = CharSet.Unicode)]
    private static extern bool Shell_NotifyIcon(uint dwMessage, ref NOTIFYICONDATA lpData);

    [DllImport("shell32.dll", CharSet = CharSet.Unicode)]
    private static extern int SHGetStockIconInfo(uint siid, uint uFlags, ref SHSTOCKICONINFO psii);

    [DllImport("user32.dll", CharSet = CharSet.Unicode)]
    private static extern IntPtr LoadImage(IntPtr hInst, string name, uint type, int cx, int cy, uint fuLoad);

    [DllImport("user32.dll")]
    private static extern bool DestroyIcon(IntPtr hIcon);

    [DllImport("user32.dll")]
    private static extern bool GetIconInfo(IntPtr hIcon, out ICONINFO piconinfo);

    [DllImport("user32.dll")]
    private static extern IntPtr CopyImage(IntPtr h, uint type, int cx, int cy, uint flags);

    [DllImport("gdi32.dll")]
    private static extern bool DeleteObject(IntPtr ho);

    [DllImport("user32.dll")]
    private static extern IntPtr SetWindowLongPtr(IntPtr hWnd, int nIndex, IntPtr dwNewLong);

    [DllImport("user32.dll")]
    private static extern IntPtr CallWindowProc(IntPtr lpPrevWndFunc, IntPtr hWnd, uint msg, IntPtr wParam, IntPtr lParam);

    [DllImport("user32.dll")]
    private static extern IntPtr CreatePopupMenu();

    [DllImport("user32.dll", CharSet = CharSet.Unicode)]
    private static extern bool InsertMenuItem(IntPtr hMenu, uint item, bool fByPosition, ref MENUITEMINFO lpmii);

    [DllImport("user32.dll")]
    private static extern bool SetMenuInfo(IntPtr hMenu, ref MENUINFO lpcmi);

    [DllImport("user32.dll")]
    private static extern int GetMenuItemCount(IntPtr hMenu);

    [DllImport("user32.dll")]
    private static extern bool DestroyMenu(IntPtr hMenu);

    [DllImport("user32.dll")]
    private static extern bool GetCursorPos(out POINT lpPoint);

    [DllImport("user32.dll")]
    private static extern bool SetForegroundWindow(IntPtr hWnd);

    [DllImport("user32.dll")]
    private static extern int TrackPopupMenu(IntPtr hMenu, uint uFlags, int x, int y, int nReserved, IntPtr hWnd, IntPtr prcRect);
}
