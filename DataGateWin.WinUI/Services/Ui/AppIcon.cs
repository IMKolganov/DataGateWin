using System.Runtime.InteropServices;
using Microsoft.UI.Windowing;
using Microsoft.UI.Xaml;
using WinRT.Interop;

namespace DataGateWin.Services.Ui;

/// <summary>
/// Taskbar / title-bar icon for unpackaged WinUI. Prefers the shield favicon (same as WPF),
/// not Assets/AppIcon.ico (different mark that reads as “blank” on a dark taskbar).
/// </summary>
internal static class AppIcon
{
    public const string AppUserModelId = "IMKolganov.DataGate";

    private const int ImageIcon = 1;
    private const uint LrLoadFromFile = 0x0010;
    private const int IconSmall = 0;
    private const int IconBig = 1;
    private const uint WmSetIcon = 0x0080;
    private const int SmCxIcon = 11;
    private const int SmCyIcon = 12;
    private const int SmCxSmIcon = 49;
    private const int SmCySmIcon = 50;

    public static void SetProcessAppUserModelId()
    {
        try
        {
            _ = SetCurrentProcessExplicitAppUserModelID(AppUserModelId);
        }
        catch
        {
            /* best-effort */
        }
    }

    public static string? ResolveIconPath()
    {
        var baseDir = AppContext.BaseDirectory;
        foreach (var relative in new[]
                 {
                     Path.Combine("Images", "favicon.ico"),
                     Path.Combine("Assets", "favicon.ico"),
                     Path.Combine("Assets", "AppIcon.ico"),
                 })
        {
            var full = Path.Combine(baseDir, relative);
            if (File.Exists(full))
                return full;
        }

        return null;
    }

    public static void ApplyToWindow(Window window)
    {
        var path = ResolveIconPath();
        if (path is null)
            return;

        try
        {
            window.AppWindow.SetIcon(path);
        }
        catch
        {
            /* continue with Win32 */
        }

        try
        {
            var hwnd = WindowNative.GetWindowHandle(window);
            ApplyWin32Icons(hwnd, path);
        }
        catch
        {
            /* best-effort */
        }
    }

    /// <summary>Re-apply after Activate — WinUI sometimes resets the window icon.</summary>
    public static void ApplyToWindow(AppWindow appWindow, IntPtr hwnd)
    {
        var path = ResolveIconPath();
        if (path is null)
            return;

        try
        {
            appWindow.SetIcon(path);
        }
        catch { /* ignore */ }

        ApplyWin32Icons(hwnd, path);
    }

    private static void ApplyWin32Icons(IntPtr hwnd, string iconPath)
    {
        if (hwnd == IntPtr.Zero || string.IsNullOrWhiteSpace(iconPath))
            return;

        var big = LoadImage(
            IntPtr.Zero,
            iconPath,
            ImageIcon,
            GetSystemMetrics(SmCxIcon),
            GetSystemMetrics(SmCyIcon),
            LrLoadFromFile);
        var small = LoadImage(
            IntPtr.Zero,
            iconPath,
            ImageIcon,
            GetSystemMetrics(SmCxSmIcon),
            GetSystemMetrics(SmCySmIcon),
            LrLoadFromFile);

        if (big != IntPtr.Zero)
            _ = SendMessage(hwnd, WmSetIcon, (IntPtr)IconBig, big);
        if (small != IntPtr.Zero)
            _ = SendMessage(hwnd, WmSetIcon, (IntPtr)IconSmall, small);
    }

    [DllImport("shell32.dll", CharSet = CharSet.Unicode)]
    private static extern int SetCurrentProcessExplicitAppUserModelID(string appID);

    [DllImport("user32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern IntPtr LoadImage(IntPtr hInst, string name, int type, int cx, int cy, uint fuLoad);

    [DllImport("user32.dll")]
    private static extern int GetSystemMetrics(int nIndex);

    [DllImport("user32.dll")]
    private static extern IntPtr SendMessage(IntPtr hWnd, uint msg, IntPtr wParam, IntPtr lParam);
}
