using DataGateWin.CrashReporting;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Media;

namespace DataGateWin.Services.Ui;

/// <summary>
/// Assigning a bad <see cref="Image.Source"/> can FailFast WinUI. Never throw to the caller:
/// clear the control and let the page log a user-visible error.
/// </summary>
internal static class UiSafeImage
{
    public static bool TryAssign(Image target, ImageSource? source, string tag)
    {
        ArgumentNullException.ThrowIfNull(target);
        try
        {
            // Clear first so a previous shared/broken source cannot FailFast on replace.
            target.Source = null;
            if (source is null)
            {
                target.Visibility = Visibility.Collapsed;
                return true;
            }

            target.Source = source;
            target.Visibility = Visibility.Visible;
            return true;
        }
        catch (Exception ex)
        {
            CrashReporter.ReportNonFatal(ex, tag);
            try
            {
                target.Source = null;
                target.Visibility = Visibility.Collapsed;
            }
            catch
            {
                // ignore — never rethrow into WinUI dispatcher (0xc000027b)
            }

            return false;
        }
    }

    public static bool TryAssignBrush(ImageBrush target, ImageSource? source, string tag)
    {
        ArgumentNullException.ThrowIfNull(target);
        try
        {
            target.ImageSource = source;
            return source is not null;
        }
        catch (Exception ex)
        {
            CrashReporter.ReportNonFatal(ex, tag);
            try { target.ImageSource = null; }
            catch { /* ignore */ }
            return false;
        }
    }
}
