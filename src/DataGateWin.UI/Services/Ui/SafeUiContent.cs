using DataGateWin.CrashReporting;

namespace DataGateWin.Services.Ui;

/// <summary>
/// Single entry for building Frame content. Every main-nav page must be created through here
/// so construction failures become a visible error panel instead of killing the shell.
/// </summary>
public static class SafeUiContent
{
    public static T GetOrCreate<T>(ref T? cache, Func<T> factory, string context)
        where T : class
    {
        if (cache is not null)
            return cache;

        try
        {
            cache = factory() ?? throw new InvalidOperationException(context + " factory returned null.");
            return cache;
        }
        catch (Exception ex)
        {
            CrashReporter.ReportNonFatal(ex, context + ".GetOrCreate");
            throw;
        }
    }

    /// <summary>
    /// Create content for the nav frame. On any managed failure returns <see cref="UiErrorPanel"/>.
    /// Callers must assign the result to the Frame — never swallow and leave the previous page
    /// without feedback when the user explicitly navigated.
    /// </summary>
    public static Microsoft.UI.Xaml.UIElement Create(
        Func<Microsoft.UI.Xaml.UIElement> factory,
        string context)
    {
        try
        {
            return factory()
                   ?? UiErrorPanel.Create(context, new InvalidOperationException("UI factory returned null."));
        }
        catch (Exception ex)
        {
            return UiErrorPanel.FromException(context, ex);
        }
    }
}
