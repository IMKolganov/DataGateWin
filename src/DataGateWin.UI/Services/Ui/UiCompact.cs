using Microsoft.UI.Dispatching;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Media;

namespace DataGateWin.Services.Ui;

/// <summary>
/// One place for control density: every button, combo box, text box and date picker gets the same
/// height and font size. Default WinUI templates drive their height from padding, so we set Height
/// explicitly. Applied at runtime (not via implicit styles) because App.xaml cannot BasedOn the
/// theme styles in unpackaged WinUI. Controls tagged "hero" (the main action) are left alone.
/// </summary>
internal static class UiCompact
{
    public const double ControlHeight = 28;
    public const double ControlFontSize = 13;

    private static readonly System.Runtime.CompilerServices.ConditionalWeakTable<Expander, object> HookedExpanders = new();

    /// <summary>Applies compact sizing once the element is in the visual tree.</summary>
    public static void Attach(FrameworkElement? page)
    {
        if (page is null)
            return;

        if (page.IsLoaded)
        {
            Apply(page);
            return;
        }

        RoutedEventHandler? handler = null;
        handler = (_, _) =>
        {
            page.Loaded -= handler;
            Apply(page);
        };
        page.Loaded += handler;
    }

    public static void Apply(DependencyObject root)
    {
        try
        {
            Walk(root);
        }
        catch
        {
            // Cosmetic only; never let density tweaks break a page.
        }
    }

    private static void Walk(DependencyObject node)
    {
        switch (node)
        {
            case Button { Tag: "hero" }:
                return;
            case ComboBox c:
                Fix(c, new Thickness(10, 0, 0, 0));
                return;
            case TextBox t:
                if (t.AcceptsReturn)
                    return;
                Fix(t, new Thickness(8, 0, 8, 0));
                return;
            case CalendarDatePicker d:
                d.FontSize = ControlFontSize;
                d.Height = ControlHeight;
                d.MinHeight = ControlHeight;
                return;
            case Button b:
                Fix(b, new Thickness(12, 0, 12, 0));
                return;
            case ToggleSwitch:
            case ProgressBar:
            case ProgressRing:
            case ListViewBase:
                return;
            case Expander e:
                HookExpander(e);
                break;
        }

        var count = VisualTreeHelper.GetChildrenCount(node);
        for (var i = 0; i < count; i++)
            Walk(VisualTreeHelper.GetChild(node, i));
    }

    private static void HookExpander(Expander e)
    {
        if (HookedExpanders.TryGetValue(e, out _))
            return;
        HookedExpanders.Add(e, new object());
        // Collapsed content is not in the visual tree yet; size it once it has been created.
        e.Expanding += (_, _) =>
            e.DispatcherQueue.TryEnqueue(DispatcherQueuePriority.Low, () => Apply(e));
    }

    private static void Fix(Control c, Thickness padding)
    {
        c.FontSize = ControlFontSize;
        c.Height = ControlHeight;
        c.MinHeight = ControlHeight;
        c.Padding = padding;
        c.VerticalContentAlignment = VerticalAlignment.Center;
    }
}
