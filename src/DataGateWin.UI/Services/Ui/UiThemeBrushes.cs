using System.Runtime.CompilerServices;
using DataGateWin.CrashReporting;
using Microsoft.UI;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Media;

namespace DataGateWin.Services.Ui;

/// <summary>
/// Theme brushes for unpackaged WinUI. Never resolve via ThemeResource markup —
/// a missing WinUI theme key FailFasts the process (0xc000027b). Lookup Application.Resources
/// for optional resources. Card colors follow each element’s runtime theme.
/// </summary>
public static class UiThemeBrushes
{
    public const string CardBackgroundKey = "CardBackgroundFillColorDefaultBrush";
    public const string CardStrokeKey = "ControlStrokeColorDefaultBrush";
    public const string CautionForegroundKey = "SystemFillColorCautionBrush";
    public const string SecondaryFillKey = "ControlFillColorSecondaryBrush";

    public static Brush CardBackground()
        => CardBackground(App.ResolveElementTheme());

    private static Brush CardBackground(ElementTheme theme)
        => new SolidColorBrush(theme == ElementTheme.Dark
            ? ColorHelper.FromArgb(255, 45, 45, 45)
            : ColorHelper.FromArgb(255, 255, 255, 255));

    public static Brush CardStroke()
        => CardStroke(App.ResolveElementTheme());

    public static Brush CautionForeground()
        => TryGet(CautionForegroundKey) ?? FallbackCaution();

    public static Brush SecondaryFill()
        => new SolidColorBrush(App.ResolveElementTheme() == ElementTheme.Dark
            ? ColorHelper.FromArgb(255, 50, 50, 50)
            : ColorHelper.FromArgb(255, 245, 245, 245));

    public static Brush? TryGet(string key)
    {
        if (string.IsNullOrWhiteSpace(key))
            return null;

        try
        {
            var res = Application.Current?.Resources;
            if (res is not null &&
                res.TryGetValue(key, out var value) &&
                value is Brush brush)
            {
                return brush;
            }
        }
        catch (Exception ex)
        {
            CrashReporter.ReportNonFatal(ex, "UiThemeBrushes.TryGet:" + key);
        }

        return null;
    }

    private sealed class ManagedChrome
    {
        public bool Background;
        public bool Stroke;
    }

    private static readonly ConditionalWeakTable<FrameworkElement, ManagedChrome> Managed = new();
    private static readonly List<(WeakReference<FrameworkElement> Target, ManagedChrome Chrome)> Targets = new();

    public static void RefreshTheme(ElementTheme theme)
    {
        for (var i = Targets.Count - 1; i >= 0; i--)
        {
            if (Targets[i].Target.TryGetTarget(out var target))
                RefreshChrome(target, Targets[i].Chrome, theme);
            else
                Targets.RemoveAt(i);
        }
    }

    private static Brush CardStroke(ElementTheme theme)
        => new SolidColorBrush(theme == ElementTheme.Dark
            ? ColorHelper.FromArgb(255, 65, 65, 65)
            : ColorHelper.FromArgb(255, 225, 225, 225));

    public static void ApplyCardBackground(FrameworkElement? target)
    {
        if (target is not null)
            ManageChrome(target, background: true, stroke: false);
    }

    private static void ManageChrome(FrameworkElement target, bool background, bool stroke)
    {
        if (!Managed.TryGetValue(target, out var state))
        {
            state = new ManagedChrome();
            Managed.Add(target, state);
            Targets.Add((new WeakReference<FrameworkElement>(target), state));
            var chrome = state;
            target.ActualThemeChanged += (_, _) => RefreshChrome(target, chrome);
            target.Loaded += (_, _) => RefreshChrome(target, chrome);
        }
        state.Background |= background;
        state.Stroke |= stroke;
        RefreshChrome(target, state);
    }

    private static void RefreshChrome(FrameworkElement target, ManagedChrome state, ElementTheme? requestedTheme = null)
    {
        var theme = requestedTheme ?? target.ActualTheme;
        if (state.Background)
        {
            var brush = CardBackground(theme);
            if (target is Border border) border.Background = brush;
            else if (target is Panel panel) panel.Background = brush;
            else if (target is Control control) control.Background = brush;
        }
        if (state.Stroke && target is Border outlined)
            outlined.BorderBrush = CardStroke(theme);
    }

    /// <summary>
    /// Paint card-looking Borders under <paramref name="root"/> that have no Background set
    /// (after ThemeResource was removed from XAML to avoid FailFast).
    /// Walks the logical tree so it works right after InitializeComponent, before Loaded.
    /// </summary>
    public static void ApplyMissingCardChrome(DependencyObject? root)
    {
        if (root is null)
            return;

        try
        {
            WalkLogical(root, fe =>
            {
                if (fe is not Border border)
                    return;

                var background = border.Background is null;
                var stroke = border.BorderBrush is null &&
                    (border.BorderThickness.Left > 0 || border.BorderThickness.Top > 0 ||
                     border.BorderThickness.Right > 0 || border.BorderThickness.Bottom > 0);
                if (background || stroke)
                    ManageChrome(border, background, stroke);
            });
        }
        catch (Exception ex)
        {
            CrashReporter.ReportNonFatal(ex, "UiThemeBrushes.ApplyMissingCardChrome");
        }
    }

    static void WalkLogical(DependencyObject node, Action<FrameworkElement> onElement)
    {
        // Never enter LiveCharts / SkiaSharp subtrees: painting their Borders covers the canvas.
        if (IsChartOrSkiaSubtree(node))
            return;

        if (node is FrameworkElement fe)
            onElement(fe);

        switch (node)
        {
            case Panel panel:
                foreach (var child in panel.Children)
                {
                    if (child is DependencyObject d)
                        WalkLogical(d, onElement);
                }
                break;
            case Border border when border.Child is DependencyObject borderChild:
                WalkLogical(borderChild, onElement);
                break;
            // UserControl before ContentControl — UserControl is a ContentControl.
            case UserControl userControl when userControl.Content is DependencyObject ucContent:
                WalkLogical(ucContent, onElement);
                break;
            case ContentControl contentControl when contentControl.Content is DependencyObject content:
                WalkLogical(content, onElement);
                break;
            case ContentPresenter presenter when presenter.Content is DependencyObject presented:
                WalkLogical(presented, onElement);
                break;
            case ItemsControl itemsControl:
                foreach (var item in itemsControl.Items)
                {
                    if (item is DependencyObject d)
                        WalkLogical(d, onElement);
                }
                break;
            case Page page when page.Content is DependencyObject pageContent:
                WalkLogical(pageContent, onElement);
                break;
            case ScrollViewer scroll when scroll.Content is DependencyObject scrollContent:
                WalkLogical(scrollContent, onElement);
                break;
            case Viewbox viewbox when viewbox.Child is DependencyObject viewboxChild:
                WalkLogical(viewboxChild, onElement);
                break;
        }
    }

    static bool IsChartOrSkiaSubtree(DependencyObject node)
    {
        var asm = node.GetType().Assembly.GetName().Name ?? "";
        return asm.StartsWith("LiveCharts", StringComparison.OrdinalIgnoreCase)
               || asm.StartsWith("SkiaSharp", StringComparison.OrdinalIgnoreCase);
    }

    static Brush FallbackCard()
        => new SolidColorBrush(ColorHelper.FromArgb(0x28, 0x80, 0x80, 0x80));

    static Brush FallbackStroke()
        => new SolidColorBrush(ColorHelper.FromArgb(0x40, 0x80, 0x80, 0x80));

    static Brush FallbackCaution()
        => new SolidColorBrush(ColorHelper.FromArgb(0xFF, 0xC4, 0x8C, 0x2B));
}
