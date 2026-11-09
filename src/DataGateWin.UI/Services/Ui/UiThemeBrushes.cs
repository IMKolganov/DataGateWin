using DataGateWin.CrashReporting;
using Microsoft.UI;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Media;

namespace DataGateWin.Services.Ui;

/// <summary>
/// Theme brushes for unpackaged WinUI. Never resolve via ThemeResource markup —
/// a missing WinUI theme key FailFasts the process (0xc000027b). Lookup Application.Resources
/// and always fall back to a solid color so UI can degrade instead of dying.
/// </summary>
public static class UiThemeBrushes
{
    public const string CardBackgroundKey = "CardBackgroundFillColorDefaultBrush";
    public const string CardStrokeKey = "ControlStrokeColorDefaultBrush";
    public const string CautionForegroundKey = "SystemFillColorCautionBrush";
    public const string SecondaryFillKey = "ControlFillColorSecondaryBrush";

    public static Brush CardBackground()
        => TryGet(CardBackgroundKey) ?? FallbackCard();

    public static Brush CardStroke()
        => TryGet(CardStrokeKey) ?? FallbackStroke();

    public static Brush CautionForeground()
        => TryGet(CautionForegroundKey) ?? FallbackCaution();

    public static Brush SecondaryFill()
        => TryGet(SecondaryFillKey) ?? FallbackCard();

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

    public static void ApplyCardBackground(FrameworkElement? target)
    {
        if (target is null)
            return;
        try
        {
            if (target is Border border)
                border.Background = CardBackground();
            else if (target is Panel panel)
                panel.Background = CardBackground();
            else if (target is Control control)
                control.Background = CardBackground();
        }
        catch (Exception ex)
        {
            CrashReporter.ReportNonFatal(ex, "UiThemeBrushes.ApplyCardBackground");
        }
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
            var card = CardBackground();
            var stroke = CardStroke();
            WalkLogical(root, fe =>
            {
                if (fe is not Border border)
                    return;

                if (border.Background is null)
                    border.Background = card;

                if (border.BorderThickness.Left > 0 ||
                    border.BorderThickness.Top > 0 ||
                    border.BorderThickness.Right > 0 ||
                    border.BorderThickness.Bottom > 0)
                {
                    if (border.BorderBrush is null)
                        border.BorderBrush = stroke;
                }
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
