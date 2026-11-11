using System.Globalization;
using System.Xml.Linq;
using DataGateWin.Configuration;
using DataGateWin.CrashReporting;
using Microsoft.UI.Dispatching;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;

namespace DataGateWin.Localization;

/// <summary>
/// WinUI language switcher: in-memory string table + <see cref="Loc.Resolver"/>.
/// Does not mutate process UI culture or Application.MergedDictionaries at runtime
/// (those FailFast unpackaged WinUI with 0x80070490 / 0xC000027B).
/// </summary>
public static class WinUiLanguageService
{
    private static readonly Dictionary<string, string> Strings = new(StringComparer.Ordinal);
    private static readonly object RaiseGate = new();
    private static bool _raiseLanguageChangedQueued;

    public static readonly string[] SupportedCodes = UiLocale.All.Select(l => l.Code).ToArray();

    public static IReadOnlyList<string> GetLanguagePickerCodes() => UiLocale.GetLanguagePickerCodes();

    public const string SystemPreference = "system";

    /// <summary>UI dispatcher used to raise <see cref="LanguageChanged"/> outside ComboBox SelectionChanged.</summary>
    public static DispatcherQueue? UiDispatcher { get; set; }

    public static event EventHandler? LanguageChanged;

    public static void WireLocResolver()
    {
        Loc.Resolver = key =>
        {
            if (Strings.TryGetValue(key, out var s) && !string.IsNullOrEmpty(s))
                return s;

            if (Application.Current?.Resources.TryGetValue(key, out var obj) == true
                && obj is string rs
                && rs.Length > 0)
                return rs;

            return null;
        };
    }

    public static string GetStoredLanguagePreference()
        => NormalizePreferenceForStorage(App.Settings.UiLanguage);

    public static string ResolveEffectiveLanguageCode(string? preference)
    {
        var p = NormalizePreferenceForStorage(preference);
        if (p == SystemPreference)
            return CultureMapping.MapCultureToSupportedCode(CultureInfo.InstalledUICulture);
        return p;
    }

    public static string NormalizePreferenceForStorage(string? languageCode)
    {
        if (string.IsNullOrWhiteSpace(languageCode))
            return SystemPreference;

        var s = languageCode.Trim().ToLowerInvariant();
        if (s is "system" or "auto" or "default" or "os")
            return SystemPreference;

        if (SupportedCodes.Contains(s, StringComparer.OrdinalIgnoreCase))
            return s;

        return SystemPreference;
    }

    public static void ApplyFromSettings()
    {
        Apply(App.Settings.UiLanguage, persist: false);
    }

    public static void Apply(string? languageCode, bool persist)
    {
        Trace("Apply begin persist=" + persist + " code=" + (languageCode ?? "(null)"));
        var preference = persist
            ? NormalizePreferenceForStorage(languageCode)
            : NormalizePreferenceForStorage(App.Settings.UiLanguage);

        if (persist)
        {
            App.Settings.UiLanguage = preference;
            AppSettingsStore.SaveSafe(App.Settings);
            Trace("Apply saved preference=" + preference);
        }

        var effective = ResolveEffectiveLanguageCode(preference);
        Trace("Apply effective=" + effective);

        try
        {
            var loc = UiLocale.FindByCode(effective);
            var ci = loc != null
                ? CultureInfo.GetCultureInfo(loc.CultureName)
                : CultureInfo.GetCultureInfo("en-US");
            // Never assign process DefaultThread* culture fields here.
            // WinUI unpackaged FailFasts (0x80070490 / 0xC000027B) when the process UI culture
            // changes while XamlControlsResources / live trees are loaded.
            Loc.FormatCulture = ci;
        }
        catch (CultureNotFoundException ex)
        {
            CrashReporter.ReportNonFatal(ex, "WinUiLanguageService.ApplyCulture");
            Loc.FormatCulture = CultureInfo.GetCultureInfo("en-US");
        }

        ReloadStringTable(effective);
        Trace("Apply string table reloaded count=" + Strings.Count);
        // Do not add/remove Application.Resources.MergedDictionaries after startup windows exist —
        // that also FailFasts. Loc.Resolver already reads the in-memory Strings table.
        // Defer LanguageChanged so ComboBox SelectionChanged can finish before any Items mutate.
        QueueLanguageChanged();
        Trace("Apply end (LanguageChanged queued)");
    }

    public static bool IsRightToLeft(string? preference = null)
    {
        var code = ResolveEffectiveLanguageCode(preference ?? GetStoredLanguagePreference());
        return code is "ar" or "fa";
    }

    public static void ApplyFlowDirection(FrameworkElement? root)
    {
        if (root is null)
            return;
        var next = IsRightToLeft()
            ? FlowDirection.RightToLeft
            : FlowDirection.LeftToRight;
        if (root.FlowDirection != next)
        {
            Trace("ApplyFlowDirection " + root.FlowDirection + " -> " + next);
            root.FlowDirection = next;
        }

        // LiveCharts/Skia charts break under RTL inheritance — keep them LTR always.
        ForceChartsLeftToRight(root);
    }

    /// <summary>
    /// LiveCharts WinUI canvases render blank/corrupt when an ancestor sets RTL FlowDirection.
    /// </summary>
    public static void ForceChartsLeftToRight(DependencyObject? root)
    {
        if (root is null)
            return;
        try
        {
            WalkForceChartLtr(root);
        }
        catch (Exception ex)
        {
            CrashReporter.ReportNonFatal(ex, "WinUiLanguageService.ForceChartsLeftToRight");
        }
    }

    private static void WalkForceChartLtr(DependencyObject node)
    {
        if (IsLiveChartsOrSkia(node) && node is FrameworkElement fe)
        {
            if (fe.FlowDirection != FlowDirection.LeftToRight)
                fe.FlowDirection = FlowDirection.LeftToRight;
            return;
        }

        switch (node)
        {
            case Panel panel:
                foreach (var child in panel.Children)
                {
                    if (child is DependencyObject d)
                        WalkForceChartLtr(d);
                }
                break;
            case Border border when border.Child is DependencyObject borderChild:
                WalkForceChartLtr(borderChild);
                break;
            case UserControl userControl when userControl.Content is DependencyObject ucContent:
                if (IsLiveChartsOrSkia(userControl))
                {
                    userControl.FlowDirection = FlowDirection.LeftToRight;
                    return;
                }
                WalkForceChartLtr(ucContent);
                break;
            case ContentControl contentControl when contentControl.Content is DependencyObject content:
                WalkForceChartLtr(content);
                break;
            case ContentPresenter presenter when presenter.Content is DependencyObject presented:
                WalkForceChartLtr(presented);
                break;
            case Page page when page.Content is DependencyObject pageContent:
                WalkForceChartLtr(pageContent);
                break;
            case ScrollViewer scroll when scroll.Content is DependencyObject scrollContent:
                WalkForceChartLtr(scrollContent);
                break;
            case Microsoft.UI.Xaml.Controls.Frame frame when frame.Content is DependencyObject frameContent:
                WalkForceChartLtr(frameContent);
                break;
            case NavigationView nav:
                if (nav.Content is DependencyObject navContent)
                    WalkForceChartLtr(navContent);
                break;
        }
    }

    private static bool IsLiveChartsOrSkia(DependencyObject node)
    {
        var asm = node.GetType().Assembly.GetName().Name ?? "";
        return asm.StartsWith("LiveCharts", StringComparison.OrdinalIgnoreCase)
               || asm.StartsWith("SkiaSharp", StringComparison.OrdinalIgnoreCase);
    }

    private static void QueueLanguageChanged()
    {
        lock (RaiseGate)
        {
            if (_raiseLanguageChangedQueued)
                return;
            _raiseLanguageChangedQueued = true;
        }

        var dq = UiDispatcher ?? DispatcherQueue.GetForCurrentThread();
        if (dq is not null && dq.TryEnqueue(DispatcherQueuePriority.Normal, RaiseLanguageChangedSafe))
            return;

        RaiseLanguageChangedSafe();
    }

    private static void RaiseLanguageChangedSafe()
    {
        lock (RaiseGate)
            _raiseLanguageChangedQueued = false;

        Trace("LanguageChanged invoke begin");
        try
        {
            LanguageChanged?.Invoke(null, EventArgs.Empty);
            Trace("LanguageChanged invoke end");
        }
        catch (Exception ex)
        {
            Trace("LanguageChanged invoke EX: " + ex.GetType().Name + " " + ex.Message);
            CrashReporter.ReportNonFatal(ex, "WinUiLanguageService.LanguageChanged");
        }
    }

    private static void Trace(string step)
    {
        try
        {
            var dir = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
                "DataGateWin");
            Directory.CreateDirectory(dir);
            File.AppendAllText(
                Path.Combine(dir, "language-switch.log"),
                DateTime.UtcNow.ToString("o", CultureInfo.InvariantCulture) + " " + step + Environment.NewLine);
        }
        catch
        {
            // never throw from diagnostics
        }
    }

    public static string GetLanguageDisplayName(string code)
    {
        if (string.Equals(code, SystemPreference, StringComparison.OrdinalIgnoreCase))
        {
            if (Strings.TryGetValue("Lang_Name_system", out var sys) && !string.IsNullOrWhiteSpace(sys))
                return sys;
            return "Same as Windows display language";
        }

        var loc = UiLocale.FindByCode(code);
        if (loc is null)
            return code;
        try
        {
            return CultureInfo.GetCultureInfo(loc.CultureName).NativeName;
        }
        catch (CultureNotFoundException ex)
        {
            CrashReporter.ReportNonFatal(ex, "WinUiLanguageService.GetLanguageDisplayName");
            return code;
        }
    }

    private static void ReloadStringTable(string effective)
    {
        Strings.Clear();
        MergeFileIntoTable("en");
        if (!string.Equals(effective, "en", StringComparison.OrdinalIgnoreCase))
            MergeFileIntoTable(effective);
    }

    private static void MergeFileIntoTable(string code)
    {
        try
        {
            var path = Path.Combine(AppContext.BaseDirectory, "Localization", $"Strings.{code}.xaml");
            if (!File.Exists(path))
                return;

            var doc = XDocument.Load(path);
            XNamespace x = "http://schemas.microsoft.com/winfx/2006/xaml";
            foreach (var el in doc.Descendants())
            {
                if (!el.Name.LocalName.Equals("String", StringComparison.Ordinal))
                    continue;
                var key = el.Attribute(x + "Key")?.Value;
                if (string.IsNullOrEmpty(key))
                    continue;
                Strings[key] = el.Value;
            }
        }
        catch (Exception ex)
        {
            CrashReporter.ReportNonFatal(ex, "WinUiLanguageService.MergeFileIntoTable");
        }
    }
}
