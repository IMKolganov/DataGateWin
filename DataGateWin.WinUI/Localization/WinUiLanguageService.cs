using System.Globalization;
using System.Xml.Linq;
using DataGateWin.Configuration;
using DataGateWin.CrashReporting;
using Microsoft.UI.Xaml;

namespace DataGateWin.Localization;

/// <summary>
/// WinUI language switcher: en base + overlay merge into <see cref="Application.Resources"/>,
/// and wires <see cref="Loc.Resolver"/>.
/// </summary>
public static class WinUiLanguageService
{
    private static readonly Dictionary<string, string> Strings = new(StringComparer.Ordinal);
    private static ResourceDictionary? _activeBase;
    private static ResourceDictionary? _activeOverlay;

    public static readonly string[] SupportedCodes = UiLocale.All.Select(l => l.Code).ToArray();

    public static IReadOnlyList<string> GetLanguagePickerCodes() => UiLocale.GetLanguagePickerCodes();

    public const string SystemPreference = "system";

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
            return CultureMapping.MapCultureToSupportedCode(CultureInfo.CurrentUICulture);
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
        var preference = persist
            ? NormalizePreferenceForStorage(languageCode)
            : NormalizePreferenceForStorage(App.Settings.UiLanguage);

        if (persist)
        {
            App.Settings.UiLanguage = preference;
            AppSettingsStore.SaveSafe(App.Settings);
        }

        var effective = ResolveEffectiveLanguageCode(preference);

        try
        {
            var loc = UiLocale.FindByCode(effective);
            var ci = loc != null
                ? CultureInfo.GetCultureInfo(loc.CultureName)
                : CultureInfo.GetCultureInfo("en-US");
            CultureInfo.DefaultThreadCurrentUICulture = ci;
            CultureInfo.DefaultThreadCurrentCulture = ci;
        }
        catch (CultureNotFoundException ex)
        {
            CrashReporter.ReportNonFatal(ex, "WinUiLanguageService.ApplyCulture");
            CultureInfo.DefaultThreadCurrentUICulture = CultureInfo.GetCultureInfo("en-US");
            CultureInfo.DefaultThreadCurrentCulture = CultureInfo.GetCultureInfo("en-US");
        }

        ReloadStringTable(effective);
        MergeResourceDictionaries(effective);
        LanguageChanged?.Invoke(null, EventArgs.Empty);
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

    private static void MergeResourceDictionaries(string effective)
    {
        var app = Application.Current;
        if (app is null)
            return;

        var merged = app.Resources.MergedDictionaries;
        if (_activeOverlay is not null)
        {
            merged.Remove(_activeOverlay);
            _activeOverlay = null;
        }

        if (_activeBase is not null)
        {
            merged.Remove(_activeBase);
            _activeBase = null;
        }

        _activeBase = TryLoadDictionary("en");
        if (_activeBase is not null)
            merged.Add(_activeBase);

        if (!string.Equals(effective, "en", StringComparison.OrdinalIgnoreCase))
        {
            _activeOverlay = TryLoadDictionary(effective);
            if (_activeOverlay is not null)
                merged.Add(_activeOverlay);
        }
    }

    private static ResourceDictionary? TryLoadDictionary(string code)
    {
        try
        {
            var path = Path.Combine(AppContext.BaseDirectory, "Localization", $"Strings.{code}.xaml");
            if (!File.Exists(path))
                return null;

            var dict = new ResourceDictionary();
            var fileOnly = new Dictionary<string, string>(StringComparer.Ordinal);
            var doc = XDocument.Load(path);
            XNamespace x = "http://schemas.microsoft.com/winfx/2006/xaml";
            foreach (var el in doc.Descendants())
            {
                if (!el.Name.LocalName.Equals("String", StringComparison.Ordinal))
                    continue;
                var key = el.Attribute(x + "Key")?.Value;
                if (string.IsNullOrEmpty(key))
                    continue;
                fileOnly[key] = el.Value;
            }

            foreach (var kv in fileOnly)
                dict[kv.Key] = kv.Value;

            return dict;
        }
        catch (Exception ex)
        {
            CrashReporter.ReportNonFatal(ex, "WinUiLanguageService.TryLoadDictionary");
            return null;
        }
    }
}
