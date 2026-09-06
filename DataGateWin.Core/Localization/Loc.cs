using System.Globalization;
using DataGateWin.CrashReporting;

namespace DataGateWin.Localization;

/// <summary>
/// Shared string lookup. Hosts wire <see cref="Resolver"/> (WPF ResourceDictionary / WinUI resources).
/// </summary>
public static class Loc
{
    /// <summary>Optional lookup (e.g. WPF/WinUI resources). When null/empty, <see cref="T(string)"/> returns the key.</summary>
    public static Func<string, string?>? Resolver { get; set; }

    public static string T(string key)
    {
        var s = Resolver?.Invoke(key);
        if (!string.IsNullOrEmpty(s))
            return s;
        return key;
    }

    public static string T(string key, params object?[] args)
    {
        var template = T(key);
        if (args is null || args.Length == 0)
            return template;
        try
        {
            return string.Format(CultureInfo.CurrentUICulture, template, args);
        }
        catch (FormatException ex)
        {
            CrashReporter.ReportNonFatal(ex, "Loc.Format");
            return template;
        }
    }
}
