using System.Xml.Linq;
using DataGateWin.Localization;
using Xunit;

namespace DataGateWin.Tests;

/// <summary>
/// WinUI overlay locales must stay in sync with <c>Strings.en.xaml</c> (runtime merges en + overlay).
/// </summary>
public sealed class WinUiLocalizationConsistencyTests
{
    private static readonly string[] ChromeKeys =
        ["Nav_Home", "Nav_Settings", "Settings_Title", "Home_Connect", "Login_SignInGoogle"];

    private static readonly string[] ChromeLocales =
        ["de", "fr", "ja", "ko", "pl", "ru", "tr", "uk", "zh-hans", "zh-hant"];

    [Fact]
    public void WinUiLocalizationFiles_CoverEveryUiLocale()
    {
        var files = GetWinUiLocalizationFiles();
        var names = files
            .Select(f => Path.GetFileName(f)!)
            .ToHashSet(StringComparer.OrdinalIgnoreCase);

        Assert.Contains("Strings.en.xaml", names);
        foreach (var loc in UiLocale.All)
        {
            Assert.True(
                names.Contains($"Strings.{loc.Code}.xaml"),
                $"Missing WinUI locale file Strings.{loc.Code}.xaml");
        }
    }

    [Fact]
    public void WinUiLocalizationFiles_NoDuplicateKeys()
    {
        foreach (var file in GetWinUiLocalizationFiles())
        {
            var keys = ReadKeys(file);
            var duplicates = keys
                .GroupBy(k => k, StringComparer.Ordinal)
                .Where(g => g.Count() > 1)
                .Select(g => g.Key)
                .OrderBy(k => k, StringComparer.Ordinal)
                .ToList();

            Assert.True(
                duplicates.Count == 0,
                $"Duplicate keys in '{Path.GetFileName(file)}': {string.Join(", ", duplicates)}");
        }
    }

    [Fact]
    public void WinUiLocalizationFiles_AllContainEnglishKeys()
    {
        var files = GetWinUiLocalizationFiles();
        var english = files.First(f =>
            string.Equals(Path.GetFileName(f), "Strings.en.xaml", StringComparison.OrdinalIgnoreCase));
        var englishKeys = new HashSet<string>(ReadKeys(english), StringComparer.Ordinal);

        Assert.Contains("Nav_Import", englishKeys);
        Assert.Contains("Import_Title", englishKeys);

        var missingReport = new List<string>();
        foreach (var file in files.Where(f => !string.Equals(f, english, StringComparison.OrdinalIgnoreCase)))
        {
            var current = new HashSet<string>(ReadKeys(file), StringComparer.Ordinal);
            var missing = englishKeys
                .Where(k => !current.Contains(k))
                .OrderBy(k => k, StringComparer.Ordinal)
                .ToList();
            if (missing.Count > 0)
            {
                missingReport.Add(
                    $"{Path.GetFileName(file)} missing {missing.Count}: {string.Join(", ", missing.Take(12))}" +
                    (missing.Count > 12 ? "…" : ""));
            }
        }

        Assert.True(missingReport.Count == 0, string.Join('\n', missingReport));
    }

    [Fact]
    public void WinUiLocalizationFiles_NoDoubleEscapedAmpersands()
    {
        foreach (var file in GetWinUiLocalizationFiles())
        {
            var text = File.ReadAllText(file);
            Assert.DoesNotContain("&amp;amp;", text, StringComparison.Ordinal);
        }
    }

    [Fact]
    public void WinUiLocalizationFiles_PrimaryLocalesTranslateChrome()
    {
        var locDir = Path.Combine(FindRepoRoot(), "DataGateWin.WinUI", "Localization");
        var english = ReadMap(Path.Combine(locDir, "Strings.en.xaml"));

        var failures = new List<string>();
        foreach (var code in ChromeLocales)
        {
            var map = ReadMap(Path.Combine(locDir, $"Strings.{code}.xaml"));
            foreach (var key in ChromeKeys)
            {
                if (!english.TryGetValue(key, out var en) || !map.TryGetValue(key, out var val))
                {
                    failures.Add($"{code}: missing {key}");
                    continue;
                }

                if (string.Equals(val, en, StringComparison.Ordinal))
                    failures.Add($"{code}: {key} is still English ({en})");
            }
        }

        Assert.True(failures.Count == 0, string.Join('\n', failures));
    }

    [Fact]
    public void WinUiLocalizationFiles_Home_Error_UiImage_IsNotLeftInEnglish()
    {
        var locDir = Path.Combine(FindRepoRoot(), "DataGateWin.WinUI", "Localization");
        var english = ReadMap(Path.Combine(locDir, "Strings.en.xaml"));
        Assert.True(english.TryGetValue("Home_Error_UiImage", out var en) && !string.IsNullOrWhiteSpace(en));

        var failures = new List<string>();
        foreach (var file in GetWinUiLocalizationFiles())
        {
            var name = Path.GetFileName(file)!;
            if (string.Equals(name, "Strings.en.xaml", StringComparison.OrdinalIgnoreCase))
                continue;

            var map = ReadMap(file);
            if (!map.TryGetValue("Home_Error_UiImage", out var val) || string.IsNullOrWhiteSpace(val))
            {
                failures.Add($"{name}: missing Home_Error_UiImage");
                continue;
            }

            if (string.Equals(val, en, StringComparison.Ordinal))
                failures.Add($"{name}: Home_Error_UiImage is still English");
        }

        Assert.True(failures.Count == 0, string.Join('\n', failures));
    }

    private static List<string> GetWinUiLocalizationFiles()
    {
        var locDir = Path.Combine(FindRepoRoot(), "DataGateWin.WinUI", "Localization");
        return Directory
            .EnumerateFiles(locDir, "Strings.*.xaml", SearchOption.TopDirectoryOnly)
            .OrderBy(Path.GetFileName, StringComparer.OrdinalIgnoreCase)
            .ToList();
    }

    private static Dictionary<string, string> ReadMap(string path)
    {
        var doc = XDocument.Load(path);
        var xNamespace = XNamespace.Get("http://schemas.microsoft.com/winfx/2006/xaml");
        return doc
            .Descendants()
            .Select(e => (
                Key: e.Attribute(xNamespace + "Key")?.Value,
                Value: (e.Value ?? "").Trim()))
            .Where(x => !string.IsNullOrWhiteSpace(x.Key))
            .ToDictionary(x => x.Key!, x => x.Value, StringComparer.Ordinal);
    }

    private static List<string> ReadKeys(string path) => ReadMap(path).Keys.ToList();

    private static string FindRepoRoot()
    {
        var dir = new DirectoryInfo(AppContext.BaseDirectory);
        while (dir is not null)
        {
            if (File.Exists(Path.Combine(dir.FullName, "DataGateWin.sln")))
                return dir.FullName;
            dir = dir.Parent;
        }

        throw new DirectoryNotFoundException("repo root");
    }
}
