using System.Xml.Linq;
using Xunit;

namespace DataGateWin.Tests;

/// <summary>
/// WinUI overlay locales must stay in sync with <c>Strings.en.xaml</c> (runtime merges en + overlay).
/// </summary>
public sealed class WinUiLocalizationConsistencyTests
{
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

    private static List<string> GetWinUiLocalizationFiles()
    {
        var locDir = Path.Combine(FindRepoRoot(), "DataGateWin.WinUI", "Localization");
        return Directory
            .EnumerateFiles(locDir, "Strings.*.xaml", SearchOption.TopDirectoryOnly)
            .OrderBy(Path.GetFileName, StringComparer.OrdinalIgnoreCase)
            .ToList();
    }

    private static List<string> ReadKeys(string path)
    {
        var doc = XDocument.Load(path);
        var xNamespace = XNamespace.Get("http://schemas.microsoft.com/winfx/2006/xaml");
        return doc
            .Descendants()
            .Select(e => e.Attribute(xNamespace + "Key")?.Value)
            .Where(v => !string.IsNullOrWhiteSpace(v))
            .Select(v => v!)
            .ToList();
    }

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
