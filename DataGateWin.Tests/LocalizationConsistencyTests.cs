using System.Xml.Linq;
using Xunit;

namespace DataGateWin.Tests;

public sealed class LocalizationConsistencyTests
{
    [Fact]
    public void LocalizationFiles_NoDuplicateKeysInAnyFile()
    {
        var files = GetLocalizationFiles();
        Assert.NotEmpty(files);

        foreach (var file in files)
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
                $"Duplicate localization keys in '{Path.GetFileName(file)}': {string.Join(", ", duplicates)}");
        }
    }

    [Fact]
    public void LocalizationFiles_AllContainKeysFromEnglishBase()
    {
        var files = GetLocalizationFiles();
        var english = files.FirstOrDefault(f =>
            string.Equals(Path.GetFileName(f), "Strings.en.xaml", StringComparison.OrdinalIgnoreCase));

        Assert.False(string.IsNullOrWhiteSpace(english), "Base localization file 'Strings.en.xaml' was not found.");

        var englishKeys = new HashSet<string>(ReadKeys(english!), StringComparer.Ordinal);
        Assert.NotEmpty(englishKeys);

        var missingReport = new List<string>();
        foreach (var file in files.Where(f => !string.Equals(f, english, StringComparison.OrdinalIgnoreCase)))
        {
            var currentKeys = new HashSet<string>(ReadKeys(file), StringComparer.Ordinal);
            var missing = englishKeys
                .Where(k => !currentKeys.Contains(k))
                .OrderBy(k => k, StringComparer.Ordinal)
                .ToList();

            if (missing.Count == 0)
                continue;

            missingReport.Add(
                $"{Path.GetFileName(file)} missing {missing.Count} keys: {string.Join(", ", missing)}");
        }

        Assert.True(
            missingReport.Count == 0,
            "Localization keys are missing:\n" + string.Join('\n', missingReport));
    }

    private static List<string> GetLocalizationFiles()
    {
        var repoRoot = FindRepoRoot();
        var locDir = Path.Combine(repoRoot, "DataGateWin.UI", "Localization");
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
            var sln = Path.Combine(dir.FullName, "DataGateWin.sln");
            if (File.Exists(sln))
                return dir.FullName;

            dir = dir.Parent;
        }

        throw new DirectoryNotFoundException("Could not locate repository root (DataGateWin.sln).");
    }
}
