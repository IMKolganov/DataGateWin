using Xunit;

namespace DataGateWin.Tests;

public sealed class XrayLocalizationContractTests
{
    [Theory]
    [InlineData("Strings.en.xaml")]
    [InlineData("Strings.ru.xaml")]
    public void PrimaryLocales_ContainXrayUnlockKeys(string fileName)
    {
        var path = FindRepoFile(Path.Combine("DataGateWin.WinUI", "Localization", fileName));
        var text = File.ReadAllText(path);
        Assert.Contains("x:Key=\"Import_Hint_Xray\"", text, StringComparison.Ordinal);
        Assert.Contains("x:Key=\"Import_PastePlaceholder_Xray\"", text, StringComparison.Ordinal);
        Assert.Contains("x:Key=\"Import_Validate_no_xray_share\"", text, StringComparison.Ordinal);
    }

    [Fact]
    public void EnglishAndRussian_XrayHints_AreNonEmpty()
    {
        var en = File.ReadAllText(FindRepoFile(Path.Combine("DataGateWin.WinUI", "Localization", "Strings.en.xaml")));
        var ru = File.ReadAllText(FindRepoFile(Path.Combine("DataGateWin.WinUI", "Localization", "Strings.ru.xaml")));

        Assert.Contains("share link", en, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("share-link", ru, StringComparison.OrdinalIgnoreCase);
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

    private static string FindRepoFile(string relative)
    {
        var candidate = Path.Combine(FindRepoRoot(), relative);
        if (!File.Exists(candidate))
            throw new FileNotFoundException(relative);
        return candidate;
    }
}
