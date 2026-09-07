using Xunit;

namespace DataGateWin.Tests;

public sealed class XrayLocalizationContractTests
{
    [Theory]
    [InlineData("Strings.en.xaml")]
    [InlineData("Strings.ru.xaml")]
    public void PrimaryLocales_ContainXrayLockKeys(string fileName)
    {
        var path = FindRepoFile(Path.Combine("DataGateWin.WinUI", "Localization", fileName));
        var text = File.ReadAllText(path);
        Assert.Contains("x:Key=\"Import_XrayComingSoon\"", text, StringComparison.Ordinal);
        Assert.Contains("x:Key=\"Import_Log_XrayNotReady\"", text, StringComparison.Ordinal);
    }

    [Fact]
    public void EnglishAndRussian_XrayKeys_AreNonEmpty()
    {
        var en = File.ReadAllText(FindRepoFile(Path.Combine("DataGateWin.WinUI", "Localization", "Strings.en.xaml")));
        var ru = File.ReadAllText(FindRepoFile(Path.Combine("DataGateWin.WinUI", "Localization", "Strings.ru.xaml")));

        Assert.Contains("not available on Windows yet", en, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("недоступны", ru, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("not supported yet", en, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("не поддерживается", ru, StringComparison.OrdinalIgnoreCase);
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
