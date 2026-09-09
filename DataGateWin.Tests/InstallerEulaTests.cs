using System.Xml.Linq;
using DataGateWin.Localization;
using Xunit;

namespace DataGateWin.Tests;

public sealed class InstallerEulaTests
{
    [Fact]
    public void EnglishEula_IsAFullAgreement_NotAStub()
    {
        var body = ReadInstallerString("InstallerExtras.en.xaml", "Install_PolicyBody");
        var accept = ReadInstallerString("InstallerExtras.en.xaml", "Install_AcceptPolicy");

        Assert.DoesNotContain("software policy", body, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("I accept the policy", accept, StringComparison.OrdinalIgnoreCase);
        Assert.True(body.Length >= 2000, $"EULA too short: {body.Length}");
        Assert.Contains("End User License Agreement", body, StringComparison.Ordinal);
        Assert.Contains("https://datagateapp.com", body, StringComparison.Ordinal);
        Assert.Contains("https://github.com/IMKolganov/DataGateWin", body, StringComparison.Ordinal);
        Assert.Contains("GNU GPL", body, StringComparison.Ordinal);
        Assert.Contains("AS IS", body, StringComparison.Ordinal);
        Assert.Contains("Acceptable use", body, StringComparison.Ordinal);
        Assert.Contains("No warranty", body, StringComparison.Ordinal);
        Assert.Contains("Limitation of liability", body, StringComparison.Ordinal);
        Assert.Contains("minors", body, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("parental-control", body, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("not liable", body, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("I accept the license agreement", accept, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void RussianEula_IsTranslated_NotLeftInEnglish()
    {
        var body = ReadInstallerString("InstallerExtras.ru.xaml", "Install_PolicyBody");
        var accept = ReadInstallerString("InstallerExtras.ru.xaml", "Install_AcceptPolicy");
        var title = ReadInstallerString("InstallerExtras.ru.xaml", "Install_LicenseTitle");
        var english = ReadInstallerString("InstallerExtras.en.xaml", "Install_PolicyBody");

        Assert.NotEqual(english, body);
        Assert.True(body.Length >= 2000, $"Russian EULA too short: {body.Length}");
        Assert.Contains("лицензионное соглашение", body, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("https://datagateapp.com", body, StringComparison.Ordinal);
        Assert.Contains("КАК ЕСТЬ", body, StringComparison.Ordinal);
        Assert.Contains("несовершеннолетн", body, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("родительского контроля", body, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("не несут ответственности", body, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("Лицензионное соглашение", title, StringComparison.Ordinal);
        Assert.Contains("Я принимаю лицензионное соглашение", accept, StringComparison.Ordinal);
        Assert.DoesNotContain("I accept the license agreement", accept, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("End User License Agreement", body, StringComparison.Ordinal);
    }

    [Fact]
    public void InstallerLanguageService_LoadsLocaleExtrasOverlay()
    {
        var src = File.ReadAllText(FindRepoFile(Path.Combine("DataGateWin.Installer", "Localization", "InstallerLanguageService.cs")));
        Assert.Contains("InstallerExtras.en.xaml", src, StringComparison.Ordinal);
        Assert.Contains("InstallerExtras.{effective}.xaml", src, StringComparison.Ordinal);
    }

    [Fact]
    public void InstallerExtras_CoverEveryUiLocale_AndAreNotLeftInEnglish()
    {
        var enTitle = ReadInstallerString("InstallerExtras.en.xaml", "Install_LicenseTitle");
        var enAccept = ReadInstallerString("InstallerExtras.en.xaml", "Install_AcceptPolicy");
        var enBody = ReadInstallerString("InstallerExtras.en.xaml", "Install_PolicyBody");
        var failures = new List<string>();

        foreach (var loc in UiLocale.All)
        {
            var file = $"InstallerExtras.{loc.Code}.xaml";
            try
            {
                var title = ReadInstallerString(file, "Install_LicenseTitle");
                var accept = ReadInstallerString(file, "Install_AcceptPolicy");
                var body = ReadInstallerString(file, "Install_PolicyBody");

                if (!body.Contains("https://datagateapp.com", StringComparison.Ordinal))
                    failures.Add($"{loc.Code}: missing datagateapp.com");
                if (body.Length < 1200)
                    failures.Add($"{loc.Code}: EULA too short ({body.Length})");

                if (string.Equals(loc.Code, "en", StringComparison.OrdinalIgnoreCase))
                    continue;

                if (string.Equals(title, enTitle, StringComparison.Ordinal))
                    failures.Add($"{loc.Code}: title still English");
                if (string.Equals(accept, enAccept, StringComparison.Ordinal))
                    failures.Add($"{loc.Code}: accept checkbox still English");
                if (string.Equals(body, enBody, StringComparison.Ordinal))
                    failures.Add($"{loc.Code}: body still English");
                if (accept.Contains("I accept the license agreement", StringComparison.OrdinalIgnoreCase))
                    failures.Add($"{loc.Code}: accept leftover English");
            }
            catch (Exception ex)
            {
                failures.Add($"{loc.Code}: {ex.Message}");
            }
        }

        Assert.True(failures.Count == 0, string.Join('\n', failures));
    }

    static string ReadInstallerString(string fileName, string key)
    {
        var path = FindRepoFile(Path.Combine("DataGateWin.Installer", "Localization", fileName));
        var doc = XDocument.Load(path);
        XNamespace sys = "clr-namespace:System;assembly=System.Runtime";
        var match = doc.Descendants()
            .FirstOrDefault(e => (string?)e.Attribute("Key") == key || (string?)e.Attribute("{http://schemas.microsoft.com/winfx/2006/xaml}Key") == key);

        Assert.False(match is null, $"Missing {key} in {fileName}");
        var text = match!.Value.Trim();
        Assert.False(string.IsNullOrWhiteSpace(text), $"{key} is empty in {fileName}");
        return text;
    }

    static string FindRepoFile(string relative)
    {
        var dir = new DirectoryInfo(AppContext.BaseDirectory);
        while (dir is not null)
        {
            var candidate = Path.Combine(dir.FullName, relative);
            if (File.Exists(candidate))
                return candidate;
            dir = dir.Parent;
        }

        throw new FileNotFoundException(relative);
    }
}
