using System.Net.Http;
using System.Reflection;
using DataGateWin.Configuration;
using DataGateWin.CrashReporting;
using DataGateWin.Localization;
using DataGateWin.Services.Auth;
using DataGateWin.Services.Update;
using DataGateWin.Views;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;

namespace DataGateWin.Pages;

public sealed partial class SettingsPage : Page
{
    private readonly AuthStateStore _authState;
    private bool _suppressLanguageCombo;
    private bool _suppressIpListsToggle;
    private bool _suppressThemeToggle;

    public SettingsPage(AuthStateStore authState)
    {
        _authState = authState;
        InitializeComponent();
        ApplyLocalizedChrome();

        _suppressThemeToggle = true;
        ThemeToggle.IsOn = !string.Equals(App.Settings.Theme, "Light", StringComparison.OrdinalIgnoreCase);
        _suppressThemeToggle = false;

        LoadVersionInfo();
        WinUiLanguageService.LanguageChanged += OnUiLanguageChanged;
        Unloaded += (_, _) => WinUiLanguageService.LanguageChanged -= OnUiLanguageChanged;
    }

    private void OnUiLanguageChanged(object? sender, EventArgs e)
        => DispatcherQueue.TryEnqueue(() =>
        {
            ApplyLocalizedChrome();
            PopulateLanguageComboSelection();
        });

    private void ApplyLocalizedChrome()
    {
        TitleText.Text = Loc.T("Settings_Title");
        LanguageHeader.Text = Loc.T("Settings_Language");
        LanguageHint.Text = Loc.T("Settings_LanguageHint");
        AppearanceHeader.Text = Loc.T("Settings_Appearance");
        AppearanceHint.Text = Loc.T("Settings_AppearanceHint");
        ThemeToggle.Header = Loc.T("Settings_DarkMode");
        IpListsHeader.Text = Loc.T("Settings_IpLists");
        IpListsMainToggle.Header = Loc.T("Settings_IpLists_Enable");
        IpListsConfigureButton.Content = Loc.T("Settings_IpLists_Open");
        VersionHeader.Text = Loc.T("Settings_CurrentVersion");
        AboutButton.Content = Loc.T("Settings_About");
        LogoutButton.Content = Loc.T("Settings_Logout");
    }

    private void SettingsPage_OnLoaded(object sender, RoutedEventArgs e)
    {
        PopulateLanguageComboSelection();
        ApplyIpListsToggleFromStore();
    }

    private void ApplyIpListsToggleFromStore()
    {
        _suppressIpListsToggle = true;
        IpListsMainToggle.IsOn = IpListStore.LoadSettings().CidrListsEnabled;
        _suppressIpListsToggle = false;
    }

    private void IpListsMainToggle_OnToggled(object sender, RoutedEventArgs e)
    {
        if (_suppressIpListsToggle)
            return;
        var s = IpListStore.LoadSettings();
        s.CidrListsEnabled = IpListsMainToggle.IsOn;
        IpListStore.SaveSettings(s);
    }

    private async void IpListsConfigure_OnClick(object sender, RoutedEventArgs e)
    {
        // TODO(parity): port IpListSettingsWindow fully
        if (XamlRoot is null)
            return;
        await new ContentDialog
        {
            Title = Loc.T("Settings_IpLists"),
            Content = "IP list route editor is not yet ported to WinUI.",
            CloseButtonText = Loc.T("Action_Ok"),
            XamlRoot = XamlRoot,
        }.ShowAsync();
        ApplyIpListsToggleFromStore();
    }

    private void PopulateLanguageComboSelection()
    {
        var pref = WinUiLanguageService.GetStoredLanguagePreference();
        _suppressLanguageCombo = true;
        LanguageCombo.Items.Clear();
        LanguageCombo.Items.Add(new ComboBoxItem
        {
            Tag = WinUiLanguageService.SystemPreference,
            Content = WinUiLanguageService.GetLanguageDisplayName(WinUiLanguageService.SystemPreference),
        });
        foreach (var code in WinUiLanguageService.GetLanguagePickerCodes())
        {
            LanguageCombo.Items.Add(new ComboBoxItem
            {
                Tag = code,
                Content = WinUiLanguageService.GetLanguageDisplayName(code),
            });
        }

        ComboBoxItem? match = null;
        foreach (ComboBoxItem item in LanguageCombo.Items)
        {
            if (item.Tag is string t && string.Equals(t, pref, StringComparison.OrdinalIgnoreCase))
            {
                match = item;
                break;
            }
        }

        LanguageCombo.SelectedItem = match ?? LanguageCombo.Items[0] as ComboBoxItem;
        _suppressLanguageCombo = false;
    }

    private void LanguageCombo_OnSelectionChanged(object sender, SelectionChangedEventArgs e)
    {
        if (_suppressLanguageCombo)
            return;
        if (LanguageCombo.SelectedItem is not ComboBoxItem { Tag: string code })
            return;
        WinUiLanguageService.Apply(code, persist: true);
    }

    private void LoadVersionInfo()
    {
        var version = Assembly.GetExecutingAssembly().GetName().Version;
        CurrentVersionText.Text = Loc.T("Settings_CurrentVersion") + " " + (version?.ToString() ?? Loc.T("Settings_UnknownVersion"));
        _ = LoadLatestVersionAsync();
    }

    private async Task LoadLatestVersionAsync()
    {
        string text;
        try
        {
            var checker = new GitHubUpdateChecker(new HttpClient(), "IMKolganov", "DataGateWin");
            var latest = await checker.TryGetLatestReleaseVersionForDisplayAsync(CancellationToken.None);
            text = latest is null
                ? Loc.T("Settings_LatestVersionUnavailable")
                : Loc.T("Settings_LatestVersion") + " " + latest;
        }
        catch (Exception ex)
        {
            CrashReporter.ReportNonFatal(ex, "SettingsPage.LoadLatestVersion");
            text = Loc.T("Settings_LatestVersionUnavailable");
        }

        DispatcherQueue.TryEnqueue(() => LatestVersionText.Text = text);
    }

    private void ThemeToggle_OnToggled(object sender, RoutedEventArgs e)
    {
        if (_suppressThemeToggle)
            return;

        var dark = ThemeToggle.IsOn;
        App.Settings.Theme = dark ? "Dark" : "Light";
        AppSettingsStore.SaveSafe(App.Settings);
        if (Application.Current is App)
        {
            Application.Current.RequestedTheme = dark ? ApplicationTheme.Dark : ApplicationTheme.Light;
            App.ApplyElementTheme(dark ? ElementTheme.Dark : ElementTheme.Light);
        }
    }

    private async void LogoutButton_OnClick(object sender, RoutedEventArgs e)
    {
        if (XamlRoot is null)
            return;

        var confirm = new ContentDialog
        {
            Title = Loc.T("Msg_LogoutTitle"),
            Content = Loc.T("Msg_LogoutConfirm"),
            PrimaryButtonText = "Yes",
            CloseButtonText = "No",
            DefaultButton = ContentDialogButton.Close,
            XamlRoot = XamlRoot,
        };
        if (await confirm.ShowAsync() != ContentDialogResult.Primary)
            return;

        try
        {
            await App.Session.LogoutAsync(CancellationToken.None);
            _authState.Clear();
            if (Application.Current is App app)
            {
                App.CurrentMainWindow?.Close();
                app.ShowLogin(_authState);
            }
        }
        catch (Exception ex)
        {
            CrashReporter.ReportNonFatal(ex, "SettingsPage.Logout");
            await new ContentDialog
            {
                Title = Loc.T("Msg_ErrorTitle"),
                Content = Loc.T("Msg_LogoutFailedFmt", ex.Message),
                CloseButtonText = Loc.T("Action_Ok"),
                XamlRoot = XamlRoot,
            }.ShowAsync();
        }
    }

    private async void AboutButton_OnClick(object sender, RoutedEventArgs e)
    {
        if (XamlRoot is null)
            return;
        await new AboutDialog().ShowAsync(XamlRoot);
    }
}
