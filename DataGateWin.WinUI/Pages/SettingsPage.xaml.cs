using System.Net.Http;
using System.Reflection;
using DataGateWin.Configuration;
using DataGateWin.CrashReporting;
using DataGateWin.Localization;
using DataGateWin.Services.Auth;
using DataGateWin.Services.Ui;
using DataGateWin.Services.Update;
using DataGateWin.Views;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;

namespace DataGateWin.Pages;

/// <summary>
/// Settings UI is code-built (no page XAML / LoadComponent). Theme brushes come from
/// <see cref="UiThemeBrushes"/> — never ThemeResource markup, which FailFasts unpackaged WinUI.
/// </summary>
public sealed class SettingsPage : Page
{
    private readonly AuthStateStore _authState;
    private bool _suppressLanguageCombo;
    private bool _suppressIpListsToggle;
    private bool _suppressThemeToggle;
    private bool _languageHookAttached;

    private TextBlock _titleText = null!;
    private TextBlock _languageHeader = null!;
    private TextBlock _languageHint = null!;
    private ComboBox _languageCombo = null!;
    private TextBlock _appearanceHeader = null!;
    private TextBlock _appearanceHint = null!;
    private ToggleSwitch _themeToggle = null!;
    private TextBlock _ipListsHeader = null!;
    private TextBlock _ipListsHint = null!;
    private ToggleSwitch _ipListsMainToggle = null!;
    private TextBlock _ipListsConfigureButtonText = null!;
    private TextBlock _versionHeader = null!;
    private TextBlock _currentVersionText = null!;
    private TextBlock _latestVersionText = null!;
    private TextBlock _aboutButtonText = null!;
    private TextBlock _accountHeader = null!;
    private TextBlock _accountHint = null!;
    private TextBlock _logoutButtonText = null!;

    public SettingsPage(AuthStateStore authState)
    {
        _authState = authState;
        try
        {
            Content = BuildContent();
            ApplyLocalizedChrome();

            _suppressThemeToggle = true;
            _themeToggle.IsOn = !string.Equals(App.Settings.Theme, "Light", StringComparison.OrdinalIgnoreCase);
            _suppressThemeToggle = false;

            LoadVersionInfo();
            WinUiLanguageService.LanguageChanged += OnUiLanguageChanged;
            _languageHookAttached = true;
            Loaded += SettingsPage_OnLoaded;
        }
        catch (Exception ex)
        {
            Content = UiErrorPanel.FromException("SettingsPage.Ctor", ex);
        }
    }

    /// <summary>Construct settings for <see cref="SafeUiContent"/> — never call from XAML LoadComponent.</summary>
    public static UIElement Create(AuthStateStore authState)
        => new SettingsPage(authState);

    private void OnUiLanguageChanged(object? sender, EventArgs e)
        => DispatcherQueue.TryEnqueue(ApplyOnShown);

    public void ApplyOnShown()
    {
        try
        {
            ApplyLocalizedChrome();
            PopulateLanguageComboSelection();
            LoadVersionInfo();
        }
        catch (Exception ex)
        {
            CrashReporter.ReportNonFatal(ex, "SettingsPage.ApplyOnShown");
        }
    }

    private void ApplyLocalizedChrome()
    {
        _titleText.Text = Loc.T("Settings_Title");
        _languageHeader.Text = Loc.T("Settings_Language");
        _languageHint.Text = Loc.T("Settings_LanguageHint");
        _appearanceHeader.Text = Loc.T("Settings_Appearance");
        _appearanceHint.Text = Loc.T("Settings_AppearanceHint");
        _themeToggle.Header = Loc.T("Settings_DarkMode");
        _ipListsHeader.Text = Loc.T("Settings_IpLists");
        _ipListsHint.Text = Loc.T("Settings_IpLists_Subtitle");
        _ipListsMainToggle.Header = Loc.T("Settings_IpLists_Enable");
        _ipListsConfigureButtonText.Text = Loc.T("Settings_IpLists_Open");
        _versionHeader.Text = Loc.T("Settings_Application");
        _aboutButtonText.Text = Loc.T("Settings_About");
        _accountHeader.Text = Loc.T("Settings_Account");
        _accountHint.Text = Loc.T("Settings_AccountHint");
        _logoutButtonText.Text = Loc.T("Settings_Logout");
    }

    private void SettingsPage_OnLoaded(object sender, RoutedEventArgs e)
    {
        try
        {
            if (!_languageHookAttached)
            {
                WinUiLanguageService.LanguageChanged += OnUiLanguageChanged;
                _languageHookAttached = true;
            }

            ApplyOnShown();
            ApplyIpListsToggleFromStore();
        }
        catch (Exception ex)
        {
            CrashReporter.ReportNonFatal(ex, "SettingsPage.OnLoaded");
        }
    }

    private void ApplyIpListsToggleFromStore()
    {
        _suppressIpListsToggle = true;
        try
        {
            _ipListsMainToggle.IsOn = IpListStore.LoadSettings().CidrListsEnabled;
        }
        catch (Exception ex)
        {
            CrashReporter.ReportNonFatal(ex, "SettingsPage.ApplyIpListsToggle");
        }
        finally
        {
            _suppressIpListsToggle = false;
        }
    }

    private void IpListsMainToggle_OnToggled(object sender, RoutedEventArgs e)
    {
        if (_suppressIpListsToggle)
            return;
        try
        {
            var s = IpListStore.LoadSettings();
            s.CidrListsEnabled = _ipListsMainToggle.IsOn;
            IpListStore.SaveSettings(s);
        }
        catch (Exception ex)
        {
            CrashReporter.ReportNonFatal(ex, "SettingsPage.IpListsToggle");
        }
    }

    private async void IpListsConfigure_OnClick(object sender, RoutedEventArgs e)
    {
        try
        {
            var wnd = new IpListSettingsWindow();
            await wnd.ShowAsync();
            ApplyIpListsToggleFromStore();
        }
        catch (Exception ex)
        {
            CrashReporter.ReportNonFatal(ex, "SettingsPage.IpListsConfigure");
        }
    }

    private void PopulateLanguageComboSelection()
    {
        var pref = WinUiLanguageService.GetStoredLanguagePreference();
        _suppressLanguageCombo = true;
        try
        {
            _languageCombo.Items.Clear();
            _languageCombo.Items.Add(new ComboBoxItem
            {
                Tag = WinUiLanguageService.SystemPreference,
                Content = WinUiLanguageService.GetLanguageDisplayName(WinUiLanguageService.SystemPreference),
            });
            foreach (var code in WinUiLanguageService.GetLanguagePickerCodes())
            {
                _languageCombo.Items.Add(new ComboBoxItem
                {
                    Tag = code,
                    Content = WinUiLanguageService.GetLanguageDisplayName(code),
                });
            }

            ComboBoxItem? match = null;
            foreach (ComboBoxItem item in _languageCombo.Items)
            {
                if (item.Tag is string t && string.Equals(t, pref, StringComparison.OrdinalIgnoreCase))
                {
                    match = item;
                    break;
                }
            }

            _languageCombo.SelectedItem = match ?? _languageCombo.Items[0] as ComboBoxItem;
        }
        finally
        {
            _suppressLanguageCombo = false;
        }
    }

    private void LanguageCombo_OnSelectionChanged(object sender, SelectionChangedEventArgs e)
    {
        if (_suppressLanguageCombo)
            return;
        if (_languageCombo.SelectedItem is not ComboBoxItem { Tag: string code })
            return;
        try
        {
            WinUiLanguageService.Apply(code, persist: true);
            ApplyOnShown();
        }
        catch (Exception ex)
        {
            CrashReporter.ReportNonFatal(ex, "SettingsPage.LanguageChange");
        }
    }

    private void LoadVersionInfo()
    {
        try
        {
            var version = AppUpdatePolicy.ResolveCurrentAppVersion(
                Assembly.GetExecutingAssembly().Location,
                Assembly.GetExecutingAssembly().GetName().Version,
                AppContext.BaseDirectory);
            _currentVersionText.Text = Loc.T("Settings_CurrentVersion") + " " +
                                       ReleaseVersionParser.FormatForDisplay(version);
        }
        catch (Exception ex)
        {
            CrashReporter.ReportNonFatal(ex, "SettingsPage.LoadVersionInfo");
            _currentVersionText.Text = Loc.T("Settings_CurrentVersion") + " " + Loc.T("Settings_UnknownVersion");
        }

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

        DispatcherQueue.TryEnqueue(() =>
        {
            try { _latestVersionText.Text = text; }
            catch (Exception ex) { CrashReporter.ReportNonFatal(ex, "SettingsPage.LatestVersionUi"); }
        });
    }

    private void ThemeToggle_OnToggled(object sender, RoutedEventArgs e)
    {
        if (_suppressThemeToggle)
            return;

        try
        {
            var dark = _themeToggle.IsOn;
            App.Settings.Theme = dark ? "Dark" : "Light";
            AppSettingsStore.SaveSafe(App.Settings);
            App.ApplyElementTheme(dark ? ElementTheme.Dark : ElementTheme.Light);
        }
        catch (Exception ex)
        {
            CrashReporter.ReportNonFatal(ex, "SettingsPage.ThemeToggle");
        }
    }

    private async void LogoutButton_OnClick(object sender, RoutedEventArgs e)
    {
        if (XamlRoot is null)
            return;

        try
        {
            var confirm = new ContentDialog
            {
                Title = Loc.T("Msg_LogoutTitle"),
                Content = Loc.T("Msg_LogoutConfirm"),
                PrimaryButtonText = Loc.T("Action_Yes"),
                CloseButtonText = Loc.T("Action_No"),
                DefaultButton = ContentDialogButton.Close,
                XamlRoot = XamlRoot,
            };
            if (await confirm.ShowAsync() != ContentDialogResult.Primary)
                return;

            await App.Session.LogoutAsync(CancellationToken.None);
            _authState.Clear();
            if (Application.Current is App app)
                app.ShowLogin(_authState);
        }
        catch (Exception ex)
        {
            CrashReporter.ReportNonFatal(ex, "SettingsPage.Logout");
            try
            {
                if (XamlRoot is null)
                    return;
                await new ContentDialog
                {
                    Title = Loc.T("Msg_ErrorTitle"),
                    Content = Loc.T("Msg_LogoutFailedFmt", VpnUserFacingError.FromException(ex)),
                    CloseButtonText = Loc.T("Action_Ok"),
                    XamlRoot = XamlRoot,
                }.ShowAsync();
            }
            catch (Exception showEx)
            {
                CrashReporter.ReportNonFatal(showEx, "SettingsPage.LogoutDialog");
            }
        }
    }

    private async void AboutButton_OnClick(object sender, RoutedEventArgs e)
    {
        if (XamlRoot is null)
            return;
        try
        {
            await new AboutDialog().ShowAsync(XamlRoot);
        }
        catch (Exception ex)
        {
            CrashReporter.ReportNonFatal(ex, "SettingsPage.About");
        }
    }

    private UIElement BuildContent()
    {
        _titleText = new TextBlock { FontSize = 20, FontWeight = Microsoft.UI.Text.FontWeights.SemiBold, VerticalAlignment = VerticalAlignment.Center };
        _languageHeader = new TextBlock { FontWeight = Microsoft.UI.Text.FontWeights.SemiBold, VerticalAlignment = VerticalAlignment.Center };
        _languageHint = new TextBlock { Opacity = 0.75, TextWrapping = TextWrapping.Wrap };
        _languageCombo = new ComboBox { MinWidth = 280 };
        _languageCombo.SelectionChanged += LanguageCombo_OnSelectionChanged;

        _appearanceHeader = new TextBlock { FontWeight = Microsoft.UI.Text.FontWeights.SemiBold, VerticalAlignment = VerticalAlignment.Center };
        _appearanceHint = new TextBlock { Opacity = 0.75, TextWrapping = TextWrapping.Wrap };
        _themeToggle = new ToggleSwitch();
        _themeToggle.Toggled += ThemeToggle_OnToggled;

        _ipListsHeader = new TextBlock { FontWeight = Microsoft.UI.Text.FontWeights.SemiBold, VerticalAlignment = VerticalAlignment.Center };
        _ipListsHint = new TextBlock { Opacity = 0.75, TextWrapping = TextWrapping.Wrap };
        _ipListsMainToggle = new ToggleSwitch();
        _ipListsMainToggle.Toggled += IpListsMainToggle_OnToggled;
        _ipListsConfigureButtonText = new TextBlock { VerticalAlignment = VerticalAlignment.Center };
        var ipListsBtn = new Button();
        ipListsBtn.Content = Row(IconButtonContent.Settings, _ipListsConfigureButtonText, 14);
        ipListsBtn.Click += IpListsConfigure_OnClick;

        _versionHeader = new TextBlock { FontWeight = Microsoft.UI.Text.FontWeights.SemiBold, VerticalAlignment = VerticalAlignment.Center };
        _currentVersionText = new TextBlock();
        _latestVersionText = new TextBlock { Opacity = 0.75 };
        _aboutButtonText = new TextBlock { VerticalAlignment = VerticalAlignment.Center };
        var aboutBtn = new Button();
        aboutBtn.Content = Row(IconButtonContent.Info, _aboutButtonText, 14);
        aboutBtn.Click += AboutButton_OnClick;

        _accountHeader = new TextBlock { FontWeight = Microsoft.UI.Text.FontWeights.SemiBold, VerticalAlignment = VerticalAlignment.Center };
        _accountHint = new TextBlock { Opacity = 0.75, TextWrapping = TextWrapping.Wrap };
        _logoutButtonText = new TextBlock { VerticalAlignment = VerticalAlignment.Center };
        var logoutBtn = new Button();
        logoutBtn.Content = Row(IconButtonContent.SignOut, _logoutButtonText, 14);
        logoutBtn.Click += LogoutButton_OnClick;

        var root = new StackPanel { Margin = new Thickness(20), Spacing = 16 };
        root.Children.Add(Row(IconButtonContent.Settings, _titleText, 18));
        root.Children.Add(Card(
            Row(IconButtonContent.Language, _languageHeader, 16),
            _languageHint,
            _languageCombo));
        root.Children.Add(Card(
            Row(IconButtonContent.Appearance, _appearanceHeader, 16),
            _appearanceHint,
            _themeToggle));
        root.Children.Add(Card(
            Row(IconButtonContent.Network, _ipListsHeader, 16),
            _ipListsHint,
            _ipListsMainToggle,
            ipListsBtn));
        root.Children.Add(Card(
            Row(IconButtonContent.Info, _versionHeader, 16),
            _currentVersionText,
            _latestVersionText,
            aboutBtn));
        root.Children.Add(Card(
            Row(IconButtonContent.Account, _accountHeader, 16),
            _accountHint,
            logoutBtn));

        return new ScrollViewer { Content = root };
    }

    private static Border Card(params UIElement[] children)
    {
        var panel = new StackPanel { Spacing = 8 };
        foreach (var child in children)
            panel.Children.Add(child);

        return new Border
        {
            Padding = new Thickness(18),
            CornerRadius = new CornerRadius(8),
            Background = UiThemeBrushes.CardBackground(),
            Child = panel,
        };
    }

    private static StackPanel Row(string glyph, FrameworkElement label, double iconSize)
    {
        var row = new StackPanel { Orientation = Orientation.Horizontal, Spacing = 8 };
        row.Children.Add(new FontIcon
        {
            Glyph = glyph,
            FontSize = iconSize,
            VerticalAlignment = VerticalAlignment.Center,
        });
        label.VerticalAlignment = VerticalAlignment.Center;
        row.Children.Add(label);
        return row;
    }
}
