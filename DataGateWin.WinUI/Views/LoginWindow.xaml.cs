using DataGateWin.Configuration;
using DataGateWin.Localization;
using DataGateWin.Services.Auth;
using DataGateWin.Services.Support;
using DataGateWin.Services.Ui;
using DataGateWin.ViewModels;
using Microsoft.Extensions.Configuration;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;

namespace DataGateWin.Views;

public sealed partial class LoginWindow : Window
{
    private readonly AuthStateStore _authState;
    private readonly LoginViewModel _vm;
    private bool _suppressLanguageCombo;

    public LoginWindow(AuthStateStore authState)
    {
        InitializeComponent();
        WindowChrome.ApplyDefault(this, width: 520, height: 560);
        _authState = authState ?? throw new ArgumentNullException(nameof(authState));

        var googleSettings = App.AppConfiguration.GetSection("GoogleAuth").Get<GoogleAuthSettings>()
            ?? throw new InvalidOperationException("GoogleAuth settings are missing.");
        var apiSettings = App.AppConfiguration.GetSection("Api").Get<ApiSettings>()
            ?? throw new InvalidOperationException("Api settings are missing.");

        _vm = new LoginViewModel(App.GoogleAuth, App.Session, googleSettings, apiSettings);
        _vm.PropertyChanged += (_, e) =>
        {
            if (e.PropertyName is nameof(LoginViewModel.StatusText) or nameof(LoginViewModel.IsBusy) or nameof(LoginViewModel.IsNotBusy))
                ApplyVmToUi();
        };
        _vm.SignedIn += (_, accessToken) =>
        {
            _authState.SetAuthorized(accessToken);
            if (Application.Current is App app)
                app.ShowMain(_authState);
        };

        WinUiLanguageService.LanguageChanged += OnUiLanguageChanged;
        Closed += (_, _) => WinUiLanguageService.LanguageChanged -= OnUiLanguageChanged;
        ApplyLocalizedChrome();
        PopulateLoginLanguageCombo();
        ApplyVmToUi();
    }

    private void ApplyVmToUi()
    {
        StatusText.Text = _vm.StatusText;
        BusyRing.IsActive = _vm.IsBusy;
        BusyRing.Visibility = _vm.IsBusy ? Visibility.Visible : Visibility.Collapsed;
        CancelButton.Visibility = _vm.IsBusy ? Visibility.Visible : Visibility.Collapsed;
        SignInButton.IsEnabled = _vm.IsNotBusy;
    }

    private void ApplyLocalizedChrome()
    {
        Title = Loc.T("App_Title");
        LanguageLabel.Text = Loc.T("Settings_Language");
        WelcomeTitle.Text = Loc.T("Login_Welcome");
        WelcomeSubtitle.Text = Loc.T("Login_SignInToContinue");
        SignInButton.Content = Loc.T("Login_SignInGoogle");
        CancelButton.Content = Loc.T("Login_Cancel");
        TelegramButton.Content = Loc.T("Telegram_SubscribeHint");
        FooterHint.Text = Loc.T("Login_FooterHint");
        ReportIssueButton.Content = Loc.T("Home_ReportIssue");
        ToolTipService.SetToolTip(ReportIssueButton, Loc.T("Home_ReportIssue"));
    }

    private void OnUiLanguageChanged(object? sender, EventArgs e)
    {
        DispatcherQueue.TryEnqueue(() =>
        {
            ApplyLocalizedChrome();
            PopulateLoginLanguageCombo();
        });
    }

    private void PopulateLoginLanguageCombo()
    {
        var pref = WinUiLanguageService.GetStoredLanguagePreference();
        _suppressLanguageCombo = true;
        LoginLanguageCombo.Items.Clear();
        LoginLanguageCombo.Items.Add(new ComboBoxItem
        {
            Tag = WinUiLanguageService.SystemPreference,
            Content = WinUiLanguageService.GetLanguageDisplayName(WinUiLanguageService.SystemPreference),
        });
        foreach (var code in WinUiLanguageService.GetLanguagePickerCodes())
        {
            LoginLanguageCombo.Items.Add(new ComboBoxItem
            {
                Tag = code,
                Content = WinUiLanguageService.GetLanguageDisplayName(code),
            });
        }

        ComboBoxItem? match = null;
        foreach (ComboBoxItem item in LoginLanguageCombo.Items)
        {
            if (item.Tag is string t && string.Equals(t, pref, StringComparison.OrdinalIgnoreCase))
            {
                match = item;
                break;
            }
        }

        LoginLanguageCombo.SelectedItem = match ?? LoginLanguageCombo.Items[0] as ComboBoxItem;
        _suppressLanguageCombo = false;
    }

    private void LoginLanguageCombo_OnSelectionChanged(object sender, SelectionChangedEventArgs e)
    {
        if (_suppressLanguageCombo)
            return;
        if (LoginLanguageCombo.SelectedItem is not ComboBoxItem { Tag: string code })
            return;
        WinUiLanguageService.Apply(code, persist: true);
    }

    private async void SignIn_OnClick(object sender, RoutedEventArgs e)
    {
        if (_vm.SignInCommand.CanExecute(null))
            await _vm.SignInCommand.ExecuteAsync(null);
    }

    private void Cancel_OnClick(object sender, RoutedEventArgs e)
    {
        if (_vm.CancelCommand.CanExecute(null))
            _vm.CancelCommand.Execute(null);
    }

    private async void ReportIssue_OnClick(object sender, RoutedEventArgs e)
    {
        var dlg = new ReportIssueDialog();
        if (Content is FrameworkElement fe)
            await dlg.ShowAsync(fe.XamlRoot);
    }

    private void TelegramChannel_OnClick(object sender, RoutedEventArgs e)
        => TelegramChannel.OpenPublicChannel();
}
