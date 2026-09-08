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
        WinUiLanguageService.ApplyFlowDirection(Content as FrameworkElement);
        WindowChrome.ApplyDefault(this, width: 520, height: 620);
        _authState = authState ?? throw new ArgumentNullException(nameof(authState));

        var googleSettings = App.AppConfiguration.GetSection("GoogleAuth").Get<GoogleAuthSettings>()
            ?? throw new InvalidOperationException("GoogleAuth settings are missing.");
        var apiSettings = App.AppConfiguration.GetSection("Api").Get<ApiSettings>()
            ?? throw new InvalidOperationException("Api settings are missing.");

        _vm = new LoginViewModel(App.GoogleAuth, App.AuthApi, App.Session, googleSettings, apiSettings);
        _vm.PropertyChanged += (_, e) =>
        {
            if (e.PropertyName is nameof(LoginViewModel.StatusText)
                or nameof(LoginViewModel.IsBusy)
                or nameof(LoginViewModel.IsNotBusy)
                or nameof(LoginViewModel.IsTotpChallengeVisible)
                or nameof(LoginViewModel.IsGoogleSignInVisible)
                or nameof(LoginViewModel.TotpLeadText)
                or nameof(LoginViewModel.TotpCode))
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
        CancelButton.Visibility = _vm.IsBusy && _vm.IsGoogleSignInVisible
            ? Visibility.Visible
            : Visibility.Collapsed;
        SignInButton.IsEnabled = _vm.SignInCommand.CanExecute(null);
        GoogleSignInPanel.Visibility = _vm.IsGoogleSignInVisible ? Visibility.Visible : Visibility.Collapsed;
        TotpPanel.Visibility = _vm.IsTotpChallengeVisible ? Visibility.Visible : Visibility.Collapsed;
        TotpLead.Text = _vm.TotpLeadText;
        if (TotpCodeBox.Text != _vm.TotpCode)
            TotpCodeBox.Text = _vm.TotpCode;
        TotpVerifyButton.IsEnabled = _vm.VerifyTotpCommand.CanExecute(null);
        TotpBackButton.IsEnabled = _vm.BackFromTotpCommand.CanExecute(null);
        TotpCodeBox.IsEnabled = _vm.IsNotBusy;
    }

    private void ApplyLocalizedChrome()
    {
        Title = Loc.T("App_Title");
        ToolTipService.SetToolTip(LoginLanguageCombo, Loc.T("Settings_Language"));
        WelcomeTitle.Text = Loc.T("Login_Welcome");
        WelcomeSubtitle.Text = Loc.T("Login_SignInToContinue");
        SignInButtonText.Text = Loc.T("Login_SignInGoogle");
        CancelButtonText.Text = Loc.T("Login_Cancel");
        TotpTitle.Text = Loc.T("Login_Totp_Title");
        TotpVerifyButtonText.Text = Loc.T("Login_Totp_Verify");
        TotpBackButtonText.Text = Loc.T("Login_Totp_Back");
        TotpCodeBox.PlaceholderText = Loc.T("Login_Totp_CodePlaceholder");
        TelegramButtonText.Text = Loc.T("Telegram_SubscribeHint");
        FooterHint.Text = Loc.T("Login_FooterHint");
        ReportIssueButtonText.Text = Loc.T("Home_ReportIssue");
        ToolTipService.SetToolTip(ReportIssueButton, Loc.T("Home_ReportIssue"));
    }

    private void OnUiLanguageChanged(object? sender, EventArgs e)
    {
        DispatcherQueue.TryEnqueue(() =>
        {
            ApplyLocalizedChrome();
            PopulateLoginLanguageCombo();
            _vm.RefreshLanguage();
            ApplyVmToUi();
            WinUiLanguageService.ApplyFlowDirection(Content as FrameworkElement);
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

    private void TotpCodeBox_OnTextChanged(object sender, TextChangedEventArgs e)
    {
        _vm.TotpCode = TotpCodeBox.Text ?? "";
    }

    private async void TotpVerify_OnClick(object sender, RoutedEventArgs e)
    {
        if (_vm.VerifyTotpCommand.CanExecute(null))
            await _vm.VerifyTotpCommand.ExecuteAsync(null);
    }

    private void TotpBack_OnClick(object sender, RoutedEventArgs e)
    {
        if (_vm.BackFromTotpCommand.CanExecute(null))
            _vm.BackFromTotpCommand.Execute(null);
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
