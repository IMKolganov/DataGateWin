using System.Net.Http;
using DataGateWin.Controllers;
using DataGateWin.CrashReporting;
using DataGateWin.Localization;
using DataGateWin.Pages;
using DataGateWin.Pages.Home;
using DataGateWin.Services.Auth;
using DataGateWin.Services.Identity;
using DataGateWin.Services.Support;
using DataGateWin.Views;
using Microsoft.UI.Windowing;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;

namespace DataGateWin;

public sealed partial class MainWindow : Window
{
    private readonly FreeTierAccessApiClient _freeTierAccessApi;
    private bool _isOnboardingDialogOpen;
    private DateTimeOffset _lastOnboardingCheckUtc = DateTimeOffset.MinValue;
    private readonly AuthStateStore _authState;
    private readonly HomeController _homeController = new();
    private readonly HomePage _homePage;
    private readonly AccessPage _accessPage = new();
    private readonly StatisticsPage _statisticsPage;
    private readonly SettingsPage _settingsPage;

    public MainWindow(AuthStateStore authState, HttpClient authedApiHttp)
    {
        InitializeComponent();
        ExtendsContentIntoTitleBar = true;
        SetTitleBar(AppTitleBar);
        AppWindow.TitleBar.PreferredHeightOption = TitleBarHeightOption.Tall;
        try { AppWindow.SetIcon(Path.Combine(AppContext.BaseDirectory, "Assets", "AppIcon.ico")); } catch { /* ignore */ }

        _authState = authState;
        _freeTierAccessApi = new FreeTierAccessApiClient(authedApiHttp);
        _homePage = new HomePage(_homeController);
        _settingsPage = new SettingsPage(_authState);
        _statisticsPage = new StatisticsPage(authedApiHttp, App.Session);

        ApplyNavLabels();
        WinUiLanguageService.LanguageChanged += OnLanguageChanged;
        Closed += (_, _) =>
        {
            WinUiLanguageService.LanguageChanged -= OnLanguageChanged;
            _homeController.Dispose();
        };

        Activated += async (_, _) =>
        {
            // First activation: navigate + footer + onboarding
        };

        // Navigate after content is ready
        DispatcherQueue.TryEnqueue(async () =>
        {
            NavigateTo("home");
            await ApplyUserPaneFooterAsync();
            await CheckAndShowFreeTierOnboardingIfNeededAsync(force: true);
        });
    }

    private void OnLanguageChanged(object? sender, EventArgs e)
        => DispatcherQueue.TryEnqueue(ApplyNavLabels);

    private void ApplyNavLabels()
    {
        Title = Loc.T("App_Title");
        AppTitleBar.Title = Loc.T("App_Title");
        NavHome.Content = Loc.T("Nav_Home");
        NavAccess.Content = Loc.T("Nav_Access");
        NavStatistics.Content = Loc.T("Nav_Statistics");
        NavSettings.Content = Loc.T("Nav_Settings");
        TelegramChannelButton.Content = Loc.T("Telegram_SubscribeHint");
        ReportIssueButton.Content = Loc.T("Home_ReportIssue");
    }

    private async Task ApplyUserPaneFooterAsync()
    {
        var token = App.Session.Current?.Token;
        var displayName = AccountDisplay.TryResolveDisplayName(token) ?? Loc.T("Common_Unknown");
        UserDisplayName.Text = displayName;
        UserAvatarInitials.Text = AccountDisplay.GetInitials(displayName);
        // TODO(parity): load profile image via UserAvatarCache (WPF helper not yet ported)
        UserAvatarImage.Visibility = Visibility.Collapsed;
        UserAvatarInitials.Visibility = Visibility.Visible;
        await Task.CompletedTask;
    }

    private void TitleBar_PaneToggleRequested(TitleBar sender, object args)
        => NavView.IsPaneOpen = !NavView.IsPaneOpen;

    private void NavView_SelectionChanged(NavigationView sender, NavigationViewSelectionChangedEventArgs args)
    {
        if (args.SelectedItem is NavigationViewItem item)
            NavigateTo(item.Tag?.ToString());
    }

    private void NavigateTo(string? tag)
    {
        switch (tag)
        {
            case "access":
                NavFrame.Content = _accessPage;
                break;
            case "statistics":
                NavFrame.Content = _statisticsPage;
                break;
            case "settings":
                NavFrame.Content = _settingsPage;
                break;
            default:
                NavFrame.Content = _homePage;
                tag = "home";
                break;
        }

        if (tag is "home" or "access")
            _ = CheckAndShowFreeTierOnboardingIfNeededAsync(force: false);
    }

    private async Task CheckAndShowFreeTierOnboardingIfNeededAsync(bool force)
    {
        if (_isOnboardingDialogOpen)
            return;

        if (!force && !FreeTierOnboardingPolicy.ShouldRefreshOnPoll(_lastOnboardingCheckUtc, DateTimeOffset.UtcNow))
            return;

        _lastOnboardingCheckUtc = DateTimeOffset.UtcNow;

        try
        {
            var resp = await _freeTierAccessApi.GetStatusAsync(CancellationToken.None);
            var status = resp.Data;
            if (!FreeTierOnboardingPolicy.ShouldShow(status) || status == null)
                return;

            _isOnboardingDialogOpen = true;
            if (Content is FrameworkElement fe && fe.XamlRoot is not null)
            {
                var wnd = new FreeTierOnboardingWindow(_freeTierAccessApi, status);
                await wnd.ShowAsync(fe.XamlRoot);
                App.ScheduleUpdateCheck();
            }
        }
        catch (Exception ex)
        {
            CrashReporter.ReportNonFatal(ex, "MainWindow.CheckFreeTierOnboarding");
        }
        finally
        {
            _isOnboardingDialogOpen = false;
        }
    }

    private async void ReportIssue_OnClick(object sender, RoutedEventArgs e)
    {
        if (Content is FrameworkElement fe)
            await new ReportIssueDialog().ShowAsync(fe.XamlRoot);
    }

    private void TelegramChannel_OnClick(object sender, RoutedEventArgs e)
        => TelegramChannel.OpenPublicChannel();
}
