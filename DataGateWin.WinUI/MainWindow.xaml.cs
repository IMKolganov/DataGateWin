using System.Net.Http;
using DataGateWin.Controllers;
using DataGateWin.CrashReporting;
using DataGateWin.Localization;
using DataGateWin.Pages;
using DataGateWin.Pages.Home;
using DataGateWin.Services.Auth;
using DataGateWin.Services.Identity;
using DataGateWin.Services.Security;
using DataGateWin.Services.Support;
using DataGateWin.Services.Ui;
using DataGateWin.Views;
using Microsoft.UI.Windowing;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Media;
using Microsoft.UI.Xaml.Media.Imaging;

namespace DataGateWin;

public sealed partial class MainWindow : Window
{
    private readonly FreeTierAccessApiClient _freeTierAccessApi;
    private readonly HttpClient _authedApiHttp;
    private bool _isOnboardingDialogOpen;
    private DateTimeOffset _lastOnboardingCheckUtc = DateTimeOffset.MinValue;
    private readonly AuthStateStore _authState;
    private readonly HomeController _homeController = new();
    private HomePage? _homePage;
    private AccessPage? _accessPage;
    private ImportPage? _importPage;
    private StatisticsPage? _statisticsPage;
    private SettingsPage? _settingsPage;
    private readonly TorrentClientMonitor _torrentClientMonitor;

    public MainWindow(AuthStateStore authState, HttpClient authedApiHttp)
    {
        InitializeComponent();
        ExtendsContentIntoTitleBar = true;
        SetTitleBar(AppTitleBar);
        AppWindow.TitleBar.PreferredHeightOption = TitleBarHeightOption.Tall;
        WindowChrome.ApplyDefault(this, width: 980, height: 620, minWidth: 900, minHeight: 560);

        _authState = authState;
        _authedApiHttp = authedApiHttp;
        _freeTierAccessApi = new FreeTierAccessApiClient(authedApiHttp);
        _torrentClientMonitor = new TorrentClientMonitor(
            DispatcherQueue,
            () => Content is FrameworkElement fe ? fe.XamlRoot : null);

        ApplyNavLabels();
        UpdatePaneFooterLayout();
        WinUiLanguageService.LanguageChanged += OnLanguageChanged;
        Closed += (_, _) =>
        {
            WinUiLanguageService.LanguageChanged -= OnLanguageChanged;
            _torrentClientMonitor.Dispose();
            _homeController.Dispose();
        };

        DispatcherQueue.TryEnqueue(async () =>
        {
            _torrentClientMonitor.Start();
            NavigateTo("home");
            await ApplyUserPaneFooterAsync();
            UpdatePaneFooterLayout();
            await CheckAndShowFreeTierOnboardingIfNeededAsync(force: true);
        });
    }

    private void OnLanguageChanged(object? sender, EventArgs e)
        => DispatcherQueue.TryEnqueue(() =>
        {
            ApplyNavLabels();
            UpdatePaneFooterLayout();
        });

    private void ApplyNavLabels()
    {
        Title = Loc.T("App_Title");
        AppTitleBar.Title = Loc.T("App_Title");
        NavHome.Content = Loc.T("Nav_Home");
        NavAccess.Content = Loc.T("Nav_Access");
        NavImport.Content = Loc.T("Nav_Import");
        NavStatistics.Content = Loc.T("Nav_Statistics");
        NavSettings.Content = Loc.T("Nav_Settings");
        TelegramChannelButton.Content = Loc.T("Telegram_SubscribeHint");
        ReportIssueButton.Content = Loc.T("Home_ReportIssue");
        ToolTipService.SetToolTip(TelegramChannelCompactButton, Loc.T("Telegram_SubscribeHint"));
        ToolTipService.SetToolTip(ReportIssueCompactButton, Loc.T("Home_ReportIssue"));
    }

    private void NavView_PaneStateChanged(NavigationView sender, object args)
        => UpdatePaneFooterLayout();

    private void UpdatePaneFooterLayout()
    {
        var expanded = NavView.IsPaneOpen;
        TelegramChannelButton.Visibility = expanded ? Visibility.Visible : Visibility.Collapsed;
        ReportIssueButton.Visibility = expanded ? Visibility.Visible : Visibility.Collapsed;
        TelegramChannelCompactButton.Visibility = expanded ? Visibility.Collapsed : Visibility.Visible;
        ReportIssueCompactButton.Visibility = expanded ? Visibility.Collapsed : Visibility.Visible;
        UserDisplayName.Visibility = expanded ? Visibility.Visible : Visibility.Collapsed;
        UserAvatarBorder.HorizontalAlignment = expanded ? HorizontalAlignment.Left : HorizontalAlignment.Center;
        if (expanded)
            Grid.SetColumnSpan(UserAvatarBorder, 1);
        else
            Grid.SetColumnSpan(UserAvatarBorder, 2);
        PaneFooterRoot.Margin = expanded ? new Thickness(8, 0, 8, 8) : new Thickness(0, 0, 0, 8);
    }

    private async Task ApplyUserPaneFooterAsync()
    {
        void ShowUserAvatarFallback()
        {
            UserAvatarBrush.ImageSource = null;
            UserAvatarInitials.Visibility = Visibility.Visible;
        }

        var token = App.Session.Current?.Token;
        var displayName = AccountDisplay.TryResolveDisplayName(token) ?? Loc.T("Common_Unknown");
        UserDisplayName.Text = displayName;
        UserAvatarInitials.Text = AccountDisplay.GetInitials(displayName);

        var picUrl = JwtClaimReader.GetProfileImageUrlFromBearerToken(token);
        if (string.IsNullOrWhiteSpace(picUrl))
        {
            ShowUserAvatarFallback();
            return;
        }

        var userId = JwtClaimReader.GetNumericUserIdFromBearerToken(token);

        try
        {
            var path = await UserAvatarCache.TryEnsureCachedPathAsync(picUrl, userId, CancellationToken.None)
                .ConfigureAwait(false);

            DispatcherQueue.TryEnqueue(() =>
            {
                try
                {
                    if (path is null)
                    {
                        ShowUserAvatarFallback();
                        return;
                    }

                    UserAvatarBrush.ImageSource = UserAvatarCache.CreateBitmapFromFile(path);
                    UserAvatarInitials.Visibility = Visibility.Collapsed;
                }
                catch (Exception ex)
                {
                    CrashReporter.ReportNonFatal(ex, "MainWindow.ApplyUserPaneFooter.ApplyImage");
                    ShowUserAvatarFallback();
                }
            });
        }
        catch (Exception ex)
        {
            CrashReporter.ReportNonFatal(ex, "MainWindow.ApplyUserPaneFooter");
            DispatcherQueue.TryEnqueue(ShowUserAvatarFallback);
        }
    }

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
                _accessPage ??= new AccessPage();
                NavFrame.Content = _accessPage;
                break;
            case "import":
                _importPage ??= new ImportPage(_homeController);
                NavFrame.Content = _importPage;
                break;
            case "statistics":
                _statisticsPage ??= new StatisticsPage(_authedApiHttp, App.Session);
                NavFrame.Content = _statisticsPage;
                break;
            case "settings":
                _settingsPage ??= new SettingsPage(_authState);
                NavFrame.Content = _settingsPage;
                break;
            default:
                _homePage ??= new HomePage(_homeController);
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
