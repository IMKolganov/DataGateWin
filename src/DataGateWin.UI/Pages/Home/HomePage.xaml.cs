using DataGateWin.Configuration;
using DataGateWin.Controllers;
using DataGateWin.CrashReporting;
using DataGateWin.Localization;
using DataGateWin.Models.Ipc;
using DataGateWin.Services.Traffic;
using DataGateWin.Services.Ui;
using DataGateWin.Services.VpnServers;
using DataGateWin.Services.Profiles;
using DataGateWin.ViewModels;
using DataGateWin.Views;
using Microsoft.UI.Dispatching;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Media;
using Microsoft.UI.Text;
using System.Text.RegularExpressions;

namespace DataGateWin.Pages.Home;

public sealed partial class HomePage : Page
{
    private readonly HomeController _controller;
    private readonly SemaphoreSlim _serverListLock = new(1, 1);
    private OpenVpnServersApiClient? _serversApi;
    private List<CachedVpnServerRow>? _cachedServerRows;
    private bool _suppressSettingsSave;
    private bool _suppressServerListFetch;
    private bool _suppressEngineLogsToggle;
    private bool _languageHookAttached;
    private readonly List<string> _logLines = new();
    private readonly object _logUiLock = new();
    private bool _logFlushScheduled;
    private bool _logDirty;
    private string? _renderedLogText;
    private DispatcherQueueTimer? _trafficTimer;
    private readonly LiveTrafficRateTracker _trafficRates = new();
    private readonly VpnAdapterTrafficSampler _trafficSampler = new();
    private bool _trafficFaultReported;

    public HomeLiveTrafficViewModel Traffic { get; }

    public HomePage(HomeController controller)
    {
        Traffic = new HomeLiveTrafficViewModel();
        InitializeComponent();
        LogTextBox.ActualThemeChanged += (_, _) =>
        {
            _renderedLogText = null;
            if (LogTextBox.Visibility == Visibility.Visible)
            {
                string text;
                lock (_logUiLock)
                    text = CrashReporting.InMemoryLogBudget.JoinLinesForTextBox(_logLines);
                RenderLogs(text);
            }
        };
        UiThemeBrushes.ApplyMissingCardChrome(this);
        UiThemeBrushes.ApplyCardBackground(TrafficLogsCard);
        _controller = controller;
        try
        {
            TrafficChart.FlowDirection = FlowDirection.LeftToRight;
            TrafficChart.AnimationsSpeed = TimeSpan.Zero;
        }
        catch (Exception ex) { CrashReporter.ReportNonFatal(ex, "HomePage.TrafficChartInit"); }
        ApplyLocalizedChrome();
    }

    private void ApplyLocalizedChrome()
    {
        WelcomeTitle.Text = Loc.T("Home_WelcomeTitle");
        ConnectionStatusLabel.Text = Loc.T("Home_ConnectionStatus");
        VpnServerLabel.Text = Loc.T("Home_VpnServer");
        ServerLabel.Text = Loc.T("Home_Server");
        ImportedProfileLabel.Text = Loc.T("Home_ImportedProfile");
        NetworkServerLabel.Text = Loc.T("Home_Network_Server") + ":";
        RefreshServersButtonText.Text = Loc.T("Home_Refresh");
        RefreshImportedButtonText.Text = Loc.T("Home_Refresh");
        ConnectButtonText.Text = Loc.T("Home_Connect");
        DisconnectButtonText.Text = Loc.T("Home_Disconnect");
        TrafficTitle.Text = Loc.T("Home_Traffic_Title");
        EngineLogsLabel.Text = Loc.T("Home_ShowEngineLogs");
        DetailsHeaderText.Text = Loc.T("Home_Details");
        StatusHeadline.Text = Loc.T("Home_Status_Idle");
        Traffic.ApplyChrome();
        Bindings.Update();

        var prev = ServerModeCombo.SelectedIndex;
        ServerModeCombo.Items.Clear();
        ServerModeCombo.Items.Add(Loc.T("Home_ModeAuto"));
        ServerModeCombo.Items.Add(Loc.T("Home_ModeManual"));
        ServerModeCombo.Items.Add(Loc.T("Home_ModeImported"));
        ServerModeCombo.SelectedIndex = prev < 0 ? 0 : Math.Min(prev, 2);
    }

    private async void HomePage_OnLoaded(object sender, RoutedEventArgs e)
    {
        UiThemeBrushes.ApplyMissingCardChrome(this);
        if (!_languageHookAttached)
        {
            WinUiLanguageService.LanguageChanged += OnUiLanguageChanged;
            _languageHookAttached = true;
        }

        ApplyLocalizedChrome();

        _serversApi ??= new OpenVpnServersApiClient(App.AuthedApiHttp);

        Traffic.SetChartTheme(ActualTheme == ElementTheme.Dark);
        ActualThemeChanged -= HomePage_OnActualThemeChanged;
        ActualThemeChanged += HomePage_OnActualThemeChanged;
        ApplyTrafficVisibility(UiState.Idle);

        _controller.AttachUi(
            statusTextSetter: s => DispatchUi(() => SetStatusDetail(s)),
            uiStateApplier: (state, status, network) => DispatchUi(() => ApplyUiState(state, status, network)),
            // AppendLog is thread-safe; do not DispatchUi per line (route floods enqueue thousands of UI jobs).
            logAppender: AppendLog);

        _suppressServerListFetch = true;
        try
        {
            RestoreVpnHomeSettingsFromStore();
            RebuildImportedProfileCombo();
            UpdateManualRowVisibility();
        }
        finally
        {
            _suppressServerListFetch = false;
        }

        await EnsureAccessTokenForApiAsync();

        if (HomeServerListLoadPolicy.ShouldForceRefreshOnHomeLoaded(_suppressServerListFetch))
            await EnsureManualServerListReadyAsync(forceRefresh: true);

        try
        {
            await _controller.OnLoadedAsync();
        }
        catch (Exception ex)
        {
            CrashReporter.ReportNonFatal(ex, "HomePage.OnLoaded");
            _controller.AppendLogLine(Loc.T("Home_Log_EngineAttachFmt", VpnUserFacingError.FromException(ex)));
        }
    }

    /// <summary>
    /// Nav switched back to Home. Frame Content swap does not always re-run Loaded;
    /// refresh the server list when cache is empty (same policy as WPF IsVisibleChanged).
    /// </summary>
    public async Task RefreshOnShownAsync()
    {
        ApplyLocalizedChrome();
        RestoreVpnHomeSettingsFromStore();
        RebuildServerComboFromCache();
        RebuildImportedProfileCombo();
        UpdateManualRowVisibility();
        _controller.ReapplyUiToLastState();

        if (!IsLoaded)
            return;

        var hasCache = _cachedServerRows is { Count: > 0 };
        if (!HomeServerListLoadPolicy.ShouldFetchOnBecameVisible(
                isVisible: true,
                isLoaded: true,
                suppressFetch: _suppressServerListFetch,
                hasCachedServers: hasCache))
            return;

        await EnsureAccessTokenForApiAsync();
        await EnsureManualServerListReadyAsync(forceRefresh: false);
    }

    private void HomePage_OnUnloaded(object sender, RoutedEventArgs e)
    {
        if (_languageHookAttached)
        {
            WinUiLanguageService.LanguageChanged -= OnUiLanguageChanged;
            _languageHookAttached = false;
        }

        SaveVpnHomeSettingsFromUi();
        StopTrafficTimer();
        ActualThemeChanged -= HomePage_OnActualThemeChanged;
        _controller.OnUnloaded();
    }

    private void HomePage_OnActualThemeChanged(FrameworkElement sender, object args)
        => Traffic.SetChartTheme(ActualTheme == ElementTheme.Dark);

    private void OnUiLanguageChanged(object? sender, EventArgs e)
        => DispatcherQueue.TryEnqueue(() =>
        {
            try
            {
                ApplyLocalizedChrome();
                RelocalizeServerComboLabels();
                RebuildImportedProfileCombo();
                WinUiLanguageService.ForceChartsLeftToRight(this);
                Traffic.ApplyChrome();
                _controller.ReapplyUiToLastState();
            }
            catch (Exception ex)
            {
                CrashReporter.ReportNonFatal(ex, "HomePage.OnUiLanguageChanged");
            }
        });

    private async void ConnectButton_OnClick(object sender, RoutedEventArgs e)
    {
        if (ServerModeCombo.SelectedIndex == 2)
        {
            await ConnectImportedFromHomeAsync();
            return;
        }

        var autoPick = ServerModeCombo.SelectedIndex <= 0;
        int? manualId = null;
        if (!autoPick)
        {
            if (ManualServerCombo.SelectedItem is not HomeVpnServerListItem item || item.Id <= 0)
            {
                if (Content?.XamlRoot is { } root)
                {
                    await new ContentDialog
                    {
                        Title = Loc.T("Msg_ChooseServerTitle"),
                        Content = Loc.T("Msg_ChooseServerBody"),
                        CloseButtonText = Loc.T("Action_Ok"),
                        XamlRoot = root,
                    }.ShowAsync();
                }
                return;
            }

            manualId = item.Id;
        }

        SaveVpnHomeSettingsFromUi();
        ConnectButton.IsEnabled = false;
        try
        {
            // Keep click-handler off the heavy path; controller uses ConfigureAwait(false).
            await _controller.ConnectAsync(autoPick, manualId).ConfigureAwait(true);
        }
        catch (Exception ex)
        {
            CrashReporter.ReportNonFatal(ex, "HomePage.ConnectClick");
            var human = VpnUserFacingError.FromException(ex);
            SetStatusDetail(Loc.T("Home_Status_IdleErrorFmt", human));
            AppendLog(Loc.T("Home_Log_ErrorFmt", human));
        }
        finally
        {
            _controller.ReapplyUiToLastState();
        }
    }

    private async Task ConnectImportedFromHomeAsync()
    {
        if (ImportedProfileCombo.SelectedItem is not HomeImportedProfileListItem item || item.Id == Guid.Empty)
        {
            if (Content?.XamlRoot is { } root)
            {
                await new ContentDialog
                {
                    Title = Loc.T("Msg_ChooseImportedTitle"),
                    Content = Loc.T("Msg_ChooseImportedBody"),
                    CloseButtonText = Loc.T("Action_Ok"),
                    XamlRoot = root,
                }.ShowAsync();
            }
            return;
        }

        var profile = _controller.ListImportedProfiles().FirstOrDefault(p => p.Id == item.Id);
        if (profile is null)
        {
            SetStatusDetail(Loc.T("Import_Log_ProfileMissing"));
            return;
        }

        var (proceed, creds) = await OpenVpnAuthDialog.TryPromptAsync(XamlRoot, profile);
        if (!proceed)
            return;

        if (creds is not null)
            _controller.RememberImportedAuthUsername(profile.Id, creds.Username);

        SaveVpnHomeSettingsFromUi();
        ConnectButton.IsEnabled = false;
        try
        {
            await _controller.ConnectImportedProfileAsync(profile.Id, creds).ConfigureAwait(true);
        }
        catch (Exception ex)
        {
            CrashReporter.ReportNonFatal(ex, "HomePage.ConnectImported");
            var human = VpnUserFacingError.FromException(ex);
            SetStatusDetail(Loc.T("Home_Status_IdleErrorFmt", human));
            AppendLog(Loc.T("Home_Log_ErrorFmt", human));
        }
        finally
        {
            _controller.ReapplyUiToLastState();
        }
    }

    private async void DisconnectButton_OnClick(object sender, RoutedEventArgs e)
    {
        DisconnectButton.IsEnabled = false;
        try
        {
            await _controller.DisconnectAsync().ConfigureAwait(true);
        }
        catch (Exception ex)
        {
            CrashReporter.ReportNonFatal(ex, "HomePage.DisconnectClick");
            var human = VpnUserFacingError.FromException(ex);
            SetStatusDetail(Loc.T("Home_Status_IdleErrorFmt", human));
            AppendLog(Loc.T("Home_Log_ErrorFmt", human));
        }
        finally
        {
            _controller.ReapplyUiToLastState();
        }
    }

    private async void ServerModeCombo_OnSelectionChanged(object sender, SelectionChangedEventArgs e)
    {
        UpdateManualRowVisibility();
        SaveVpnHomeSettingsFromUi();

        _controller.ReapplyUiToLastState();

        if (!_suppressSettingsSave && ServerModeCombo.SelectedIndex == 2)
            RebuildImportedProfileCombo();

        var hasCache = _cachedServerRows is { Count: > 0 };
        if (ServerModeCombo.SelectedIndex == 1 && hasCache && ManualServerCombo.Items.Count == 0)
            RebuildServerComboFromCache();

        if (!HomeServerListLoadPolicy.ShouldFetchOnManualModeSelected(
                suppressFetch: _suppressServerListFetch,
                isLoaded: IsLoaded,
                isManualMode: ServerModeCombo.SelectedIndex == 1,
                hasCachedServers: hasCache))
            return;

        await EnsureManualServerListReadyAsync(forceRefresh: false);
    }

    private void ManualServerCombo_OnSelectionChanged(object sender, SelectionChangedEventArgs e)
        => SaveVpnHomeSettingsFromUi();

    private void ImportedProfileCombo_OnSelectionChanged(object sender, SelectionChangedEventArgs e)
        => SaveVpnHomeSettingsFromUi();

    private void RefreshImportedButton_OnClick(object sender, RoutedEventArgs e)
        => RebuildImportedProfileCombo();

    private async void RefreshServersButton_OnClick(object sender, RoutedEventArgs e)
        => await EnsureManualServerListReadyAsync(forceRefresh: true);

    private async Task EnsureManualServerListReadyAsync(bool forceRefresh)
    {
        RefreshServersButton.IsEnabled = false;
        ManualServerCombo.IsEnabled = false;
        try
        {
            await EnsureAccessTokenForApiAsync();
            await RefreshServerListAsync(forceRefresh);
            ApplyManualSelectionFromSettings();
            SaveVpnHomeSettingsFromUi();
        }
        finally
        {
            _controller.ReapplyUiToLastState();
        }
    }

    private void ApplyManualSelectionFromSettings()
    {
        _suppressSettingsSave = true;
        try
        {
            var keepId = App.Settings.HomeVpnManualServerId;
            if (keepId > 0)
            {
                foreach (HomeVpnServerListItem item in ManualServerCombo.Items)
                {
                    if (item.Id == keepId)
                    {
                        ManualServerCombo.SelectedItem = item;
                        break;
                    }
                }
            }
            else if (ManualServerCombo.SelectedIndex < 0 && ManualServerCombo.Items.Count > 0)
                ManualServerCombo.SelectedIndex = 0;
        }
        finally
        {
            _suppressSettingsSave = false;
        }
    }

    private void ApplyUiState(UiState state, string statusText, VpnConnectionSessionInfo? network)
    {
        try
        {
            // Plain Text — SetTextEnlargingFlags builds one Inline per grapheme and
            // FailFasts WinUI (E_INVALIDARG / CoreMessaging) on long engine errors.
            SetStatusDetail(UiSafeText.ForStatus(statusText));

            var isBusy = state is UiState.Connecting or UiState.Disconnecting;
            var idle = state == UiState.Idle;
            ApplyHeroState(state);
            ConnectButton.IsEnabled = HomeSessionUiPolicy.IsHomeConnectEnabled(state);
            DisconnectButton.IsEnabled = HomeSessionUiPolicy.IsHomeDisconnectEnabled(state);
            var canPickServer = !isBusy && idle;
            ServerModeCombo.IsEnabled = canPickServer;
            ManualServerCombo.IsEnabled = canPickServer && ServerModeCombo.SelectedIndex == 1;
            ImportedProfileCombo.IsEnabled = canPickServer && ServerModeCombo.SelectedIndex == 2;
            RefreshServersButton.IsEnabled = canPickServer && ServerModeCombo.SelectedIndex == 1;
            RefreshImportedButton.IsEnabled = canPickServer && ServerModeCombo.SelectedIndex == 2;
            ApplyNetworkInfo(network);
            ApplyTrafficVisibility(state);
        }
        catch (Exception ex)
        {
            CrashReporter.ReportNonFatal(ex, "HomePage.ApplyUiState");
            try { SetStatusDetail(UiSafeText.ForStatus(statusText ?? Loc.T("Home_Status_Idle"))); } catch { /* ignore */ }
            try
            {
                ConnectButton.IsEnabled = true;
                DisconnectButton.IsEnabled = false;
            }
            catch { /* ignore */ }
            AppendLog(Loc.T("Home_Log_ErrorFmt", VpnUserFacingError.FromException(ex)));
        }
    }

    private void ApplyHeroState(UiState state)
    {
        StatusHeadline.Text = state switch
        {
            UiState.Connected => Loc.T("Home_Status_Connected"),
            UiState.Connecting => Loc.T("Home_Status_Connecting"),
            UiState.Disconnecting => Loc.T("Home_Status_Disconnecting"),
            _ => Loc.T("Home_Status_Idle"),
        };
        var color = state switch
        {
            UiState.Connected => Windows.UI.Color.FromArgb(255, 0x3D, 0xC0, 0x5C),
            UiState.Connecting or UiState.Disconnecting => Windows.UI.Color.FromArgb(255, 0xE0, 0xA0, 0x30),
            _ => Windows.UI.Color.FromArgb(255, 0x8A, 0x8A, 0x8A),
        };
        StatusDot.Fill = new Microsoft.UI.Xaml.Media.SolidColorBrush(color);
        // One action at a time: Connect while idle, Disconnect for every other state.
        ConnectButton.Visibility = state == UiState.Idle ? Visibility.Visible : Visibility.Collapsed;
        DisconnectButton.Visibility = state == UiState.Idle ? Visibility.Collapsed : Visibility.Visible;
        SetStatusDetail(StatusText.Text);
    }

    /// <summary>Detail line under the headline; hidden when it only repeats the headline.</summary>
    private void SetStatusDetail(string? text)
    {
        var s = text ?? "";
        StatusText.Text = s;
        var head = StatusHeadline.Text ?? "";
        StatusText.Visibility = string.IsNullOrWhiteSpace(s)
            || string.Equals(s.Trim(), head.Trim(), StringComparison.OrdinalIgnoreCase)
            ? Visibility.Collapsed
            : Visibility.Visible;
    }

    private void ApplyNetworkInfo(VpnConnectionSessionInfo? network)
    {
        try
        {
            var show = network is { HasIdentity: true };
            NetworkInfoPanel.Visibility = show ? Visibility.Visible : Visibility.Collapsed;
            if (!show)
                return;

            var dash = Loc.T("Home_Network_Unavailable");
            var server = string.IsNullOrWhiteSpace(network!.ServerName) ? dash : network.ServerName;
            NetworkServerLabel.Text = Loc.T("Home_Network_Server") + ":";
            NetworkServerName.Text = ServerNameFlag.TrySplit(server, out _, out var rest) && !string.IsNullOrEmpty(rest)
                ? rest
                : server;
            try
            {
                var flag = ServerNameUi.TryGetFlagImage(server);
                if (!UiSafeImage.TryAssign(NetworkServerFlag, flag, "HomePage.ApplyNetworkInfo.Flag"))
                    AppendLog(Loc.T("Home_Log_ErrorFmt", Loc.T("Home_Error_UiImage")));
            }
            catch (Exception ex)
            {
                CrashReporter.ReportNonFatal(ex, "HomePage.ApplyNetworkInfo.Flag");
                UiSafeImage.TryAssign(NetworkServerFlag, null, "HomePage.ApplyNetworkInfo.FlagClear");
                AppendLog(Loc.T("Home_Log_ErrorFmt", Loc.T("Home_Error_UiImage")));
            }

            NetworkVpnIpText.Text = Loc.T("Home_Network_VpnIp") + ": " +
                (string.IsNullOrWhiteSpace(network.VpnIp) ? dash : network.VpnIp!);
            NetworkExternalIpText.Text = Loc.T("Home_Network_ExternalIp") + ": " +
                (string.IsNullOrWhiteSpace(network.ExternalIp) ? dash : network.ExternalIp!);
            var dns = network.DnsServers is { Count: > 0 }
                ? string.Join(", ", network.DnsServers)
                : dash;
            NetworkDnsText.Text = Loc.T("Home_Network_Dns") + ": " + dns;
        }
        catch (Exception ex)
        {
            CrashReporter.ReportNonFatal(ex, "HomePage.ApplyNetworkInfo");
            try { UiSafeImage.TryAssign(NetworkServerFlag, null, "HomePage.ApplyNetworkInfo.Clear"); }
            catch { /* ignore */ }
            AppendLog(Loc.T("Home_Log_ErrorFmt", VpnUserFacingError.FromException(ex)));
        }
    }

    private void NetworkServerFlag_OnImageFailed(object sender, ExceptionRoutedEventArgs e)
    {
        UiSafeImage.TryAssign(NetworkServerFlag, null, "HomePage.FlagImageFailed");
        AppendLog(Loc.T("Home_Log_ErrorFmt", Loc.T("Home_Error_UiImage")));
    }

    private void AppendLog(string line)
    {
        if (string.IsNullOrWhiteSpace(line))
            return;

        var ts = DateTime.Now.ToString("HH:mm:ss");
        var chunk = $"[{ts}] {line}";

        lock (_logUiLock)
        {
            CrashReporting.InMemoryLogBudget.AppendLine(_logLines, chunk);
            _logDirty = true;
            if (_logFlushScheduled)
                return;
            _logFlushScheduled = true;
        }

        ScheduleLogFlush();
    }

    private void ScheduleLogFlush()
    {
        // Coalesce floods — rebuilding TextBox.Text per line freezes WinUI ("Not Responding").
        void StartTimer()
        {
            var flushTimer = DispatcherQueue.CreateTimer();
            flushTimer.Interval = TimeSpan.FromMilliseconds(400);
            flushTimer.IsRepeating = false;
            flushTimer.Tick += (_, _) =>
            {
                flushTimer.Stop();
                string text;
                lock (_logUiLock)
                {
                    _logFlushScheduled = false;
                    if (!_logDirty)
                        return;
                    _logDirty = false;
                    text = CrashReporting.InMemoryLogBudget.JoinLinesForTextBox(_logLines);
                }

                if (LogTextBox.Visibility == Visibility.Visible)
                    RenderLogs(text);
            };
            flushTimer.Start();
        }

        try
        {
            if (DispatcherQueue.HasThreadAccess)
                StartTimer();
            else
                DispatcherQueue.TryEnqueue(() =>
                {
                    try { StartTimer(); }
                    catch (Exception ex) { CrashReporter.ReportNonFatal(ex, "HomePage.ScheduleLogFlush.Enqueue"); }
                });
        }
        catch (Exception ex)
        {
            CrashReporter.ReportNonFatal(ex, "HomePage.ScheduleLogFlush");
            lock (_logUiLock) { _logFlushScheduled = false; }
        }
    }

    private void DispatchUi(Action action)
    {
        void Safe()
        {
            try { action(); }
            catch (Exception ex) { CrashReporter.ReportNonFatal(ex, "HomePage.DispatchUi"); }
        }

        try
        {
            if (DispatcherQueue.HasThreadAccess)
                Safe();
            else
                DispatcherQueue.TryEnqueue(Safe);
        }
        catch (Exception ex)
        {
            CrashReporter.ReportNonFatal(ex, "HomePage.DispatchUi.Enqueue");
        }
    }

    private void UpdateManualRowVisibility()
    {
        ManualServerRow.Visibility = ServerModeCombo.SelectedIndex == 1 ? Visibility.Visible : Visibility.Collapsed;
        ImportedProfileRow.Visibility = ServerModeCombo.SelectedIndex == 2 ? Visibility.Visible : Visibility.Collapsed;
    }

    private void ShowEngineLogsToggle_OnToggled(object sender, RoutedEventArgs e)
    {
        if (_suppressEngineLogsToggle)
            return;
        ApplyEngineLogVisibility();
        SaveVpnHomeSettingsFromUi();
    }

    private void ApplyEngineLogVisibility()
    {
        var show = ShowEngineLogsToggle.IsOn;
        LogTextBox.Visibility = show ? Visibility.Visible : Visibility.Collapsed;

        if (!show)
            return;

        string text;
        lock (_logUiLock)
            text = CrashReporting.InMemoryLogBudget.JoinLinesForTextBox(_logLines);
        RenderLogs(text);
        DispatcherQueue.TryEnqueue(() =>
        {
            try
            {
                LogTextBox.UpdateLayout();
                LogTextBox.StartBringIntoView();
            }
            catch (Exception ex)
            {
                CrashReporter.ReportNonFatal(ex, "HomePage.BringEngineLogIntoView");
            }
        });
    }

    private static readonly Regex LogErrorPattern = new(
        @"\b(fatal|failed|failure|exception|auth_failed|access_denied)\b|\berror\b(?!""?\s*[:=]\s*(?:null|false|0)\b)|\berr\s*=\s*[1-9]\d*\b|ошибк|не удалось",
        RegexOptions.IgnoreCase | RegexOptions.CultureInvariant | RegexOptions.Compiled);

    private static readonly Regex LogTagPattern = new(
        @"\G\s*\[[a-z][a-z0-9_-]*\]",
        RegexOptions.IgnoreCase | RegexOptions.CultureInvariant | RegexOptions.Compiled);
    private static readonly Regex LogWarningPattern = new(
        @"\b(warn|warning|retry|retrying|timeout|timed out)\b|предупрежд",
        RegexOptions.IgnoreCase | RegexOptions.CultureInvariant | RegexOptions.Compiled);

    private static readonly Regex LogSuccessPattern = new(
        @"\b(UI attached|Engine connected|connect OK|client connected|Initialization Sequence Completed|success|succeeded)\b",
        RegexOptions.IgnoreCase | RegexOptions.CultureInvariant | RegexOptions.Compiled);

    private static readonly Regex LogFieldPattern = new(
        @"\b[a-zA-Z][a-zA-Z0-9_]*(?==)",
        RegexOptions.CultureInvariant | RegexOptions.Compiled);

    private void RenderLogs(string text)
    {
        if (text == _renderedLogText)
            return;

        // RichEdit uses one CR per paragraph; use its offsets when coloring ranges.
        var content = text.Replace("\r\n", "\n").Replace('\r', '\n').Replace('\n', '\r');
        var dark = LogTextBox.ActualTheme == ElementTheme.Dark;
        var normal = dark ? Microsoft.UI.Colors.Gainsboro : Microsoft.UI.Colors.Black;
        var timestamp = dark ? Microsoft.UI.Colors.CornflowerBlue : Microsoft.UI.Colors.RoyalBlue;
        var success = dark ? Microsoft.UI.Colors.LightGreen : Microsoft.UI.Colors.DarkGreen;
        var fieldColor = dark ? Microsoft.UI.Colors.Silver : Microsoft.UI.Colors.DimGray;
        var engineColor = dark ? Microsoft.UI.Colors.Plum : Microsoft.UI.Colors.DarkMagenta;
        var ipcColor = dark ? Microsoft.UI.Colors.Turquoise : Microsoft.UI.Colors.Teal;
        var dnsColor = dark ? Microsoft.UI.Colors.PeachPuff : Microsoft.UI.Colors.SaddleBrown;
        var error = dark ? Microsoft.UI.Colors.LightCoral : Microsoft.UI.Colors.Firebrick;
        var warning = dark ? Microsoft.UI.Colors.Khaki : Microsoft.UI.Colors.SaddleBrown;
        var tagColor = dark ? Microsoft.UI.Colors.LightSkyBlue : Microsoft.UI.Colors.SteelBlue;
        var selection = LogTextBox.Document.Selection;
        var selectionStart = selection.StartPosition;
        var selectionEnd = selection.EndPosition;
        // RichEdit protects formatting as well as text when IsReadOnly is set.
        // Temporarily allow document edits on the UI thread, restoring protection
        // even if a document operation throws. No input can interleave here.
        var wasReadOnly = LogTextBox.IsReadOnly;
        LogTextBox.IsReadOnly = false;
        try
        {
            LogTextBox.Document.SetText(TextSetOptions.None, content);
            var format = LogTextBox.Document.GetRange(0, content.Length).CharacterFormat;
            format.ForegroundColor = normal;
            format.Bold = FormatEffect.Off;

            var offset = 0;
            foreach (var line in content.Split('\r'))
            {
                // An explicit WARNING may describe a possible failure, not an actual one.
                var isWarning = LogWarningPattern.IsMatch(line);
                var isError = !isWarning && LogErrorPattern.IsMatch(line);
                var isSuccess = !isWarning && !isError &&
                    (LogSuccessPattern.IsMatch(line) || line.EndsWith(Loc.T("Home_Log_UiAttached"), StringComparison.Ordinal));
                var color = isWarning ? warning : isError ? error : isSuccess ? success : normal;
                if (line.Length > 0)
                    LogTextBox.Document.GetRange(offset, offset + line.Length).CharacterFormat.ForegroundColor = color;
                // The timestamp added by AppendLog is always [HH:mm:ss].
                if (line.Length >= 10 && line[0] == '[' && line[9] == ']')
                {
                    var timeFormat = LogTextBox.Document.GetRange(offset, offset + 10).CharacterFormat;
                    timeFormat.ForegroundColor = isSuccess ? success : timestamp;
                    // Tags remain distinguishable even on warning/error lines.
                    var tag = LogTagPattern.Match(line, 10);
                    while (tag.Success)
                    {
                        var label = tag.Value.Trim();
                        var tagFormat = LogTextBox.Document.GetRange(offset + tag.Index, offset + tag.Index + tag.Length).CharacterFormat;
                        tagFormat.ForegroundColor = label.ToLowerInvariant() switch
                        {
                            "[engine]" => engineColor,
                            "[ipc]" or "[control]" or "[events]" => ipcColor,
                            "[dns]" => dnsColor,
                            _ => tagColor,
                        };
                        tag = tag.NextMatch();
                    }
                }
                if (isWarning || isError || isSuccess)
                {
                    var pattern = isWarning ? LogWarningPattern : isError ? LogErrorPattern : LogSuccessPattern;
                    foreach (Match match in pattern.Matches(line))
                        LogTextBox.Document.GetRange(offset + match.Index, offset + match.Index + match.Length)
                            .CharacterFormat.Bold = FormatEffect.On;
                }
                else
                {
                    // Highlight metadata keys, leaving serialized payloads and paths intact.
                    var metadataEnd = line.IndexOf('{');
                    var metadata = metadataEnd >= 0 ? line[..metadataEnd] : line;
                    foreach (Match field in LogFieldPattern.Matches(metadata))
                        LogTextBox.Document.GetRange(offset + field.Index, offset + field.Index + field.Length)
                            .CharacterFormat.ForegroundColor = fieldColor;
                }
                offset += line.Length + 1;
            }
            selection.SetRange(Math.Min(selectionStart, content.Length), Math.Min(selectionEnd, content.Length));
            _renderedLogText = text;
        }
        finally
        {
            LogTextBox.IsReadOnly = wasReadOnly;
        }
    }

    /// <summary>Live traffic chart only while Connected — hidden on start / disconnect / connecting.</summary>
    private void ApplyTrafficVisibility(UiState state)
    {
        var show = HomeSessionUiPolicy.IsHomeTrafficVisible(state);
        try
        {
            TrafficPanel.Visibility = show ? Visibility.Visible : Visibility.Collapsed;
        }
        catch (Exception ex)
        {
            CrashReporter.ReportNonFatal(ex, "HomePage.ApplyTrafficVisibility");
        }

        if (show)
        {
            StartTrafficTimer();
            return;
        }

        StopTrafficTimer();
        try
        {
            _trafficRates.Reset();
            Traffic.ResetSeries();
            _trafficFaultReported = false;
        }
        catch (Exception ex)
        {
            CrashReporter.ReportNonFatal(ex, "HomePage.ResetTraffic");
        }
    }

    private void StartTrafficTimer()
    {
        if (_trafficTimer != null)
            return;

        var timer = DispatcherQueue.CreateTimer();
        timer.Interval = TimeSpan.FromSeconds(1);
        timer.IsRepeating = true;
        timer.Tick += TrafficTimer_OnTick;
        _trafficTimer = timer;
        timer.Start();
        SampleTraffic();
    }

    private void StopTrafficTimer()
    {
        var timer = _trafficTimer;
        if (timer == null)
            return;

        _trafficTimer = null;
        timer.Stop();
        timer.Tick -= TrafficTimer_OnTick;
    }

    private void TrafficTimer_OnTick(DispatcherQueueTimer sender, object args)
    {
        try { SampleTraffic(); }
        catch (Exception ex) { ShowTrafficFault(LiveTrafficError.LocKey(ex), ex); }
    }

    private void SampleTraffic()
    {
        try
        {
            var read = _trafficSampler.TryRead();
            if (read.Failed)
            {
                ShowTrafficFault(read.ErrorLocKey ?? LiveTrafficError.KeyGeneric, read.Error);
                return;
            }

            _trafficFaultReported = false;
            var tick = _trafficRates.Push(read.Counters, DateTime.UtcNow);
            Traffic.Push(tick);
        }
        catch (Exception ex)
        {
            ShowTrafficFault(LiveTrafficError.LocKey(ex), ex);
        }
    }

    private void ShowTrafficFault(string locKey, Exception? ex)
    {
        try
        {
            _trafficRates.Reset();
            Traffic.SetErrorFromKey(locKey);
        }
        catch (Exception uiEx)
        {
            CrashReporter.ReportNonFatal(uiEx, "HomePage.ShowTrafficFault.Ui");
        }

        if (_trafficFaultReported)
            return;

        _trafficFaultReported = true;
        if (ex is not null)
            CrashReporter.ReportNonFatal(ex, "HomePage.SampleTraffic");

        try
        {
            AppendLog(Loc.T("Home_Log_ErrorFmt", Loc.T(locKey)));
        }
        catch (Exception logEx)
        {
            CrashReporter.ReportNonFatal(logEx, "HomePage.ShowTrafficFault.Log");
        }
    }


    private void RestoreVpnHomeSettingsFromStore()
    {
        _suppressSettingsSave = true;
        try
        {
            var s = App.Settings;
            if (s.HomeVpnImportedProfileId is Guid importedId && importedId != Guid.Empty)
                ServerModeCombo.SelectedIndex = 2;
            else
                ServerModeCombo.SelectedIndex = s.HomeVpnAutoPickServer ? 0 : 1;
            _suppressEngineLogsToggle = true;
            ShowEngineLogsToggle.IsOn = s.HomeShowEngineLogs;
            _suppressEngineLogsToggle = false;
            ApplyEngineLogVisibility();
            UpdateManualRowVisibility();
        }
        finally
        {
            _suppressSettingsSave = false;
        }
    }

    private void SaveVpnHomeSettingsFromUi()
    {
        if (_suppressSettingsSave)
            return;

        var s = App.Settings;
        s.HomeShowEngineLogs = ShowEngineLogsToggle.IsOn;
        if (ServerModeCombo.SelectedIndex == 2)
        {
            s.HomeVpnAutoPickServer = false;
            if (ImportedProfileCombo.SelectedItem is HomeImportedProfileListItem imported)
                s.HomeVpnImportedProfileId = imported.Id;
        }
        else
        {
            s.HomeVpnImportedProfileId = null;
            s.HomeVpnAutoPickServer = ServerModeCombo.SelectedIndex <= 0;
            if (ManualServerCombo.SelectedItem is HomeVpnServerListItem mid && mid.Id > 0)
                s.HomeVpnManualServerId = mid.Id;
            else if (!s.HomeVpnAutoPickServer && ManualServerCombo.SelectedItem is not null)
                s.HomeVpnManualServerId = 0;
        }

        AppSettingsStore.SaveSafe(s);
    }

    private static async Task EnsureAccessTokenForApiAsync()
    {
        for (var i = 0; i < 50; i++)
        {
            var t = await App.Session.GetValidAccessTokenAsync(CancellationToken.None);
            if (!string.IsNullOrWhiteSpace(t))
                return;
            await Task.Delay(100);
        }
    }

    private async Task RefreshServerListAsync(bool forceRefresh)
    {
        if (!forceRefresh && _cachedServerRows is { Count: > 0 })
            return;

        await _serverListLock.WaitAsync();
        try
        {
            if (!forceRefresh && _cachedServerRows is { Count: > 0 })
                return;

            _serversApi ??= new OpenVpnServersApiClient(App.AuthedApiHttp);

            var fetchFailed = false;
            try
            {
                var resp = await _serversApi.GetAllWithStatusAsync(CancellationToken.None);
                var raw = resp.Data?.VpnServerWithStatuses;
                var eligible = WssServerSelector.FilterEligible(raw);
                _cachedServerRows = eligible
                    .Select(x =>
                    {
                        var srv = x.VpnServerResponses!.VpnServer;
                        return new CachedVpnServerRow
                        {
                            Id = srv.Id,
                            Name = srv.ServerName ?? "",
                            Clients = x.CountConnectedClients,
                            Online = srv.IsOnline,
                            IsXray = WssServerSelector.IsXrayWindowsSupported(srv),
                            IsOpenVpnDirect = WssServerSelector.IsOpenVpnDirect(srv),
                        };
                    })
                    .ToList();
            }
            catch (Exception ex)
            {
                CrashReporter.ReportNonFatal(ex, "HomePage.RefreshServerList");
                fetchFailed = true;
                _cachedServerRows = null;
                _controller.AppendLogLine(Loc.T("Home_Log_VpnListFmt", VpnUserFacingError.FromException(ex)));
            }

            var rows = _cachedServerRows;
            void ApplyList()
            {
                _suppressSettingsSave = true;
                try
                {
                    ManualServerCombo.Items.Clear();
                    if (rows is { Count: > 0 })
                    {
                        foreach (var r in rows)
                            ManualServerCombo.Items.Add(CreateServerListItem(r));
                    }
                    ApplyManualSelectionFromSettings();
                }
                finally
                {
                    _suppressSettingsSave = false;
                }

                if ((rows is null || rows.Count == 0) && !fetchFailed)
                    _controller.AppendLogLine(Loc.T("Home_Log_NoWss"));
            }

            DispatchUi(ApplyList);
        }
        finally
        {
            _serverListLock.Release();
        }
    }

    private void RebuildServerComboFromCache()
    {
        if (_cachedServerRows is null || _cachedServerRows.Count == 0)
            return;

        _suppressSettingsSave = true;
        try
        {
            var prev = (ManualServerCombo.SelectedItem as HomeVpnServerListItem)?.Id
                ?? App.Settings.HomeVpnManualServerId;
            ManualServerCombo.Items.Clear();
            foreach (var r in _cachedServerRows)
                ManualServerCombo.Items.Add(CreateServerListItem(r));

            if (prev > 0)
            {
                foreach (HomeVpnServerListItem item in ManualServerCombo.Items)
                {
                    if (item.Id == prev)
                    {
                        ManualServerCombo.SelectedItem = item;
                        break;
                    }
                }
            }
        }
        finally
        {
            _suppressSettingsSave = false;
        }
    }

    /// <summary>Refresh server row labels after language change without Items.Clear (FailFast-safe).</summary>
    private void RelocalizeServerComboLabels()
    {
        if (_cachedServerRows is null || _cachedServerRows.Count == 0)
            return;
        if (ManualServerCombo.Items.Count == 0)
        {
            RebuildServerComboFromCache();
            return;
        }

        var byId = _cachedServerRows.ToDictionary(r => r.Id);
        foreach (HomeVpnServerListItem item in ManualServerCombo.Items)
        {
            if (!byId.TryGetValue(item.Id, out var row))
                continue;
            item.Label = CreateServerListItem(row).Label;
        }

        // Force ComboBox to re-read ToString() without clearing the collection.
        var selected = ManualServerCombo.SelectedItem;
        _suppressSettingsSave = true;
        try
        {
            ManualServerCombo.SelectedItem = null;
            ManualServerCombo.SelectedItem = selected;
        }
        finally
        {
            _suppressSettingsSave = false;
        }
    }

    private static HomeVpnServerListItem CreateServerListItem(CachedVpnServerRow r)
    {
        var rawName = string.IsNullOrWhiteSpace(r.Name)
            ? Loc.T("Home_ServerFallbackFmt", r.Id)
            : r.Name;
        if (!ServerNameFlag.TrySplit(rawName, out _, out var nameWithoutFlag))
            nameWithoutFlag = rawName;

        var onOff = r.Online ? Loc.T("Common_Online") : Loc.T("Common_Offline");
        var displayName = r.IsXray
            ? $"{nameWithoutFlag} (Xray)"
            : r.IsOpenVpnDirect
                ? $"{nameWithoutFlag} (OpenVPN)"
                : nameWithoutFlag;
        var label = Loc.T("Home_ServerRowFmt", displayName, r.Clients, onOff);
        return new HomeVpnServerListItem
        {
            Id = r.Id,
            Label = label,
            Name = rawName,
            Clients = r.Clients,
            Online = r.Online,
            IsXray = r.IsXray,
        };
    }

    private void RebuildImportedProfileCombo()
    {
        _suppressSettingsSave = true;
        try
        {
            var keep = (ImportedProfileCombo.SelectedItem as HomeImportedProfileListItem)?.Id
                ?? App.Settings.HomeVpnImportedProfileId;
            ImportedProfileCombo.Items.Clear();
            foreach (var p in _controller.ListImportedProfiles())
            {
                var proto = p.Protocol == ImportedVpnProtocol.Xray
                    ? Loc.T("Import_Protocol_Xray")
                    : Loc.T("Import_Protocol_OpenVpn");
                ImportedProfileCombo.Items.Add(new HomeImportedProfileListItem
                {
                    Id = p.Id,
                    Label = Loc.T("Home_ImportedRowFmt", p.Name, proto),
                });
            }

            if (keep is Guid id && id != Guid.Empty)
            {
                foreach (HomeImportedProfileListItem item in ImportedProfileCombo.Items)
                {
                    if (item.Id == id)
                    {
                        ImportedProfileCombo.SelectedItem = item;
                        break;
                    }
                }
            }

            if (ImportedProfileCombo.SelectedIndex < 0 && ImportedProfileCombo.Items.Count > 0)
                ImportedProfileCombo.SelectedIndex = 0;
        }
        finally
        {
            _suppressSettingsSave = false;
        }
    }

    private sealed class CachedVpnServerRow
    {
        public int Id { get; init; }
        public string Name { get; init; } = "";
        public int Clients { get; init; }
        public bool Online { get; init; }
        public bool IsXray { get; init; }
        public bool IsOpenVpnDirect { get; init; }
    }

    public sealed class HomeVpnServerListItem
    {
        public int Id { get; init; }
        public string Label { get; set; } = "";
        public string Name { get; init; } = "";
        public int Clients { get; init; }
        public bool Online { get; init; }
        public bool IsXray { get; init; }
        public override string ToString() => Label;
    }

    private sealed class HomeImportedProfileListItem
    {
        public Guid Id { get; init; }
        public string Label { get; set; } = "";
        public override string ToString() => Label;
    }
}
