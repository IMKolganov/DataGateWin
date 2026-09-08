using DataGateWin.Configuration;
using DataGateWin.Controllers;
using DataGateWin.CrashReporting;
using DataGateWin.Localization;
using DataGateWin.Models.Ipc;
using DataGateWin.Services.Traffic;
using DataGateWin.Services.Ui;
using DataGateWin.Services.VpnServers;
using DataGateWin.ViewModels;
using Microsoft.UI.Dispatching;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Media;

namespace DataGateWin.Pages.Home;

public sealed partial class HomePage : Page
{
    private readonly HomeController _controller;
    private readonly SemaphoreSlim _serverListLock = new(1, 1);
    private OpenVpnServersApiClient? _serversApi;
    private List<CachedVpnServerRow>? _cachedServerRows;
    private bool _suppressSettingsSave;
    private bool _suppressServerListFetch;
    private bool _languageHookAttached;
    private readonly List<string> _logLines = new();
    private readonly object _logUiLock = new();
    private bool _logFlushScheduled;
    private bool _logDirty;
    private DispatcherQueueTimer? _trafficTimer;
    private readonly LiveTrafficRateTracker _trafficRates = new();
    private readonly VpnAdapterTrafficSampler _trafficSampler = new();
    private bool _trafficFaultReported;

    public HomeLiveTrafficViewModel Traffic { get; }

    public HomePage(HomeController controller)
    {
        Traffic = new HomeLiveTrafficViewModel();
        InitializeComponent();
        _controller = controller;
        try { TrafficChart.AnimationsSpeed = TimeSpan.Zero; }
        catch (Exception ex) { CrashReporter.ReportNonFatal(ex, "HomePage.TrafficChartInit"); }
        ApplyLocalizedChrome();
    }

    private void ApplyLocalizedChrome()
    {
        WelcomeTitle.Text = Loc.T("Home_WelcomeTitle");
        ConnectionStatusLabel.Text = Loc.T("Home_ConnectionStatus");
        VpnServerLabel.Text = Loc.T("Home_VpnServer");
        ServerLabel.Text = Loc.T("Home_Server");
        NetworkServerLabel.Text = Loc.T("Home_Network_Server") + ":";
        RefreshServersButtonText.Text = Loc.T("Home_Refresh");
        ConnectButtonText.Text = Loc.T("Home_Connect");
        DisconnectButtonText.Text = Loc.T("Home_Disconnect");
        TrafficTitle.Text = Loc.T("Home_Traffic_Title");
        ShowEngineLogsCheck.Content = Loc.T("Home_ShowEngineLogs");
        Traffic.ApplyChrome();
        Bindings.Update();

        var prev = ServerModeCombo.SelectedIndex;
        ServerModeCombo.Items.Clear();
        ServerModeCombo.Items.Add(Loc.T("Home_ModeAuto"));
        ServerModeCombo.Items.Add(Loc.T("Home_ModeManual"));
        ServerModeCombo.SelectedIndex = prev < 0 ? 0 : prev;
    }

    private async void HomePage_OnLoaded(object sender, RoutedEventArgs e)
    {
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
        StartTrafficTimer();

        _controller.AttachUi(
            statusTextSetter: s => DispatchUi(() => StatusText.Text = s),
            uiStateApplier: (state, status, network) => DispatchUi(() => ApplyUiState(state, status, network)),
            // AppendLog is thread-safe; do not DispatchUi per line (route floods enqueue thousands of UI jobs).
            logAppender: AppendLog);

        _suppressServerListFetch = true;
        try
        {
            RestoreVpnHomeSettingsFromStore();
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
        RebuildServerComboFromCache();
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
        => DispatchUi(() =>
        {
            ApplyLocalizedChrome();
            RebuildServerComboFromCache();
            _controller.ReapplyUiToLastState();
        });

    private async void ConnectButton_OnClick(object sender, RoutedEventArgs e)
    {
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
            StatusText.Text = Loc.T("Home_Status_IdleErrorFmt", human);
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
            StatusText.Text = Loc.T("Home_Status_IdleErrorFmt", human);
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

        // ApplyUiState leaves ManualServerCombo disabled while mode is Auto.
        // Switching to Manual must re-apply so the combo becomes enabled even when
        // the server list is already cached (otherwise Refresh looks "required").
        _controller.ReapplyUiToLastState();

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
            StatusText.Text = UiSafeText.ForStatus(statusText);

            var isBusy = state is UiState.Connecting or UiState.Disconnecting;
            var idle = state == UiState.Idle;
            ConnectButton.IsEnabled = !isBusy && idle;
            DisconnectButton.IsEnabled = !isBusy && state is UiState.Connected or UiState.Connecting;
            var canPickServer = !isBusy && idle;
            ServerModeCombo.IsEnabled = canPickServer;
            ManualServerCombo.IsEnabled = canPickServer && ServerModeCombo.SelectedIndex == 1;
            RefreshServersButton.IsEnabled = canPickServer;
            ApplyNetworkInfo(network);
        }
        catch (Exception ex)
        {
            CrashReporter.ReportNonFatal(ex, "HomePage.ApplyUiState");
            try { StatusText.Text = UiSafeText.ForStatus(statusText ?? Loc.T("Home_Status_Idle")); } catch { /* ignore */ }
            try
            {
                ConnectButton.IsEnabled = true;
                DisconnectButton.IsEnabled = false;
            }
            catch { /* ignore */ }
        }
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
            try
            {
                var flag = ServerNameUi.TryGetFlagImage(server);
                NetworkServerFlag.Source = flag;
                NetworkServerFlag.Visibility = flag is null ? Visibility.Collapsed : Visibility.Visible;
                NetworkServerName.Text = ServerNameFlag.TrySplit(server, out _, out var rest) && !string.IsNullOrEmpty(rest)
                    ? rest
                    : server;
            }
            catch (Exception ex)
            {
                CrashReporter.ReportNonFatal(ex, "HomePage.ApplyNetworkInfo.Flag");
                NetworkServerFlag.Source = null;
                NetworkServerFlag.Visibility = Visibility.Collapsed;
                NetworkServerName.Text = server;
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
        }
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
                    LogTextBox.Text = text;
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
        => ManualServerRow.Visibility = ServerModeCombo.SelectedIndex == 1 ? Visibility.Visible : Visibility.Collapsed;

    private void ShowEngineLogsCheck_OnClick(object sender, RoutedEventArgs e)
    {
        ApplyEngineLogVisibility();
        SaveVpnHomeSettingsFromUi();
    }

    private void ApplyEngineLogVisibility()
    {
        var show = ShowEngineLogsCheck.IsChecked == true;
        LogTextBox.Visibility = show ? Visibility.Visible : Visibility.Collapsed;

        if (!show)
            return;

        string text;
        lock (_logUiLock)
            text = CrashReporting.InMemoryLogBudget.JoinLinesForTextBox(_logLines);
        LogTextBox.Text = text;
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
            ServerModeCombo.SelectedIndex = s.HomeVpnAutoPickServer ? 0 : 1;
            ShowEngineLogsCheck.IsChecked = s.HomeShowEngineLogs;
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
        s.HomeVpnAutoPickServer = ServerModeCombo.SelectedIndex <= 0;
        s.HomeShowEngineLogs = ShowEngineLogsCheck.IsChecked == true;
        if (ManualServerCombo.SelectedItem is HomeVpnServerListItem mid && mid.Id > 0)
            s.HomeVpnManualServerId = mid.Id;
        else if (!s.HomeVpnAutoPickServer && ManualServerCombo.SelectedItem is not null)
            s.HomeVpnManualServerId = 0;

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
        var flagImage = ServerNameUi.TryGetFlagImage(rawName);
        return new HomeVpnServerListItem
        {
            Id = r.Id,
            FlagImage = flagImage,
            FlagVisibility = flagImage is null ? Visibility.Collapsed : Visibility.Visible,
            Label = label,
        };
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

    private sealed class HomeVpnServerListItem
    {
        public int Id { get; init; }
        public ImageSource? FlagImage { get; init; }
        public Visibility FlagVisibility { get; init; }
        public string Label { get; init; } = "";
        public override string ToString() => Label;
    }
}
