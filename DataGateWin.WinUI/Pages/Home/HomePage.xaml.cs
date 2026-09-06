using DataGateWin.Configuration;
using DataGateWin.Controllers;
using DataGateWin.CrashReporting;
using DataGateWin.Localization;
using DataGateWin.Models.Ipc;
using DataGateWin.Services.VpnServers;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;

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

    public HomePage(HomeController controller)
    {
        InitializeComponent();
        _controller = controller;
        ApplyLocalizedChrome();
    }

    private void ApplyLocalizedChrome()
    {
        WelcomeTitle.Text = Loc.T("Home_WelcomeTitle");
        ConnectionStatusLabel.Text = Loc.T("Home_ConnectionStatus");
        VpnServerLabel.Text = Loc.T("Home_VpnServer");
        ServerLabel.Text = Loc.T("Home_Server");
        RefreshServersButton.Content = Loc.T("Home_Refresh");
        ConnectButton.Content = Loc.T("Home_Connect");
        DisconnectButton.Content = Loc.T("Home_Disconnect");
        LogsLabel.Text = Loc.T("Home_EngineLogs");

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

        _serversApi ??= new OpenVpnServersApiClient(App.AuthedApiHttp);

        _controller.AttachUi(
            statusTextSetter: s => DispatchUi(() => StatusText.Text = s),
            uiStateApplier: (state, status, network) => DispatchUi(() => ApplyUiState(state, status, network)),
            logAppender: line => DispatchUi(() => AppendLog(line)));

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
            _controller.AppendLogLine(Loc.T("Home_Log_EngineAttachFmt", ex.Message));
        }
    }

    private void HomePage_OnUnloaded(object sender, RoutedEventArgs e)
    {
        if (_languageHookAttached)
        {
            WinUiLanguageService.LanguageChanged -= OnUiLanguageChanged;
            _languageHookAttached = false;
        }

        SaveVpnHomeSettingsFromUi();
        _controller.OnUnloaded();
    }

    private void OnUiLanguageChanged(object? sender, EventArgs e)
        => DispatchUi(() =>
        {
            ApplyLocalizedChrome();
            RebuildServerComboFromCache();
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
        await _controller.ConnectAsync(autoPick, manualId);
    }

    private async void DisconnectButton_OnClick(object sender, RoutedEventArgs e)
        => await _controller.DisconnectAsync();

    private async void ServerModeCombo_OnSelectionChanged(object sender, SelectionChangedEventArgs e)
    {
        UpdateManualRowVisibility();
        SaveVpnHomeSettingsFromUi();

        var hasCache = _cachedServerRows is { Count: > 0 };
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
        StatusText.Text = statusText;
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

    private void ApplyNetworkInfo(VpnConnectionSessionInfo? network)
    {
        var show = network is { HasIdentity: true };
        NetworkInfoPanel.Visibility = show ? Visibility.Visible : Visibility.Collapsed;
        if (!show)
            return;

        var dash = Loc.T("Home_Network_Unavailable");
        NetworkServerText.Text = Loc.T("Home_Network_Server") + ": " +
            (string.IsNullOrWhiteSpace(network!.ServerName) ? dash : network.ServerName);
        NetworkVpnIpText.Text = Loc.T("Home_Network_VpnIp") + ": " +
            (string.IsNullOrWhiteSpace(network.VpnIp) ? dash : network.VpnIp!);
        NetworkExternalIpText.Text = Loc.T("Home_Network_ExternalIp") + ": " +
            (string.IsNullOrWhiteSpace(network.ExternalIp) ? dash : network.ExternalIp!);
    }

    private void AppendLog(string line)
    {
        if (string.IsNullOrWhiteSpace(line))
            return;

        var ts = DateTime.Now.ToString("HH:mm:ss");
        var chunk = $"[{ts}] {line}";
        var dropped = CrashReporting.InMemoryLogBudget.AppendLine(_logLines, chunk);
        if (dropped)
            LogTextBox.Text = CrashReporting.InMemoryLogBudget.JoinLinesForTextBox(_logLines);
        else
            LogTextBox.Text += chunk + Environment.NewLine;
    }

    private void DispatchUi(Action action)
    {
        if (DispatcherQueue.HasThreadAccess)
            action();
        else
            DispatcherQueue.TryEnqueue(() => action());
    }

    private void UpdateManualRowVisibility()
        => ManualServerRow.Visibility = ServerModeCombo.SelectedIndex == 1 ? Visibility.Visible : Visibility.Collapsed;

    private void RestoreVpnHomeSettingsFromStore()
    {
        _suppressSettingsSave = true;
        try
        {
            var s = App.Settings;
            ServerModeCombo.SelectedIndex = s.HomeVpnAutoPickServer ? 0 : 1;
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

            List<HomeVpnServerListItem> items;
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
                            Online = srv.IsOnline
                        };
                    })
                    .ToList();

                items = _cachedServerRows.Select(r => new HomeVpnServerListItem
                {
                    Id = r.Id,
                    Display = FormatServerDisplay(r)
                }).ToList();
            }
            catch (Exception ex)
            {
                CrashReporter.ReportNonFatal(ex, "HomePage.RefreshServerList");
                fetchFailed = true;
                _cachedServerRows = null;
                _controller.AppendLogLine(Loc.T("Home_Log_VpnListFmt", ex.Message));
                items = [];
            }

            void ApplyList()
            {
                _suppressSettingsSave = true;
                try
                {
                    ManualServerCombo.Items.Clear();
                    foreach (var item in items)
                        ManualServerCombo.Items.Add(item);
                    ManualServerCombo.DisplayMemberPath = nameof(HomeVpnServerListItem.Display);
                    ApplyManualSelectionFromSettings();
                }
                finally
                {
                    _suppressSettingsSave = false;
                }

                if (items.Count == 0 && !fetchFailed)
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
            {
                ManualServerCombo.Items.Add(new HomeVpnServerListItem
                {
                    Id = r.Id,
                    Display = FormatServerDisplay(r)
                });
            }

            ManualServerCombo.DisplayMemberPath = nameof(HomeVpnServerListItem.Display);
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

    private static string FormatServerDisplay(CachedVpnServerRow r)
    {
        var name = string.IsNullOrWhiteSpace(r.Name)
            ? Loc.T("Home_ServerFallbackFmt", r.Id)
            : r.Name;
        var onOff = r.Online ? Loc.T("Common_Online") : Loc.T("Common_Offline");
        return Loc.T("Home_ServerRowFmt", name, r.Clients, onOff);
    }

    private sealed class CachedVpnServerRow
    {
        public int Id { get; init; }
        public string Name { get; init; } = "";
        public int Clients { get; init; }
        public bool Online { get; init; }
    }

    private sealed class HomeVpnServerListItem
    {
        public int Id { get; init; }
        public string Display { get; init; } = "";
        public override string ToString() => Display;
    }
}
