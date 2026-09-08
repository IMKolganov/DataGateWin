using System.Globalization;
using DataGateWin.CrashReporting;
using DataGateWin.Localization;
using DataGateWin.Models.Ipc;
using DataGateWin.Services.Installation;
using DataGateWin.Services.Ipc;
using DataGateWin.Services.IpList;
using DataGateWin.Services.OpenVpnFiles;
using DataGateWin.Services.Profiles;
using DataGateWin.Services.Ui;
using DataGateWin.Services.VpnServers;
using DataGateWin.Services.Xray;

namespace DataGateWin.Controllers;

public sealed class HomeController : IDisposable
{
    private readonly SemaphoreSlim _opLock = new(1, 1);

    private CancellationTokenSource? _lifetimeCts;
    private bool _desiredConnected;
    private int _reconnectAttempt;
    private bool _connectAutoPick = true;
    private int? _connectManualId;
    private Guid? _connectImportedProfileId;

    private readonly EngineSessionService _engine;
    private readonly InstallationIdService _installation = new();
    private readonly ImportedVpnProfileStore _importedProfiles = new();
    private readonly StartSessionPayloadBuilder _payloadBuilder;

    private readonly object _uiLock = new();

    private Action<string>? _setStatusText;
    private Action<UiState, string, VpnConnectionSessionInfo?>? _applyUiState;
    private Action<string>? _log;

    private UiState _lastUiState = UiState.Idle;
    private string _lastStatusText = Loc.T("Home_Status_Idle");
    private Func<string>? _statusComposer;
    private VpnConnectionSessionInfo? _sessionInfo;

    /// <summary>Fired on every VPN UI state change (engine and user actions). Used by tray toasts.</summary>
    public event Action<UiState, string>? UiStateChanged;

    public UiState LastUiState => _lastUiState;
    public string LastStatusText => _lastStatusText;

    public HomeController()
    {
        var serversApi = new OpenVpnServersApiClient(App.AuthedApiHttp);
        var selector = new WssServerSelector(serversApi);
        var filesApi = new OpenVpnFilesApiClient(App.AuthedApiHttp);
        var xrayFilesApi = new XrayClientLinksApiClient(App.AuthedApiHttp);

        _payloadBuilder = new StartSessionPayloadBuilder(
            wssServerSelector: selector,
            installationIdService: _installation,
            filesApi: filesApi,
            xrayFilesApi: xrayFilesApi,
            session: App.Session,
            ipListRoutes: new IpListRoutesRepository());

        _engine = new EngineSessionService(
            enginePathResolver: new EnginePathResolver(),
            payloadBuilder: _payloadBuilder,
            log: Log,
            onEngineEvent: HandleEngineEvent
        );
    }

    public void AppendLogLine(string line) => Log(line);

    public void ReapplyUiToLastState()
        => ApplyUiState(_lastUiState, _statusComposer ?? (() => Loc.T("Home_Status_Idle")));

    /// <summary>Last humanized start failure (for Import/tray status).</summary>
    public string? LastConnectErrorHuman => _engine.LastStartErrorHuman;

    public void AttachUi(
        Action<string> statusTextSetter,
        Action<UiState, string, VpnConnectionSessionInfo?> uiStateApplier,
        Action<string> logAppender)
    {
        lock (_uiLock)
        {
            _setStatusText = statusTextSetter;
            _applyUiState = uiStateApplier;
            _log = logAppender;
        }

        ReapplyUiToLastState();
        Log(Loc.T("Home_Log_UiAttached"));
    }

    public void DetachUi()
    {
        lock (_uiLock)
        {
            _setStatusText = null;
            _applyUiState = null;
            _log = null;
        }
    }

    public async Task OnLoadedAsync()
    {
        // Page navigation must not reset VPN intent / session identity.
        // Only ensure a live CTS for future connect/disconnect/reconnect work.
        if (_lifetimeCts == null || _lifetimeCts.IsCancellationRequested)
            _lifetimeCts = new CancellationTokenSource();

        var ct = _lifetimeCts.Token;
        var returningToPage =
            _lastUiState is UiState.Connected or UiState.Connecting or UiState.Disconnecting
            || _sessionInfo is { HasIdentity: true }
            || _desiredConnected;

        try
        {
            if (!returningToPage)
                ApplyKeyed(UiState.Connecting, "Home_Status_Attaching");
            else
                ReapplyUiToLastState();

            await _engine.AttachOrStartAsync(ct).ConfigureAwait(false);
            RememberSelectionFromEngine();
            await RefreshStatusAsync(ct).ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested)
        {
            ApplyKeyed(UiState.Idle, "Home_Status_Idle");
        }
        catch (Exception ex)
        {
            if (TryHandleEngineMissing(ex))
                return;

            CrashReporter.ReportNonFatal(ex, "HomeController.OnLoaded");
            Log(Loc.T("Home_Log_ErrorFmt", VpnUserFacingError.FromException(ex)));
            // Always surface attach failure (including return-to-Home), so we never leave a
            // stale Connected UI when the engine IPC is dead.
            ApplyUiState(UiState.Idle, () =>
                Loc.T("Home_Status_AttachFailedFmt", VpnUserFacingError.FromException(ex)));
        }
    }

    public void OnUnloaded()
    {
        // Keep controller CTS + session info alive across menu navigation.
        // Cancelling here used to kill reconnect and force a cold "Attaching" reset on return.
        DetachUi();
    }

    public async Task<bool> ConnectAsync(bool autoPickServer, int? manualVpnServerId)
    {
        _desiredConnected = true;
        _connectAutoPick = autoPickServer;
        _connectManualId = manualVpnServerId;
        _connectImportedProfileId = null;
        return await EnsureConnectedAsync();
    }

    /// <returns>True when a start was accepted (or the desired session was already up).</returns>
    public async Task<bool> ConnectImportedProfileAsync(Guid profileId)
    {
        _desiredConnected = true;
        _connectImportedProfileId = profileId;
        _connectManualId = null;
        return await EnsureConnectedAsync();
    }

    public async Task DisconnectAsync()
    {
        _desiredConnected = false;
        await EnsureDisconnectedAsync(userInitiated: true);
    }

    private async Task<bool> EnsureConnectedAsync()
    {
        var ct = _lifetimeCts?.Token ?? CancellationToken.None;

        await _opLock.WaitAsync(ct).ConfigureAwait(false);
        try
        {
            ApplyKeyed(UiState.Connecting, "Home_Status_Connecting");

            await _engine.AttachOrStartAsync(ct).ConfigureAwait(false);

            var state = await _engine.GetEngineStateAsync(ct).ConfigureAwait(false);
            if (EngineState.IsUnknown(state))
            {
                Log(Loc.T("Home_Log_ErrorFmt", VpnUserFacingError.FromMessage("GetStatus failed")));
                ApplyUiState(UiState.Idle, () =>
                    Loc.T("Home_Status_IdleErrorFmt", VpnUserFacingError.FromMessage("GetStatus failed")));
                if (_desiredConnected)
                    _ = ScheduleReconnectAsync();
                return false;
            }

            var needsRestart = NeedsSessionRestart(state) || EngineState.NeedsCleanup(state);
            if (EngineState.IsLiveSession(state) && !needsRestart)
            {
                RememberSelectionFromEngine();
                if (EngineState.IsConnected(state))
                {
                    ApplyConnected(state);
                    return true;
                }

                // Already starting/connecting for the desired target — wait for Connected/Error.
                ApplyKeyed(UiState.Connecting, "Home_Status_ConnectingWaiting");
                return true;
            }

            if (!EngineState.IsIdle(state))
            {
                ApplyKeyed(UiState.Disconnecting, "Home_Status_Disconnecting");
                var stopped = await _engine.StopSessionSafeAsync(ct).ConfigureAwait(false);
                ClearSessionInfo();
                var afterStop = await _engine.GetEngineStateAsync(ct).ConfigureAwait(false);
                if (!stopped || (!EngineState.IsUnknown(afterStop) && !EngineState.IsIdle(afterStop)))
                {
                    Log(Loc.T("Home_Log_ErrorFmt", VpnUserFacingError.FromMessage("StopSession incomplete")));
                    ApplyUiState(UiState.Idle, () =>
                        Loc.T("Home_Status_IdleErrorFmt", VpnUserFacingError.FromMessage("StopSession incomplete")));
                    if (_desiredConnected)
                        _ = ScheduleReconnectAsync();
                    return false;
                }

                ApplyKeyed(UiState.Connecting, "Home_Status_Connecting");
            }

            bool started;
            if (_connectImportedProfileId is Guid importedId)
            {
                started = await StartImportedProfileAsync(importedId, ct).ConfigureAwait(false);
            }
            else
            {
                started = await _engine.StartSessionAsync(_connectAutoPick, _connectManualId, ct).ConfigureAwait(false);
                if (started)
                    RememberSelectionFromEngine();
            }

            if (!started)
            {
                ClearSessionInfo();
                if (_engine.LastStartFailedNoEligibleServers && _connectImportedProfileId is null)
                {
                    Log(Loc.T("Home_Log_NoWss"));
                    _desiredConnected = false;
                }

                ApplyUiState(UiState.Idle, ComposeStartFailedStatus);
                if (_desiredConnected)
                    _ = ScheduleReconnectAsync();
                return false;
            }

            // ReplyOk means accepted — Connected/Error events decide the real outcome.
            ApplyKeyed(UiState.Connecting, "Home_Status_ConnectingWaiting");
            _reconnectAttempt = 0;
            return true;
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested)
        {
            ApplyKeyed(UiState.Idle, "Home_Status_Idle");
            return false;
        }
        catch (Exception ex)
        {
            if (TryHandleEngineMissing(ex))
                return false;

            CrashReporter.ReportNonFatal(ex, "HomeController.EnsureConnected");
            ApplyUiState(UiState.Idle, () =>
                Loc.T("Home_Status_IdleErrorFmt", VpnUserFacingError.FromException(ex)));
            Log(Loc.T("Home_Log_ErrorFmt", VpnUserFacingError.FromException(ex)));

            if (_desiredConnected)
                _ = ScheduleReconnectAsync();
            return false;
        }
        finally
        {
            _opLock.Release();
        }
    }

    /// <summary>
    /// True when the active engine session should be stopped before starting the desired target.
    /// </summary>
    private bool NeedsSessionRestart(string? engineState)
    {
        // Terminal phases are handled via NeedsCleanup; here we compare desired vs remembered identity.
        if (!EngineState.IsLiveSession(engineState) && !EngineState.NeedsCleanup(engineState))
            return false;

        if (_connectImportedProfileId is not null)
        {
            // Explicit Import Connect always restarts (profile identity is not in engine state).
            return EngineState.IsLiveSession(engineState) || EngineState.NeedsCleanup(engineState);
        }

        // Catalog desired: restart if an imported session is active (ServerId == 0 with a name).
        if (_sessionInfo is { ServerId: 0, ServerName: var name } && !string.IsNullOrWhiteSpace(name))
            return true;

        if (_connectManualId is int wantId
            && _sessionInfo is { ServerId: var haveId }
            && haveId > 0
            && haveId != wantId)
            return true;

        return false;
    }

    private async Task<bool> StartImportedProfileAsync(Guid profileId, CancellationToken ct)
    {
        var profile = _importedProfiles.Get(profileId);
        if (profile is null)
        {
            Log(Loc.T("Import_Log_ProfileMissing"));
            return false;
        }

        try
        {
            var payload = profile.Protocol switch
            {
                ImportedVpnProtocol.OpenVpn => ImportedOpenVpnPayloadBuilder.Build(profile, _installation),
                ImportedVpnProtocol.Xray => ImportedXrayPayloadBuilder.Build(profile, _installation),
                _ => throw new InvalidOperationException("Unsupported imported protocol: " + profile.Protocol),
            };
            _sessionInfo = new VpnConnectionSessionInfo
            {
                ServerId = 0,
                ServerName = profile.Name,
                ExternalIp = null,
                DnsServers = profile.Protocol == ImportedVpnProtocol.Xray
                    ? XrayWindowsConfigBuilder.ExtractExplicitDnsServers(profile.ConfigText)
                    : null,
            };
            _payloadBuilder.ClearLastSelection();
            Log(Loc.T("Import_Log_ConnectingFmt", profile.Name));
            return await _engine.StartSessionWithPayloadAsync(payload, ct).ConfigureAwait(false);
        }
        catch (Exception ex)
        {
            CrashReporter.ReportNonFatal(ex, "HomeController.StartImportedProfile");
            _engine.RememberStartError(ex);
            Log(Loc.T("Home_Log_ErrorFmt", VpnUserFacingError.FromException(ex)));
            return false;
        }
    }

    private async Task EnsureDisconnectedAsync(bool userInitiated)
    {
        var ct = _lifetimeCts?.Token ?? CancellationToken.None;

        await _opLock.WaitAsync(ct).ConfigureAwait(false);
        try
        {
            ApplyKeyed(UiState.Disconnecting, "Home_Status_Disconnecting");

            await _engine.StopSessionSafeAsync(ct).ConfigureAwait(false);
            ClearSessionInfo();

            ApplyKeyed(UiState.Idle, userInitiated ? "Home_Status_Idle" : "Home_Status_IdleDisconnected");
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested)
        {
            ApplyKeyed(UiState.Idle, "Home_Status_Idle");
        }
        catch (Exception ex)
        {
            CrashReporter.ReportNonFatal(ex, "HomeController.EnsureDisconnected");
            ClearSessionInfo();
            ApplyUiState(UiState.Idle, () =>
                Loc.T("Home_Status_IdleErrorFmt", VpnUserFacingError.FromException(ex)));
            Log(Loc.T("Home_Log_ErrorFmt", VpnUserFacingError.FromException(ex)));
        }
        finally
        {
            _opLock.Release();
        }
    }

    private async Task RefreshStatusAsync(CancellationToken ct)
    {
        if (!await _engine.IsAttachedAsync(ct).ConfigureAwait(false))
        {
            if (!_desiredConnected)
                ClearSessionInfo();
            ApplyKeyed(UiState.Idle, "Home_Status_IdleNotAttached");
            return;
        }

        var state = await _engine.GetEngineStateAsync(ct).ConfigureAwait(false);
        if (EngineState.IsUnknown(state))
        {
            ApplyKeyed(UiState.Idle, "Home_Status_IdleNotAttached");
            return;
        }

        if (EngineState.IsIdle(state) || EngineState.NeedsCleanup(state))
        {
            if (!_desiredConnected)
                ClearSessionInfo();
            ApplyKeyed(UiState.Idle, "Home_Status_Idle");
            return;
        }

        if (EngineState.IsConnected(state))
        {
            RememberSelectionFromEngine();
            ApplyConnected(state);
            return;
        }

        // starting / connecting / stopping
        RememberSelectionFromEngine();
        ApplyKeyed(UiState.Connecting, "Home_Status_ConnectingWaiting");
    }

    private bool TryHandleEngineMissing(Exception ex)
    {
        if (!EngineMissingUi.IsEngineMissingException(ex))
            return false;

        EngineMissingUi.ShowDialog(App.GetActiveXamlRoot());
        ClearSessionInfo();
        ApplyKeyed(UiState.Idle, "Home_Status_EngineMissing");
        Log(Loc.T("Home_Log_EngineMissing"));
        _desiredConnected = false;
        _reconnectAttempt = 0;
        return true;
    }

    private async Task ScheduleReconnectAsync()
    {
        var ct = _lifetimeCts?.Token ?? CancellationToken.None;

        if (!_desiredConnected)
            return;

        _reconnectAttempt++;
        var delay = ReconnectPolicy.GetDelay(_reconnectAttempt);

        var seconds = delay.TotalSeconds.ToString("0", CultureInfo.InvariantCulture);
        ApplyUiState(UiState.Connecting, () => Loc.T("Home_Status_ReconnectingFmt", seconds));
        Log(Loc.T(
            "Home_Log_ReconnectScheduledFmt",
            _reconnectAttempt.ToString(CultureInfo.InvariantCulture),
            seconds));

        try { await Task.Delay(delay, ct).ConfigureAwait(false); }
        catch (OperationCanceledException) { ApplyKeyed(UiState.Idle, "Home_Status_Idle"); return; }

        if (_desiredConnected)
            await EnsureConnectedAsync().ConfigureAwait(false);
    }

    private void HandleEngineEvent(EngineEvent ev)
    {
        if (ev.Kind == EngineEventKind.StateChanged)
        {
            if (EngineState.IsIdle(ev.State) || EngineState.NeedsCleanup(ev.State))
            {
                if (HomeSessionUiPolicy.ShouldClearSessionIdentity(_desiredConnected))
                    ClearSessionInfo();

                if (_desiredConnected)
                {
                    ApplyKeyed(UiState.Connecting, "Home_Status_ConnectingWaiting");
                    return;
                }

                ApplyKeyed(UiState.Idle, "Home_Status_Idle");
                return;
            }

            if (EngineState.IsConnected(ev.State))
            {
                ApplyConnected(ev.State);
                return;
            }

            // starting / connecting / stopping — never show Connected
            ApplyKeyed(UiState.Connecting, "Home_Status_ConnectingWaiting");
            return;
        }

        if (ev.Kind == EngineEventKind.Connected)
        {
            _reconnectAttempt = 0;
            RememberSelectionFromEngine();
            if (_sessionInfo != null && !string.IsNullOrWhiteSpace(ev.Ip))
                _sessionInfo.VpnIp = ev.Ip.Trim();

            ApplyConnected(null);
            return;
        }

        if (ev.Kind == EngineEventKind.Disconnected)
        {
            var rawReason = ev.Reason;
            Log(Loc.T("Home_Log_DisconnectedLineFmt",
                string.IsNullOrWhiteSpace(rawReason)
                    ? Loc.T("Common_Unknown")
                    : VpnUserFacingError.FromMessage(rawReason)));

            string ComposeDisconnect()
            {
                var reason = string.IsNullOrWhiteSpace(rawReason)
                    ? Loc.T("Common_Unknown")
                    : VpnUserFacingError.FromMessage(rawReason);
                return Loc.T("Home_Status_IdleDisconnectedReasonFmt", reason);
            }

            if (_desiredConnected)
            {
                // Keep footer identity while ScheduleReconnect rebuilds the session.
                ApplyUiState(UiState.Connecting, ComposeDisconnect);
                _ = ScheduleReconnectAsync();
                return;
            }

            ClearSessionInfo();
            ApplyUiState(UiState.Idle, ComposeDisconnect);
            return;
        }

        if (ev.Kind == EngineEventKind.Error)
        {
            var raw = ev.Message;
            Log(Loc.T("Home_Log_ErrorFmt", VpnUserFacingError.FromMessage(raw)));
            ApplyUiState(UiState.Idle, () =>
                Loc.T("Home_Status_IdleErrorFmt", VpnUserFacingError.FromMessage(raw)));
            if (_desiredConnected)
                _ = ScheduleReconnectAsync();
            return;
        }

        if (ev.Kind == EngineEventKind.EngineExited)
        {
            Log(Loc.T("Home_Log_ErrorFmt", Loc.T("Home_Error_EngineExit")));
            ClearSessionInfo();
            ApplyUiState(UiState.Idle, () =>
                Loc.T("Home_Status_IdleErrorFmt", Loc.T("Home_Error_EngineExit")));
            if (_desiredConnected)
                _ = ScheduleReconnectAsync();
        }
    }

    private void RememberSelectionFromEngine()
    {
        var sel = _engine.LastSelection;
        if (sel == null)
            return;

        // Preserve tunnel IP across payload rebuilds during reconnect.
        var previousVpnIp = _sessionInfo?.VpnIp;
        _sessionInfo = new VpnConnectionSessionInfo
        {
            ServerId = sel.ServerId,
            ServerName = sel.ServerName,
            ExternalIp = sel.ExternalIp,
            VpnIp = !string.IsNullOrWhiteSpace(sel.VpnIp) ? sel.VpnIp : previousVpnIp,
            DnsServers = sel.DnsServers ?? _sessionInfo?.DnsServers,
        };
    }

    private void ClearSessionInfo()
    {
        _sessionInfo = null;
        _engine.ClearLastSelection();
    }

    private string ComposeStartFailedStatus()
    {
        var human = _engine.LastStartErrorHuman;
        return string.IsNullOrWhiteSpace(human)
            ? Loc.T("Home_Status_IdleStartFailed")
            : Loc.T("Home_Status_IdleErrorFmt", human);
    }

    private void ApplyConnected(string? engineState)
        => ApplyUiState(UiState.Connected, () => ConnectedStatusText(engineState));

    private void ApplyKeyed(UiState state, string key)
        => ApplyUiState(state, () => Loc.T(key));

    private string ConnectedStatusText(string? engineState) =>
        HomeSessionUiPolicy.ComposeConnectedStatus(
            serverName: _sessionInfo?.ServerName,
            vpnIp: _sessionInfo?.VpnIp,
            engineState: engineState,
            lastStatusText: null,
            lastWasConnected: false,
            connectedPlain: Loc.T("Home_Status_Connected"),
            connectedServerFmt: Loc.T("Home_Status_ConnectedServerFmt"),
            connectedIpFmt: Loc.T("Home_Status_ConnectedIpFmt"),
            connectedFmt: Loc.T("Home_Status_ConnectedFmt"));

    private void ApplyUiState(UiState state, Func<string> composer)
    {
        _lastUiState = state;
        _statusComposer = composer;
        var statusText = composer();
        _lastStatusText = statusText;

        var network = state is UiState.Connected or UiState.Connecting or UiState.Disconnecting
            ? _sessionInfo
            : null;

        Action<UiState, string, VpnConnectionSessionInfo?>? apply;
        Action<UiState, string>? tray;
        lock (_uiLock)
        {
            apply = _applyUiState;
            tray = UiStateChanged;
        }

        apply?.Invoke(state, statusText, network);
        tray?.Invoke(state, statusText);
    }

    private void Log(string line)
    {
        lock (_uiLock)
        {
            _log?.Invoke(line);
        }
    }

    public void Dispose()
    {
        try { _lifetimeCts?.Cancel(); } catch (Exception ex) { CrashReporter.ReportNonFatal(ex, "HomeController.DisposeCancel"); }
        _lifetimeCts = null;

        DetachUi();
        _engine.Dispose();
        _opLock.Dispose();
    }
}

