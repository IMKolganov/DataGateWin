using System.ComponentModel;
using System.Diagnostics;
using System.IO;
using System.Threading;
using DataGateWin.CrashReporting;
using DataGateWin.Ipc;
using DataGateWin.Localization;
using DataGateWin.Models.Ipc;
using DataGateWin.Services.Ui;
using DataGateWin.Services.VpnServers;
using Newtonsoft.Json.Linq;

namespace DataGateWin.Services.Ipc;

public sealed class EngineSessionService(
    EnginePathResolver enginePathResolver,
    StartSessionPayloadBuilder payloadBuilder,
    Action<string> log,
    Action<EngineEvent> onEngineEvent)
    : IDisposable
{
    private EngineIpcClient? _client;
    private bool _handlersAttached;
    private readonly EngineLogNoiseFilter _logNoise = new();

    private const string SessionId = "dev";

    /// <summary>Last <see cref="StartSessionAsync"/> failed because no WSS server matched filters.</summary>
    public bool LastStartFailedNoEligibleServers { get; private set; }

    private Exception? _lastStartException;
    private string? _lastStartRaw;

    /// <summary>Short human message from the last failed start (payload/API/engine reply).</summary>
    public string? LastStartErrorHuman =>
        _lastStartException != null ? VpnUserFacingError.FromException(_lastStartException)
        : _lastStartRaw != null ? VpnUserFacingError.FromMessage(_lastStartRaw)
        : null;

    public void RememberStartError(Exception ex)
    {
        _lastStartException = ex;
        _lastStartRaw = null;
    }

    public void RememberStartErrorHuman(string? message)
    {
        _lastStartException = null;
        _lastStartRaw = string.IsNullOrWhiteSpace(message) ? null : message.Trim();
    }

    private void ClearLastStartError()
    {
        _lastStartException = null;
        _lastStartRaw = null;
    }

    /// <summary>Server row remembered from the last successful payload build (Home network footer).</summary>
    public VpnConnectionSessionInfo? LastSelection => payloadBuilder.LastSelection;

    public void ClearLastSelection() => payloadBuilder.ClearLastSelection();

    // Guard so we don't kill repeatedly if service is used multiple times
    private bool _startupKillDone;

    private static EngineSessionService? s_active;

    /// <summary>
    /// Gracefully stops the active VPN session if the UI still has a live IPC client.
    /// Safe to call from <c>OnExit</c> / session-ending handlers.
    /// </summary>
    public static async Task TryStopActiveSessionSafeAsync(TimeSpan timeout)
    {
        var svc = s_active;
        if (svc?._client == null)
            return;

        using var cts = new CancellationTokenSource(timeout);
        await svc.StopSessionSafeAsync(cts.Token).ConfigureAwait(false);
    }

    /// <summary>
    /// Serialize attach/start so concurrent UI paths (e.g. Home load + Connect) cannot interleave
    /// <see cref="EngineIpcClient.TryConnectExistingAsync"/> with <see cref="EngineIpcClient.ResetConnection"/>.
    /// </summary>
    private readonly SemaphoreSlim _connectionOps = new(1, 1);

    public void Dispose()
    {
        if (ReferenceEquals(s_active, this))
            s_active = null;

        try { _client?.Dispose(); } catch (Exception ex) { CrashReporter.ReportNonFatal(ex, "EngineSessionService.DisposeClient"); }
        _client = null;
        _handlersAttached = false;
        _connectionOps.Dispose();
    }

    public async Task AttachAsync(CancellationToken ct)
    {
        await _connectionOps.WaitAsync(ct).ConfigureAwait(false);
        try
        {
            EnsureClientCreated();
            AttachHandlersOnce();

            if (_client!.IsConnected)
                return;

            using var attachCts = CancellationTokenSource.CreateLinkedTokenSource(ct);
            attachCts.CancelAfter(TimeSpan.FromSeconds(8));

            var attached = await _client.TryConnectExistingAsync(8000, attachCts.Token).ConfigureAwait(false);
            if (!attached)
                throw new InvalidOperationException($"Attach failed: {_client.LastAttachError ?? "unknown"}");
        }
        finally
        {
            _connectionOps.Release();
        }
    }

    public async Task AttachOrStartAsync(CancellationToken ct)
    {
        await _connectionOps.WaitAsync(ct).ConfigureAwait(false);
        try
        {
            EnsureClientCreated();
            AttachHandlersOnce();

            if (_client!.IsConnected)
                return;

            using var attachCts = CancellationTokenSource.CreateLinkedTokenSource(ct);
            attachCts.CancelAfter(TimeSpan.FromSeconds(10));

            var attached = await _client.TryConnectExistingAsync(1000, attachCts.Token).ConfigureAwait(false);
            if (attached)
            {
                log("Engine attached (existing).");
                return;
            }

            log($"Attach failed: {_client.LastAttachError ?? "unknown"}. Starting/attaching engine process...");

            _client.ResetConnection();

            using var startCts = CancellationTokenSource.CreateLinkedTokenSource(ct);
            startCts.CancelAfter(TimeSpan.FromSeconds(12));
            await _client.StartOrAttachAsync(startCts.Token).ConfigureAwait(false);

            log("Engine connected.");
        }
        finally
        {
            _connectionOps.Release();
        }
    }

    public async Task<bool> IsAttachedAsync(CancellationToken ct)
    {
        EnsureClientCreated();
        return _client!.IsConnected;
    }

    public async Task<string?> GetEngineStateAsync(CancellationToken ct)
    {
        EnsureClientCreated();

        using var statusCts = CancellationTokenSource.CreateLinkedTokenSource(ct);
        statusCts.CancelAfter(TimeSpan.FromSeconds(5));

        var reply = await _client!.SendCommandAsync("GetStatus", "{}", statusCts.Token).ConfigureAwait(false);
        if (!reply.Ok)
            return null;

        return reply.Payload?["state"]?.ToString();
    }

    public Task<bool> StartSessionAsync(CancellationToken ct) =>
        StartSessionAsync(autoPickServer: true, manualVpnServerId: null, ct);

    public async Task<bool> StartSessionAsync(bool autoPickServer, int? manualVpnServerId, CancellationToken ct)
    {
        EnsureClientCreated();
        LastStartFailedNoEligibleServers = false;
        ClearLastStartError();

        JObject? payload;
        try
        {
            payload = await payloadBuilder
                .BuildAsync(autoPickServer, manualVpnServerId, ct)
                .ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested)
        {
            log("StartSession skipped: canceled.");
            RememberStartErrorHuman("canceled");
            return false;
        }
        catch (Exception ex)
        {
            CrashReporter.ReportNonFatal(ex, "EngineSessionService.StartSessionPayload");
            RememberStartError(ex);
            log($"BuildAsync failed: {ex.Message}");
            return false;
        }

        if (payload == null)
        {
            log("No eligible WSS VPN servers.");
            LastStartFailedNoEligibleServers = true;
            RememberStartErrorHuman("No eligible");
            return false;
        }

        return await SendStartSessionAsync(payload, ct).ConfigureAwait(false);
    }

    public Task<bool> StartSessionWithPayloadAsync(JObject payload, CancellationToken ct)
    {
        ArgumentNullException.ThrowIfNull(payload);
        EnsureClientCreated();
        LastStartFailedNoEligibleServers = false;
        ClearLastStartError();
        return SendStartSessionAsync(payload, ct);
    }

    private async Task<bool> SendStartSessionAsync(JObject payload, CancellationToken ct)
    {
        // Catalog Xray already appends in the payload builder; imported Xray hits this path only.
        try
        {
            await payloadBuilder.AppendXrayIpListBypassAsync(payload, ct).ConfigureAwait(false);
            InjectRdpPeerBypass(payload);

            using var startCts = CancellationTokenSource.CreateLinkedTokenSource(ct);
            startCts.CancelAfter(TimeSpan.FromSeconds(20));

            var reply = await _client!.SendCommandAsync(
                "StartSession",
                payload.ToString(Newtonsoft.Json.Formatting.None),
                startCts.Token).ConfigureAwait(false);

            if (!reply.Ok)
            {
                var code = reply.Code ?? "?";
                var message = reply.Message ?? "?";
                CrashReporter.ReportNonFatal(
                    new InvalidOperationException($"StartSession failed: {code} - {message}"),
                    "EngineSessionService.StartSessionReply");
                RememberStartErrorHuman($"{code}: {message}");
                log($"StartSession failed: {code} - {message}");
                return false;
            }

            return true;
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested)
        {
            RememberStartErrorHuman("canceled");
            log("StartSession canceled.");
            return false;
        }
        catch (Exception ex)
        {
            CrashReporter.ReportNonFatal(ex, "EngineSessionService.StartSessionSend");
            RememberStartError(ex);
            log($"StartSession send failed: {ex.Message}");
            return false;
        }
    }

    /// <summary>
    /// Keep active RDP clients on the physical NIC so full-tunnel VPN does not drop the session.
    /// </summary>
    private void InjectRdpPeerBypass(JObject payload)
    {
        var peers = RdpPeerCidrs.CollectEstablishedPeerCidrs();
        if (peers.Count == 0)
            return;

        log($"[ui] RDP peer bypass: {string.Join(", ", peers)}");

        var protocol = payload.Value<string>("protocol")?.Trim().ToLowerInvariant();
        if (protocol == "xray")
        {
            var arr = payload["directBypassCidrs"] as JArray ?? new JArray();
            foreach (var cidr in peers)
            {
                if (!arr.Any(t => string.Equals(t.Value<string>(), cidr, StringComparison.OrdinalIgnoreCase)))
                    arr.Add(cidr);
            }
            payload["directBypassCidrs"] = arr;
            return;
        }

        var ovpn = payload.Value<string>("ovpnContent");
        if (string.IsNullOrEmpty(ovpn))
            return;

        var sb = new System.Text.StringBuilder(ovpn);
        if (!ovpn.EndsWith('\n'))
            sb.Append('\n');
        sb.AppendLine("# DataGate RDP peer bypass (keep remote desktop alive)");
        foreach (var cidr in peers)
        {
            var slash = cidr.LastIndexOf('/');
            var ip = slash > 0 ? cidr[..slash] : cidr;
            if (ip.Contains(':', StringComparison.Ordinal))
                sb.Append("route-ipv6 ").Append(cidr).AppendLine(" net_gateway");
            else
                sb.Append("route ").Append(ip).AppendLine(" 255.255.255.255 net_gateway");
        }
        payload["ovpnContent"] = sb.ToString();
    }


    /// <returns>True when StopSession replied OK (or there was no client).</returns>
    public async Task<bool> StopSessionSafeAsync(CancellationToken ct)
    {
        if (_client == null)
        {
            log("[ui][disconnect] StopSession skipped: client is null");
            return true;
        }

        log($"[ui][disconnect] StopSession START isConnected={_client.IsConnected}");

        try
        {
            using var stopCts = CancellationTokenSource.CreateLinkedTokenSource(ct);
            stopCts.CancelAfter(TimeSpan.FromSeconds(20));

            var startedAt = DateTime.UtcNow;
            log("[ui][disconnect] StopSession sending command... timeout=20s");

            var reply = await _client.SendCommandAsync("StopSession", "{}", stopCts.Token).ConfigureAwait(false);

            var ms = (DateTime.UtcNow - startedAt).TotalMilliseconds;
            log($"[ui][disconnect] StopSession reply received in {ms:0}ms ok={reply.Ok} code={reply.Code ?? "<null>"} message={reply.Message ?? "<null>"}");

            if (!reply.Ok)
            {
                log($"[ui][disconnect] StopSession FAILED code={reply.Code ?? "?"} message={reply.Message ?? "?"}");
                return false;
            }

            log("[ui][disconnect] StopSession OK");
            return true;
        }
        catch (OperationCanceledException oce) when (ct.IsCancellationRequested)
        {
            log($"[ui][disconnect] StopSession CANCELED by outer token: {oce.Message}");
            return false;
        }
        catch (OperationCanceledException oce)
        {
            log($"[ui][disconnect] StopSession TIMEOUT/CANCELED by internal token: {oce.Message}");
            return false;
        }
        catch (Exception ex)
        {
            CrashReporter.ReportNonFatal(ex, "EngineSessionService.StopSession");
            log($"[ui][disconnect] StopSession ERROR: {ex}");
            return false;
        }
        finally
        {
            log("[ui][disconnect] StopSession END");
        }
    }

    private void EnsureClientCreated()
    {
        if (_client != null)
            return;

        var engineExePath = enginePathResolver.ResolveEngineExePath();
        if (!File.Exists(engineExePath))
            throw new FileNotFoundException("Engine executable not found.", engineExePath);

        KillEngineProcessesByExactPathOnce(engineExePath);
        EngineDnsRecoveryRunner.TryRecover(engineExePath, log);

        s_active = this;
        _client = new EngineIpcClient(engineExePath, SessionId);
    }

    private void KillEngineProcessesByExactPathOnce(string engineExePath)
    {
        if (_startupKillDone)
            return;

        _startupKillDone = true;

        try
        {
            var fullTarget = Path.GetFullPath(engineExePath);

            foreach (var p in Process.GetProcessesByName("engine"))
            {
                try
                {
                    string? procPath = null;

                    try
                    {
                        procPath = p.MainModule?.FileName;
                    }
                    catch (Win32Exception)
                    {
                        // Access denied for some processes; ignore
                    }
                    catch (InvalidOperationException)
                    {
                        // Process exited; ignore
                    }

                    if (procPath == null)
                        continue;

                    if (!Path.GetFullPath(procPath).Equals(fullTarget, StringComparison.OrdinalIgnoreCase))
                        continue;

                    log($"[ui][startup] Killing stale engine process pid={p.Id} path={procPath}");

                    try
                    {
                        p.Kill(entireProcessTree: true);
                    }
                    catch (Exception ex)
                    {
                        CrashReporter.ReportNonFatal(ex, "EngineSessionService.KillEnginePrimary");
                        // Fallback
                        p.Kill();
                    }

                    try
                    {
                        p.WaitForExit(2000);
                    }
                    catch (Exception ex)
                    {
                        CrashReporter.ReportNonFatal(ex, "EngineSessionService.KillEngineWait");
                        // Ignore
                    }
                }
                finally
                {
                    try { p.Dispose(); } catch (Exception ex) { CrashReporter.ReportNonFatal(ex, "EngineSessionService.KillEngineDisposeProcess"); }
                }
            }
        }
        catch (Exception ex)
        {
            CrashReporter.ReportNonFatal(ex, "EngineSessionService.KillEngineProcesses");
            log($"[ui][startup] KillEngineProcesses failed (ignored): {ex.Message}");
        }
    }

    private void AttachHandlersOnce()
    {
        if (_client == null || _handlersAttached)
            return;

        _handlersAttached = true;

        // Engine writes every log to stderr AND as an IPC Log event. Only forward stderr here
        // so the UI is not hit twice per line (route floods ×2 freeze weak machines).
        _client.EngineLogReceived += (_, line) => ForwardEngineLog(line);

        _client.EngineExited += (_, code) =>
        {
            FlushNoiseSummary();
            log($"Engine exited with code: {code}");
            if (code != 0)
            {
                CrashReporter.ReportNonFatal(
                    new InvalidOperationException($"Engine exited with non-zero code: {code}"),
                    "EngineSessionService.EngineExited");
            }

            _ = CrashReporter.FlushPendingAsync(CancellationToken.None);
            onEngineEvent(new EngineEvent
            {
                Kind = EngineEventKind.EngineExited,
                ExitCode = code
            });
        };

        _client.EventReceived += (_, ev) =>
        {
            try
            {
                var mapped = EngineEventMapper.Map(ev);
                if (mapped == null)
                    return;

                // Log lines already arrive via EngineLogReceived (stderr). Skip re-logging.
                if (mapped.Kind == EngineEventKind.Log)
                    return;

                onEngineEvent(mapped);
            }
            catch (Exception ex)
            {
                CrashReporter.ReportNonFatal(ex, "EngineSessionService.EventHandler");
                log($"Event handler error: {ex}");
            }
        };
    }

    private void ForwardEngineLog(string line)
    {
        if (string.IsNullOrWhiteSpace(line))
            return;

        var filtered = _logNoise.Filter(line);
        if (filtered == null)
            return;

        foreach (var part in filtered.Split(new[] { '\r', '\n' }, StringSplitOptions.RemoveEmptyEntries))
        {
            log(part);
            if (IsDllLoadFailureLine(part))
                log(Loc.T("Home_Log_DllMissingHint"));
        }
    }

    private void FlushNoiseSummary()
    {
        var summary = _logNoise.Flush();
        if (!string.IsNullOrWhiteSpace(summary))
            log(summary);
    }

    /// <summary>Detects engine log lines like LoadLibraryExW(wintun.dll) failed: 126 …</summary>
    private static bool IsDllLoadFailureLine(string line)
    {
        if (string.IsNullOrEmpty(line))
            return false;
        if (!line.Contains(".dll", StringComparison.OrdinalIgnoreCase))
            return false;
        if (!line.Contains("LoadLibrary", StringComparison.OrdinalIgnoreCase))
            return false;
        return line.Contains("126", StringComparison.Ordinal)
            || line.Contains("could not be found", StringComparison.OrdinalIgnoreCase)
            || line.Contains("not be found", StringComparison.OrdinalIgnoreCase)
            || line.Contains("The specified module", StringComparison.OrdinalIgnoreCase);
    }
}
