// SessionController.cpp (only minimal text changes, full file returned as requested)
#include "SessionController.h"

#include "app/CrashReporter.h"
#include "BridgeManager.h"
#include "OvpnConfigProcessor.h"
#include "OvpnTextUtils.h"
#include "SessionStateStore.h"
#include "VpnSessionRunner.h"
#include "WintunAdapterManager.h"
#include "xray/XrayConfigBuilder.h"
#include "xray/XrayRuntime.h"

#include <json/json.h>

#include "vpn/WintunHolder.h"

#include <algorithm>
#include <atomic>
#include <cctype>
#include <chrono>
#include <memory>
#include <mutex>
#include <sstream>
#include <thread>
#include <utility>
#include <vector>

namespace datagate::session
{
    static void ReportSessionStartFailure(const std::string& code, const std::string& message)
    {
        CrashReporter::ReportNonFatal("SessionController.Start." + code, message);
    }

    static const char* GuessStopInitiator(SessionPhase phase)
    {
        // Best-effort guess based on current phase at the moment callback fires.
        // - If we are in Stopping => most likely user initiated StopSession
        // - Otherwise => transport/network error or remote close
        if (phase == SessionPhase::Stopping)
            return "user_stop";

        return "transport_error";
    }

    static std::string NormalizeProtocol(std::string p)
    {
        std::transform(p.begin(), p.end(), p.begin(),
                       [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
        if (p.empty())
            return "openvpn";
        return p;
    }

    class SessionController::Impl
    {
    public:
        SessionStateStore store;
        WintunAdapterManager wintun;
        BridgeManager bridge;
        OvpnConfigProcessor ovpn;
        VpnSessionRunner vpn;
        datagate::xray::XrayRuntime xray;
        bool xrayActive = false;
        std::atomic<bool> xrayWatchStop{false};
        std::thread xrayWatchThread;

        std::mutex cbMtx;

        Impl()
        {
            bridge.SetLog([this](const std::string& line)
            {
                store.PublishLogLine(line);
            });
            vpn.SetCallbacks(
                [this](const std::string& line)
                {
                    store.PublishLogLine("[ovpn] " + line);
                },
                [this](const datagate::vpn::VpnRunner::ConnectedInfo& ci)
                {
                    store.ResetDisconnectDedup();

                    store.SetPhase(SessionPhase::Connected);
                    store.PublishStateSnapshot();

                    ConnectedInfo x{};
                    x.vpnIfIndex = ci.vpnIfIndex;
                    x.vpnIpv4 = ci.vpnIpv4;
                    store.PublishConnected(x);

                    std::ostringstream oss;
                    oss << "[session] connected callback: ifIndex=" << ci.vpnIfIndex
                        << " ipv4=" << ci.vpnIpv4;
                    store.PublishLogLine(oss.str());
                },
                [this](const std::string& reason)
                {
                    const auto before = store.GetState();
                    const char* initiator = GuessStopInitiator(before.phase);

                    std::ostringstream oss0;
                    oss0 << "[session] disconnected callback ENTER"
                         << " initiator=" << initiator
                         << " prev_phase=" << ToString(before.phase)
                         << " reason=" << reason;
                    store.PublishLogLine(oss0.str());

                    const bool shouldEmitDisconnected = store.MarkDisconnectedOnce();
                    store.PublishLogLine(std::string("[session] disconnected dedup: emit=") + (shouldEmitDisconnected ? "true" : "false"));

                    const bool wasRunning =
                        before.phase == SessionPhase::Connected ||
                        before.phase == SessionPhase::Connecting ||
                        before.phase == SessionPhase::Starting;

                    store.PublishLogLine(std::string("[session] disconnected wasRunning=") + (wasRunning ? "true" : "false"));

                    if (wasRunning)
                    {
                        // Unexpected drop: tear down VPN+bridge and go Idle.
                        // Leaving "stopped" made StopSession WaitForIdle time out (Stop ignored Stopped)
                        // and the UI treated non-idle as Connected without StartSession.
                        store.PublishLogLine("[session] unexpected disconnect — teardown to Idle");
                        store.SetPhase(SessionPhase::Stopping);
                        store.PublishStateSnapshot();
                        StopAllNoCallbacks();
                        store.SetPhase(SessionPhase::Idle);
                        store.PublishStateSnapshot();

                        const auto after = store.GetState();
                        std::ostringstream oss1;
                        oss1 << "[session] phase transition on disconnect: "
                             << ToString(before.phase) << " -> " << ToString(after.phase);
                        store.PublishLogLine(oss1.str());
                    }

                    if (shouldEmitDisconnected)
                    {
                        store.PublishDisconnected(reason);
                        store.PublishLogLine("[session] disconnected event published");
                    }
                    else
                    {
                        store.PublishLogLine("[session] disconnected event suppressed (dedup)");
                    }

                    store.PublishLogLine("[session] disconnected callback EXIT");
                });
        }

        void SyncCallbacksFromController(const SessionController& c)
        {
            store.SetCallbacks(c.OnStateChanged, c.OnLog, c.OnError, c.OnConnected, c.OnDisconnected);
        }

        void StopXrayWatch()
        {
            xrayWatchStop.store(true);
            if (xrayWatchThread.joinable()
                && xrayWatchThread.get_id() != std::this_thread::get_id())
            {
                xrayWatchThread.join();
            }
        }

        void StartXrayWatch()
        {
            StopXrayWatch();
            xrayWatchStop.store(false);
            xrayWatchThread = std::thread([this]()
            {
                while (!xrayWatchStop.load())
                {
                    for (int i = 0; i < 20 && !xrayWatchStop.load(); ++i)
                        std::this_thread::sleep_for(std::chrono::milliseconds(100));
                    if (xrayWatchStop.load())
                        break;
                    if (!xrayActive)
                        continue;

                    std::string stateErr;
                    if (xray.IsRunning(stateErr))
                        continue;

                    store.PublishLogLine(std::string("[xray] watchdog: libXray not running — ")
                                         + (stateErr.empty() ? "unexpected exit" : stateErr));

                    const auto before = store.GetState();
                    const bool wasRunning =
                        before.phase == SessionPhase::Connected ||
                        before.phase == SessionPhase::Connecting ||
                        before.phase == SessionPhase::Starting;
                    if (!wasRunning)
                        break;

                    const bool shouldEmitDisconnected = store.MarkDisconnectedOnce();
                    store.SetPhase(SessionPhase::Stopping);
                    store.PublishStateSnapshot();
                    // Do not join this thread from itself.
                    xrayWatchStop.store(true);
                    StopAllNoCallbacks(/*joinWatch=*/false);
                    store.SetPhase(SessionPhase::Idle);
                    store.PublishStateSnapshot();
                    if (shouldEmitDisconnected)
                        store.PublishDisconnected("xray_exit");
                    break;
                }
            });
        }

        void CleanupXray0Adapter()
        {
            std::string delErr;
            datagate::wintun::WintunHolder cleaner;
            if (!cleaner.TryDeleteAdapterByName(L"xray0", delErr) && !delErr.empty())
                store.PublishLogLine(std::string("[xray] xray0 cleanup warn: ") + delErr);
            else
                store.PublishLogLine("[xray] xray0 cleanup ok");
        }

        void StopAllNoCallbacks(bool joinWatch = true)
        {
            if (joinWatch)
                StopXrayWatch();
            else
                xrayWatchStop.store(true);

            if (xrayActive || xray.IsLoaded())
            {
                store.PublishLogLine("[session] StopAllNoCallbacks: xray.Stop()...");
                std::string xerr;
                xray.Stop(xerr);
                if (!xerr.empty())
                    store.PublishLogLine("[session] xray.Stop note: " + xerr);
                xrayActive = false;
                CleanupXray0Adapter();
                store.PublishLogLine("[session] StopAllNoCallbacks: xray.Stop() done");
            }

            store.PublishLogLine("[session] StopAllNoCallbacks: vpn.Stop()...");
            vpn.Stop();
            store.PublishLogLine("[session] StopAllNoCallbacks: vpn.Stop() done");

            store.PublishLogLine("[session] StopAllNoCallbacks: bridge.Deactivate()...");
            bridge.Stop();
            store.PublishLogLine("[session] StopAllNoCallbacks: bridge.Deactivate() done");
        }
    };

    SessionController::SessionController()
        : _impl(new Impl())
    {
        RefreshCallbacksToStore();
    }

    SessionController::~SessionController()
    {
        Stop();
        _impl->StopXrayWatch();
        _impl->bridge.Stop();
        delete _impl;
        _impl = nullptr;
    }

    void SessionController::RefreshCallbacksToStore()
    {
        _impl->SyncCallbacksFromController(*this);
    }

    bool SessionController::Start(const StartOptions& opt, std::string& outError)
    {
        RefreshCallbacksToStore();

        _impl->store.PublishLogLine("[session] Start() ENTER");

        if (!_impl->store.TryEnterStarting(outError))
        {
            _impl->store.PublishLogLine(std::string("[session] Start() rejected: ") + outError);
            return false;
        }

        _impl->store.SetLastStartOptions(opt);
        _impl->store.PublishStateSnapshot();

        const auto protocol = NormalizeProtocol(opt.protocol);
        _impl->store.PublishLogLine("[session] protocol=" + protocol);

        if (protocol == "xray")
            return StartXray(opt, outError);

        if (protocol != "openvpn")
        {
            const std::string code = "unsupported_protocol";
            const std::string msg = "Unsupported protocol: " + protocol;
            _impl->store.SetError(code, msg);
            _impl->store.PublishError(code, msg, true);
            outError = msg;
            ReportSessionStartFailure(code, msg);
            _impl->StopAllNoCallbacks();
            _impl->store.SetPhase(SessionPhase::Idle);
            _impl->store.PublishStateSnapshot();
            return false;
        }

        return StartOpenVpn(opt, outError);
    }

    bool SessionController::StartXray(const StartOptions& opt, std::string& outError)
    {
        auto failIdle = [&](const std::string& code, const std::string& msg) -> bool
        {
            _impl->store.SetError(code, msg);
            _impl->store.PublishError(code, msg, true);
            _impl->store.PublishStateSnapshot();
            outError = msg;
            ReportSessionStartFailure(code, msg);
            _impl->store.PublishLogLine(std::string("[session] StartXray() FAIL: ") + msg);
            _impl->StopAllNoCallbacks();
            _impl->store.SetPhase(SessionPhase::Idle);
            _impl->store.PublishStateSnapshot();
            return false;
        };

        _impl->store.PublishLogLine("[xray] StartXray() ENTER");
        _impl->store.SetPhase(SessionPhase::Connecting);
        _impl->store.PublishStateSnapshot();

        std::string loadErr;
        if (!_impl->xray.EnsureLoaded(loadErr))
            return failIdle("xray_load_failed", loadErr.empty() ? "Failed to load libXray.dll" : loadErr);

        {
            const auto ver = _impl->xray.VersionOrEmpty();
            if (!ver.empty())
                _impl->store.PublishLogLine("[xray] libXray version=" + ver);
        }

        std::string outboundsJson = opt.xrayConfigJson;
        std::string profileExtrasSource = outboundsJson;
        std::vector<std::string> tunnelDns;

        if (outboundsJson.empty())
        {
            if (opt.xrayShareLinks.empty())
                return failIdle("xray_bad_payload", "Missing xrayShareLinks / xrayConfigJson");

            profileExtrasSource = opt.xrayShareLinks;
            // Issued API bodies may be JSON with "vless" + dnsServers + mux.
            auto share = datagate::xray::XrayConfigBuilder::ExtractShareLinkOrEmpty(opt.xrayShareLinks);
            if (share.empty())
                share = opt.xrayShareLinks;

            // If payload already contains outbounds, skip convert.
            {
                std::string probeErr;
                std::string probeConfig;
                if (datagate::xray::XrayConfigBuilder::BuildWindowsTunClientConfig(
                        opt.xrayShareLinks, probeConfig, probeErr))
                {
                    outboundsJson = opt.xrayShareLinks;
                    _impl->store.PublishLogLine("[xray] input already has outbounds — skip convert");
                }
                else
                {
                    _impl->store.PublishLogLine("[xray] convertShareLinksToXrayJson...");
                    std::string convErr;
                    if (!_impl->xray.ConvertShareLinksToXrayJson(share, outboundsJson, convErr))
                        return failIdle("xray_convert_failed",
                                        convErr.empty() ? "convertShareLinksToXrayJson failed" : convErr);
                    _impl->store.PublishLogLine("[xray] convert OK bytes=" + std::to_string(outboundsJson.size()));
                }
            }
        }
        else
        {
            _impl->store.PublishLogLine("[xray] using provided xrayConfigJson bytes=" + std::to_string(outboundsJson.size()));
        }

        // Pull DNS from original issued profile text when present.
        {
            Json::CharReaderBuilder b;
            Json::Value root;
            std::string errs;
            std::unique_ptr<Json::CharReader> reader(b.newCharReader());
            const auto& src = profileExtrasSource.empty() ? outboundsJson : profileExtrasSource;
            if (!src.empty() && src.front() == '{'
                && reader->parse(src.data(), src.data() + src.size(), &root, &errs)
                && root.isObject())
            {
                const Json::Value* dnsArr = nullptr;
                if (root.isMember("dnsServers") && root["dnsServers"].isArray())
                    dnsArr = &root["dnsServers"];
                else if (root.isMember("DnsServers") && root["DnsServers"].isArray())
                    dnsArr = &root["DnsServers"];
                if (dnsArr)
                {
                    for (const auto& d : *dnsArr)
                        if (d.isString() && !d.asString().empty())
                            tunnelDns.push_back(d.asString());
                }

                // Preserve top-level mux onto outbounds wrapper for NormalizeMux in builder.
                if (root.isMember("mux") && root["mux"].isObject())
                {
                    Json::Value wrap(Json::objectValue);
                    Json::Value converted;
                    std::string perr;
                    std::unique_ptr<Json::CharReader> reader2(b.newCharReader());
                    if (reader2->parse(outboundsJson.data(), outboundsJson.data() + outboundsJson.size(), &converted, &perr))
                    {
                        if (converted.isArray())
                            wrap["outbounds"] = converted;
                        else if (converted.isObject() && converted.isMember("outbounds"))
                            wrap["outbounds"] = converted["outbounds"];
                        else
                            wrap = converted;
                        wrap["mux"] = root["mux"];
                        Json::StreamWriterBuilder wb;
                        wb["indentation"] = "";
                        outboundsJson = Json::writeString(wb, wrap);
                    }
                }
            }
        }

        for (const auto& d : opt.dnsServers)
        {
            if (d.empty())
                continue;
            if (std::find(tunnelDns.begin(), tunnelDns.end(), d) == tunnelDns.end())
                tunnelDns.push_back(d);
        }

        auto bypass = datagate::xray::XrayConfigBuilder::CollectProxyEndpointCidrs(outboundsJson);
        for (const auto& cidr : opt.directBypassCidrs)
        {
            if (!cidr.empty())
                bypass.push_back(cidr);
        }

        std::string fullConfig;
        std::string buildErr;
        if (!datagate::xray::XrayConfigBuilder::BuildWindowsTunClientConfig(
                outboundsJson, fullConfig, buildErr, bypass, tunnelDns))
            return failIdle("xray_config_failed", buildErr.empty() ? "BuildWindowsTunClientConfig failed" : buildErr);

        _impl->store.PublishLogLine("[xray] runXrayFromJson configBytes=" + std::to_string(fullConfig.size())
                                    + " bypassCidrs=" + std::to_string(bypass.size())
                                    + " tunnelDns=" + std::to_string(tunnelDns.size()));

        // Stale "xray0" from a previous crashed session causes:
        // "Cannot create a file when that file already exists."
        {
            std::string stopErr;
            (void)_impl->xray.Stop(stopErr);
            _impl->CleanupXray0Adapter();
        }

        std::string runErr;
        if (!_impl->xray.RunFromJson(fullConfig, runErr))
        {
            // One retry after forced cleanup — common after UI crash left engine/TUN half-alive.
            std::string stopErr2;
            (void)_impl->xray.Stop(stopErr2);
            _impl->CleanupXray0Adapter();
            runErr.clear();
            if (!_impl->xray.RunFromJson(fullConfig, runErr))
                return failIdle("xray_start_failed", runErr.empty() ? "runXrayFromJson failed" : runErr);
        }

        {
            std::string stateErr;
            if (!_impl->xray.IsRunning(stateErr))
            {
                const std::string msg = stateErr.empty()
                    ? "libXray reported not running after runXrayFromJson"
                    : stateErr;
                return failIdle("xray_not_running", msg);
            }
        }

        _impl->xrayActive = true;
        _impl->StartXrayWatch();

        _impl->store.ResetDisconnectDedup();
        _impl->store.SetPhase(SessionPhase::Connected);
        _impl->store.PublishStateSnapshot();

        ConnectedInfo ci{};
        ci.vpnIfIndex = -1;
        _impl->store.PublishConnected(ci);
        _impl->store.PublishLogLine("[xray] connected (TUN via libXray; wintun.dll must sit beside engine.exe)");
        _impl->store.PublishLogLine("[session] StartXray() EXIT ok=true");
        return true;
    }

    bool SessionController::StartOpenVpn(const StartOptions& opt, std::string& outError)
    {
        // 0) Ensure Wintun adapter exists
        {
            std::string tunErr;
            _impl->store.PublishLogLine("[session] EnsureReady(Wintun)...");
            if (!_impl->wintun.EnsureReady(tunErr))
            {
                const std::string code = "tun_init_failed";
                const std::string msg = "Failed to init Wintun adapter: " + tunErr;

                _impl->store.SetError(code, msg);
                _impl->store.PublishError(code, msg, true);
                _impl->store.PublishStateSnapshot();

                outError = msg;
                ReportSessionStartFailure(code, msg);
                _impl->store.PublishLogLine(std::string("[session] Start() FAIL: ") + msg);
                // Leave Idle so a later StartSession is not blocked on a sticky Error/Stopped.
                _impl->StopAllNoCallbacks();
                _impl->store.SetPhase(SessionPhase::Idle);
                _impl->store.PublishStateSnapshot();
                return false;
            }

            if (auto idx = _impl->wintun.GetIfIndex())
                _impl->store.PublishLogLine("[session] wintun adapter ifIndex=" + std::to_string(*idx));
            else
                _impl->store.PublishLogLine("[session] wintun adapter ifIndex=<unknown>");
        }

        // 1) Optional local WSS->(TCP/UDP) bridge (catalog path). Imported profiles skip this.
        std::string localIp;
        uint16_t localPort = 0;
        if (opt.useWssBridge)
        {
            std::string bridgeErr;
            _impl->store.PublishLogLine("[session] bridge.Activate()...");
            if (!_impl->bridge.Activate(opt, bridgeErr))
            {
                const std::string code = "bridge_start_failed";
                const std::string msg = bridgeErr.empty() ? std::string("Failed to activate WSS bridge") : bridgeErr;

                _impl->store.SetError(code, msg);
                _impl->store.PublishError(code, msg, true);
                _impl->store.PublishStateSnapshot();

                outError = msg;
                ReportSessionStartFailure(code, msg);
                _impl->store.PublishLogLine(std::string("[session] Start() FAIL: ") + msg);
                _impl->StopAllNoCallbacks();
                _impl->store.SetPhase(SessionPhase::Idle);
                _impl->store.PublishStateSnapshot();
                return false;
            }

            {
                std::ostringstream oss;
                oss << "[session] bridge.Activate() OK"
                    << " listenIp=" << _impl->bridge.ListenIp()
                    << " listenPort=" << _impl->bridge.ListenPort();
                _impl->store.PublishLogLine(oss.str());
            }

            localIp = _impl->bridge.ListenIp();
            localPort = _impl->bridge.ListenPort();
            _impl->store.SetPhase(SessionPhase::Connecting);
            _impl->store.PublishStateSnapshot();
        }
        else
        {
            _impl->store.PublishLogLine("[session] useWssBridge=false — direct OpenVPN");
            _impl->store.SetPhase(SessionPhase::Connecting);
            _impl->store.PublishStateSnapshot();
        }

        // 2) Patch OVPN for bridge, or keep remotes for direct mode; validate; add windows-driver
        {
            std::ostringstream oss;
            if (opt.useWssBridge)
                oss << "[session] ovpn.BuildForLocalBridge() local=" << localIp << ":" << localPort;
            else
                oss << "[session] ovpn.BuildDirect()";
            _impl->store.PublishLogLine(oss.str());
        }

        OvpnBuildResult built;
        if (opt.useWssBridge)
        {
            const bool useUdp = ovpn::IsUdpProto(ovpn::ResolveTransportProto(opt.ovpnContentUtf8));
            built = _impl->ovpn.BuildForLocalBridge(opt.ovpnContentUtf8, localIp, localPort, useUdp);
        }
        else
        {
            built = _impl->ovpn.BuildDirect(opt.ovpnContentUtf8);
        }

        {
            std::string ovpnErr;
            _impl->store.PublishLogLine("[session] ovpn.ValidateSingleRemote()...");
            if (!_impl->ovpn.ValidateSingleRemote(built.config, ovpnErr))
            {
                const std::string code = "ovpn_invalid_remote";
                const std::string msg = ovpnErr.empty() ? std::string("Invalid remote lines in OVPN config") : ovpnErr;

                _impl->store.PublishError(code, msg, true);
                outError = msg;

                ReportSessionStartFailure(code, msg);
                _impl->store.PublishLogLine(std::string("[session] Start() FAIL: ") + msg);
                Stop();
                return false;
            }
            _impl->store.PublishLogLine("[session] ovpn.ValidateSingleRemote() OK");
        }

        // 2.2) Log diagnostics (same info as before)
        {
            const auto& d = built.diag;

            _impl->store.PublishLogLine(
                std::string("[session] ovpn bytes=") + std::to_string(d.bytes) +
                " has<ca>=" + (d.hasCa ? "1" : "0") +
                " has<cert>=" + (d.hasCert ? "1" : "0") +
                " has<key>=" + (d.hasKey ? "1" : "0"));

            _impl->store.PublishLogLine(
                std::string("[session] has <ca>=") + (d.hasCa ? "1" : "0") +
                " <cert>=" + (d.hasCert ? "1" : "0") +
                " <key>=" + (d.hasKey ? "1" : "0") +
                " tls-crypt=" + (d.hasTlsCrypt ? "1" : "0"));

            _impl->store.PublishLogLine("[session] ovpn preview (first lines) begin");
            _impl->store.PublishLogLine(d.previewFirstLines);
            _impl->store.PublishLogLine("[session] ovpn preview (first lines) end");

            if (!d.windowsDriverLines.empty())
            {
                _impl->store.PublishLogLine("[session] ovpn windows-driver lines:");
                _impl->store.PublishLogLine(d.windowsDriverLines);
            }
            else
            {
                _impl->store.PublishLogLine("[session] ovpn windows-driver lines: <none>");
            }

            if (!d.devLines.empty())
            {
                _impl->store.PublishLogLine("[session] ovpn dev/dev-type lines:");
                _impl->store.PublishLogLine(d.devLines);
            }
        }

        // 3) Start VPN
        {
            std::string vpnErr;
            _impl->store.PublishLogLine("[session] vpn.Start()...");

            std::string guiVer = opt.guiVersion;
            if (guiVer.empty())
                guiVer = "3.11.7_datagate_windows_1.0.14";

            if (!_impl->vpn.Start(built.config, guiVer, vpnErr))
            {
                const std::string code = "vpn_start_failed";
                const std::string msg = vpnErr.empty() ? std::string("VPN start failed") : vpnErr;

                _impl->store.SetError(code, msg);
                _impl->store.PublishError(code, msg, true);

                _impl->store.PublishLogLine(std::string("[session] Start() FAIL: ") + msg);
                Stop();

                outError = msg;
                ReportSessionStartFailure(code, msg);
                return false;
            }

            _impl->store.PublishLogLine("[session] vpn.Start() OK");
        }

        _impl->store.PublishLogLine("[session] Start() EXIT ok=true");
        return true;
    }

    void SessionController::Stop()
    {
        RefreshCallbacksToStore();

        const auto before = _impl->store.GetState();
        {
            std::ostringstream oss;
            oss << "[session] Stop() ENTER"
                << " phase=" << ToString(before.phase);
            _impl->store.PublishLogLine(oss.str());
        }

        const bool canStop =
            before.IsRunning()
            || before.phase == SessionPhase::Error
            || before.phase == SessionPhase::Stopped;
        if (!canStop)
        {
            if (before.phase == SessionPhase::Idle)
                _impl->store.PublishLogLine("[session] Stop() ignored: already idle");
            else
                _impl->store.PublishLogLine("[session] Stop() ignored: not running");
            return;
        }

        const bool wasXray = _impl->xrayActive;
        const bool shouldEmitDisconnected =
            wasXray
            && (before.phase == SessionPhase::Connected
                || before.phase == SessionPhase::Connecting
                || before.phase == SessionPhase::Starting)
            && _impl->store.MarkDisconnectedOnce();

        if (before.phase != SessionPhase::Stopping)
        {
            _impl->store.SetPhase(SessionPhase::Stopping);
            _impl->store.PublishStateSnapshot();
            _impl->store.PublishLogLine("[session] Stop() phase set to Stopping");
        }

        _impl->StopAllNoCallbacks();

        const auto mid = _impl->store.GetState();
        {
            std::ostringstream oss;
            oss << "[session] Stop() after StopAllNoCallbacks"
                << " phase=" << ToString(mid.phase);
            _impl->store.PublishLogLine(oss.str());
        }

        if (_impl->store.GetState().phase != SessionPhase::Idle)
        {
            _impl->store.SetPhase(SessionPhase::Idle);
            _impl->store.PublishStateSnapshot();
            _impl->store.PublishLogLine("[session] Stop() phase forced to Idle");
        }

        if (shouldEmitDisconnected)
        {
            _impl->store.PublishDisconnected("user_stop");
            _impl->store.PublishLogLine("[session] xray disconnected event published (user_stop)");
        }

        const auto after = _impl->store.GetState();
        {
            std::ostringstream oss;
            oss << "[session] Stop() EXIT"
                << " phase=" << ToString(after.phase);
            _impl->store.PublishLogLine(oss.str());
        }
    }

    SessionState SessionController::GetState() const
    {
        return _impl->store.GetState();
    }
}
