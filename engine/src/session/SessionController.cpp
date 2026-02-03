// SessionController.cpp (only minimal text changes, full file returned as requested)
#include "SessionController.h"

#include "BridgeManager.h"
#include "OvpnConfigProcessor.h"
#include "SessionStateStore.h"
#include "VpnSessionRunner.h"
#include "WintunAdapterManager.h"

#include <mutex>
#include <sstream>
#include <utility>

namespace datagate::session
{
    static const char* GuessStopInitiator(SessionPhase phase)
    {
        // Best-effort guess based on current phase at the moment callback fires.
        // - If we are in Stopping => most likely user initiated StopSession
        // - Otherwise => transport/network error or remote close
        if (phase == SessionPhase::Stopping)
            return "user_stop";

        return "transport_error";
    }

    class SessionController::Impl
    {
    public:
        SessionStateStore store;
        WintunAdapterManager wintun;
        BridgeManager bridge;
        OvpnConfigProcessor ovpn;
        VpnSessionRunner vpn;

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
                        store.SetPhase(SessionPhase::Stopped);
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

        void StopAllNoCallbacks()
        {
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
                _impl->store.PublishLogLine(std::string("[session] Start() FAIL: ") + msg);
                return false;
            }

            if (auto idx = _impl->wintun.GetIfIndex())
                _impl->store.PublishLogLine("[session] wintun adapter ifIndex=" + std::to_string(*idx));
            else
                _impl->store.PublishLogLine("[session] wintun adapter ifIndex=<unknown>");
        }

        // 1) Start local WSS->(TCP/UDP) bridge
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
                _impl->store.PublishLogLine(std::string("[session] Start() FAIL: ") + msg);
                return false;
            }

            {
                std::ostringstream oss;
                oss << "[session] bridge.Activate() OK"
                    << " listenIp=" << _impl->bridge.ListenIp()
                    << " listenPort=" << _impl->bridge.ListenPort();
                _impl->store.PublishLogLine(oss.str());
            }

            _impl->store.SetPhase(SessionPhase::Connecting);
            _impl->store.PublishStateSnapshot();
        }

        // 2) Patch OVPN to point to local bridge, validate, add windows-driver
        const std::string localIp = _impl->bridge.ListenIp();
        const uint16_t localPort = _impl->bridge.ListenPort();

        {
            std::ostringstream oss;
            oss << "[session] ovpn.BuildForLocalBridge() local=" << localIp << ":" << localPort;
            _impl->store.PublishLogLine(oss.str());
        }

        auto built = _impl->ovpn.BuildForLocalBridge(opt.ovpnContentUtf8, localIp, localPort);

        {
            std::string ovpnErr;
            _impl->store.PublishLogLine("[session] ovpn.ValidateSingleRemote()...");
            if (!_impl->ovpn.ValidateSingleRemote(built.config, ovpnErr))
            {
                const std::string code = "ovpn_invalid_remote";
                const std::string msg = ovpnErr.empty() ? std::string("Invalid remote lines in OVPN config") : ovpnErr;

                _impl->store.PublishError(code, msg, true);
                outError = msg;

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
            if (!_impl->vpn.Start(built.config, vpnErr))
            {
                const std::string code = "vpn_start_failed";
                const std::string msg = vpnErr.empty() ? std::string("VPN start failed") : vpnErr;

                _impl->store.SetError(code, msg);
                _impl->store.PublishError(code, msg, true);

                _impl->store.PublishLogLine(std::string("[session] Start() FAIL: ") + msg);
                Stop();

                outError = msg;
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

        const bool canStop = before.IsRunning() || before.phase == SessionPhase::Error;
        if (!canStop)
        {
            _impl->store.PublishLogLine("[session] Stop() ignored: not running");
            return;
        }

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
