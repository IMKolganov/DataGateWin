#include "SessionController.h"

#include "BridgeManager.h"
#include "OvpnConfigProcessor.h"
#include "SessionStateStore.h"
#include "VpnSessionRunner.h"
#include "WintunAdapterManager.h"
#include "bridge/client/WssTcpBridge.h"

#include <mutex>
#include <sstream>
#include <utility>

namespace datagate::session
{
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
            vpn.SetCallbacks(
                [this](const std::string& line)
                {
                    store.PublishLogLine("[ovpn] " + line);
                },
                [this](const datagate::vpn::VpnRunner::ConnectedInfo& ci)
                {
                    // Update state to Connected and publish
                    store.ResetDisconnectDedup();

                    store.SetPhase(SessionPhase::Connected);
                    store.PublishStateSnapshot();

                    ConnectedInfo x{};
                    x.vpnIfIndex = ci.vpnIfIndex;
                    x.vpnIpv4 = ci.vpnIpv4;
                    store.PublishConnected(x);
                },
                [this](const std::string& reason)
                {
                    const bool shouldEmitDisconnected = store.MarkDisconnectedOnce();

                    // Only move to Stopped if it was a running phase
                    const auto st = store.GetState();
                    const bool wasRunning =
                        st.phase == SessionPhase::Connected ||
                        st.phase == SessionPhase::Connecting ||
                        st.phase == SessionPhase::Starting;

                    if (wasRunning)
                    {
                        store.SetPhase(SessionPhase::Stopped);
                        store.PublishStateSnapshot();
                    }

                    if (shouldEmitDisconnected)
                        store.PublishDisconnected(reason);
                });
        }

        void SyncCallbacksFromController(const SessionController& c)
        {
            store.SetCallbacks(c.OnStateChanged, c.OnLog, c.OnError, c.OnConnected, c.OnDisconnected);
        }

        void StopAllNoCallbacks()
        {
            vpn.Stop();
            bridge.Stop();
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

        if (!_impl->store.TryEnterStarting(outError))
            return false;

        _impl->store.SetLastStartOptions(opt);
        _impl->store.PublishStateSnapshot();

        // 0) Ensure Wintun adapter exists
        {
            std::string tunErr;
            if (!_impl->wintun.EnsureReady(tunErr))
            {
                const std::string code = "tun_init_failed";
                const std::string msg = "Failed to init Wintun adapter: " + tunErr;

                _impl->store.SetError(code, msg);
                _impl->store.PublishError(code, msg, true);
                _impl->store.PublishStateSnapshot();

                outError = msg;
                return false;
            }

            if (auto idx = _impl->wintun.GetIfIndex())
                _impl->store.PublishLogLine("[session] wintun adapter ifIndex=" + std::to_string(*idx));
            else
                _impl->store.PublishLogLine("[session] wintun adapter ifIndex=<unknown>");
        }

        // 1) Start local WSS->TCP bridge
        {
            std::string bridgeErr;
            if (!_impl->bridge.Start(opt, bridgeErr))
            {
                const std::string code = "bridge_start_failed";
                const std::string msg = bridgeErr.empty() ? std::string("Failed to start WSS TCP bridge") : bridgeErr;

                _impl->store.SetError(code, msg);
                _impl->store.PublishError(code, msg, true);
                _impl->store.PublishStateSnapshot();

                outError = msg;
                return false;
            }

            _impl->store.SetPhase(SessionPhase::Connecting);
            _impl->store.PublishStateSnapshot();
        }

        // 2) Patch OVPN to point to local bridge, validate, add windows-driver
        const std::string localIp = _impl->bridge.ListenIp();
        const uint16_t localPort = _impl->bridge.ListenPort();

        auto built = _impl->ovpn.BuildForLocalBridge(opt.ovpnContentUtf8, localIp, localPort);

        {
            std::string ovpnErr;
            if (!_impl->ovpn.ValidateSingleRemote(built.config, ovpnErr))
            {
                const std::string code = "ovpn_invalid_remote";
                const std::string msg = ovpnErr.empty() ? std::string("Invalid remote lines in OVPN config") : ovpnErr;

                _impl->store.PublishError(code, msg, true);
                outError = msg;

                Stop();
                return false;
            }
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
            if (!_impl->vpn.Start(built.config, vpnErr))
            {
                const std::string code = "vpn_start_failed";
                const std::string msg = vpnErr.empty() ? std::string("VPN start failed") : vpnErr;

                _impl->store.SetError(code, msg);
                _impl->store.PublishError(code, msg, true);

                Stop();

                outError = msg;
                return false;
            }
        }

        return true;
    }

    void SessionController::Stop()
    {
        RefreshCallbacksToStore();

        const auto st = _impl->store.GetState();
        const bool canStop = st.IsRunning() || st.phase == SessionPhase::Error;

        if (!canStop)
            return;

        if (st.phase != SessionPhase::Stopping)
        {
            _impl->store.SetPhase(SessionPhase::Stopping);
            _impl->store.PublishStateSnapshot();
        }

        _impl->StopAllNoCallbacks();

        if (_impl->store.GetState().phase != SessionPhase::Stopped)
        {
            _impl->store.SetPhase(SessionPhase::Stopped);
            _impl->store.PublishStateSnapshot();
        }
    }

    SessionState SessionController::GetState() const
    {
        return _impl->store.GetState();
    }
}
