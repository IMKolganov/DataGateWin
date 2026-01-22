#include "SessionController.h"

#include "bridge/client/WssTcpBridge.h"
#include "vpn/VpnRunner.h"

#include <utility>

namespace datagate::session
{
    static SessionState WithPhase(SessionState st, SessionPhase phase)
    {
        st.phase = phase;
        return st;
    }

    std::string SessionController::PatchOvpnRemoteToLocal(const std::string& ovpn, const std::string& localHost, uint16_t localPort)
    {
        std::string patched;
        patched.reserve(ovpn.size() + 128);

        patched += "remote ";
        patched += localHost;
        patched += " ";
        patched += std::to_string(localPort);
        patched += "\n";

        patched += ovpn;
        return patched;
    }

    std::string SessionController::DefaultListenIp(const StartOptions& opt)
    {
        return opt.bridge.listenIp.empty() ? std::string("127.0.0.1") : opt.bridge.listenIp;
    }

    uint16_t SessionController::DefaultListenPort(const StartOptions& opt)
    {
        return opt.bridge.listenPort == 0 ? static_cast<uint16_t>(18080) : opt.bridge.listenPort;
    }

    SessionController::SessionController()
    {
        // Wire VPN callbacks once. They read user callbacks atomically (copy under lock), then invoke outside lock.
        _vpn.OnConnected = [this](const datagate::vpn::VpnRunner::ConnectedInfo& ci)
        {
            ConnectedCallback onConnected;
            StateChangedCallback onStateChanged;
            SessionState snapshot;

            {
                std::lock_guard<std::mutex> lock(_mtx);

                if (OnConnected) onConnected = OnConnected;
                if (OnStateChanged) onStateChanged = OnStateChanged;

                _state.phase = SessionPhase::Connected;
                snapshot = _state;
            }

            if (onConnected)
            {
                ConnectedInfo x{};
                x.vpnIfIndex = ci.vpnIfIndex;
                x.vpnIpv4 = ci.vpnIpv4;
                onConnected(x);
            }

            if (onStateChanged)
                onStateChanged(snapshot);
        };

        _vpn.OnDisconnected = [this](const std::string& reason)
        {
            DisconnectedCallback onDisconnected;
            StateChangedCallback onStateChanged;
            SessionState snapshot;

            {
                std::lock_guard<std::mutex> lock(_mtx);

                if (OnDisconnected) onDisconnected = OnDisconnected;
                if (OnStateChanged) onStateChanged = OnStateChanged;

                if (_state.phase == SessionPhase::Connected || _state.phase == SessionPhase::Connecting)
                    _state.phase = SessionPhase::Stopped;

                snapshot = _state;
            }

            if (onDisconnected)
                onDisconnected(reason);

            if (onStateChanged)
                onStateChanged(snapshot);
        };
    }

    SessionController::~SessionController()
    {
        Stop();
    }

    void SessionController::PublishState(const SessionState& snapshot)
    {
        auto cb = OnStateChanged;
        if (cb) cb(snapshot);
    }

    void SessionController::PublishError(const std::string& code, const std::string& message, bool fatal)
    {
        auto cb = OnError;
        if (cb) cb(code, message, fatal);
    }

    bool SessionController::Start(const StartOptions& opt, std::string& outError)
    {
        StateChangedCallback onStateChanged;
        ErrorCallback onError;
        LogCallback onLog;

        {
            std::lock_guard<std::mutex> lock(_mtx);

            if (_state.IsRunning())
            {
                outError = "Session already running";
                return false;
            }

            _lastStart = opt;
            _state.lastErrorCode.clear();
            _state.lastErrorMessage.clear();
            _state.phase = SessionPhase::Starting;

            onStateChanged = OnStateChanged;
            onError = OnError;
            onLog = OnLog;
        }

        if (onStateChanged) onStateChanged(GetState());

        // 1) Start local WSS->TCP bridge
        try
        {
            WssTcpBridge::Options bo;
            bo.host = opt.bridge.host;
            bo.port = opt.bridge.port;
            bo.path = opt.bridge.path;
            bo.sni = opt.bridge.sni;
            bo.listenIp = DefaultListenIp(opt);
            bo.listenPort = DefaultListenPort(opt);
            bo.verifyServerCert = opt.bridge.verifyServerCert;
            bo.authorizationHeader = opt.bridge.authorizationHeader;

            auto bridge = std::make_unique<WssTcpBridge>(std::move(bo));
            bridge->Start();

            {
                std::lock_guard<std::mutex> lock(_mtx);
                _bridge = std::move(bridge);
                _state.phase = SessionPhase::Connecting;
            }

            if (onStateChanged) onStateChanged(GetState());
        }
        catch (...)
        {
            const std::string code = "bridge_start_failed";
            const std::string msg = "Failed to start WSS TCP bridge";

            {
                std::lock_guard<std::mutex> lock(_mtx);
                _state.lastErrorCode = code;
                _state.lastErrorMessage = msg;
                _state.phase = SessionPhase::Error;
            }

            if (onError) onError(code, msg, true);
            if (onStateChanged) onStateChanged(GetState());

            outError = msg;
            return false;
        }

        // 2) Patch OVPN to point to local bridge
        const auto ovpnPatched = PatchOvpnRemoteToLocal(
            opt.ovpnContentUtf8,
            DefaultListenIp(opt),
            DefaultListenPort(opt)
        );

        // Optional debug signal (no secrets printed)
        if (onLog)
        {
            const bool hasCert = ovpnPatched.find("<cert>") != std::string::npos;
            const bool hasKey  = ovpnPatched.find("<key>")  != std::string::npos;
            const bool hasCa   = ovpnPatched.find("<ca>")   != std::string::npos;

            onLog(std::string("[session] ovpn bytes=") + std::to_string(ovpnPatched.size())
                + " has<ca>=" + (hasCa ? "1" : "0")
                + " has<cert>=" + (hasCert ? "1" : "0")
                + " has<key>=" + (hasKey ? "1" : "0"));
        }

        // 3) Start VPN
        std::string vpnErr;

        auto has = [&](const char* x){ return ovpnPatched.find(x) != std::string::npos; };

        if (OnLog)
        {
            OnLog(std::string("[session] has <ca>=") + (has("<ca>") ? "1":"0") +
                  " <cert>=" + (has("<cert>") ? "1":"0") +
                  " <key>=" + (has("<key>") ? "1":"0") +
                  " tls-crypt=" + (has("<tls-crypt>") ? "1":"0"));
        }
        if (!_vpn.Start(ovpnPatched, vpnErr))
        {
            const std::string code = "vpn_start_failed";
            const std::string msg = vpnErr.empty() ? std::string("VPN start failed") : vpnErr;

            {
                std::lock_guard<std::mutex> lock(_mtx);
                _state.lastErrorCode = code;
                _state.lastErrorMessage = msg;
                _state.phase = SessionPhase::Error;
            }

            if (onError) onError(code, msg, true);

            // Stop bridge safely (no callbacks under lock)
            Stop();

            outError = msg;
            return false;
        }

        return true;
    }

    void SessionController::StopLockedNoCallbacks()
    {
        // Caller holds _mtx
        try { _vpn.Stop(); } catch (...) { }

        if (_bridge)
        {
            try { _bridge->Stop(); } catch (...) { }
            _bridge.reset();
        }
    }

    void SessionController::Stop()
    {
        StateChangedCallback onStateChanged;

        {
            std::lock_guard<std::mutex> lock(_mtx);

            if (!_state.IsRunning() && _state.phase != SessionPhase::Error)
                return;

            _state.phase = SessionPhase::Stopping;
            onStateChanged = OnStateChanged;
        }

        if (onStateChanged) onStateChanged(GetState());

        {
            std::lock_guard<std::mutex> lock(_mtx);
            StopLockedNoCallbacks();
            _state.phase = SessionPhase::Stopped;
            onStateChanged = OnStateChanged;
        }

        if (onStateChanged) onStateChanged(GetState());
    }

    SessionState SessionController::GetState() const
    {
        std::lock_guard<std::mutex> lock(_mtx);
        return _state;
    }
}
