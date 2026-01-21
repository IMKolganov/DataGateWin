#include "SessionController.h"

#include "bridge/client/WssTcpBridge.h"
#include "vpn/VpnRunner.h"

#include <utility>

namespace datagate::session
{
    static std::string PatchOvpnRemoteToLocal(const std::string& ovpn, const std::string& localHost, uint16_t localPort)
    {
        // Minimal, safe patch:
        // - prepend a local remote
        // - do NOT try to parse full OpenVPN grammar here
        // This works because OpenVPN uses the first effective "remote" unless random/remote-random.
        // If you later need stronger transform, implement it in OvpnTransform.cpp and call it here.

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

    SessionController::SessionController()
        : _state{}
    {
    }

    SessionController::~SessionController()
    {
        Stop();
    }

    bool SessionController::Start(const StartOptions& opt, std::string& outError)
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

        SetPhase(SessionPhase::Starting);

        // 1) Start local WSS->TCP bridge
        try
        {
            WssTcpBridge::Options bo;
            bo.host = opt.bridge.host;
            bo.port = opt.bridge.port;
            bo.path = opt.bridge.path;
            bo.sni = opt.bridge.sni;
            bo.listenIp = opt.bridge.listenIp;
            bo.listenPort = opt.bridge.listenPort;
            bo.verifyServerCert = opt.bridge.verifyServerCert;
            bo.authorizationHeader = opt.bridge.authorizationHeader;

            _bridge = new WssTcpBridge(std::move(bo));
            _bridge->Start();
        }
        catch (...)
        {
            SetError("bridge_start_failed", "Failed to start WSS TCP bridge", true);
            outError = _state.lastErrorMessage;
            SetPhase(SessionPhase::Error);
            return false;
        }

        SetPhase(SessionPhase::Connecting);

        // 2) Patch OVPN to point to local bridge
        const auto ovpnPatched = PatchOvpnRemoteToLocal(
            opt.ovpnContentUtf8,
            opt.bridge.listenIp.empty() ? std::string("127.0.0.1") : opt.bridge.listenIp,
            opt.bridge.listenPort == 0 ? static_cast<uint16_t>(18080) : opt.bridge.listenPort
        );

        // 3) Wire VPN callbacks
        _vpn.OnConnected = [&](const datagate::vpn::VpnRunner::ConnectedInfo& ci)
        {
            if (OnConnected)
            {
                ConnectedInfo x{};
                x.vpnIfIndex = ci.vpnIfIndex;
                x.vpnIpv4 = ci.vpnIpv4;
                OnConnected(x);
            }

            // update state
            {
                std::lock_guard<std::mutex> lock2(_mtx);
                _state.phase = SessionPhase::Connected;
            }

            if (OnStateChanged)
                OnStateChanged(GetState());
        };

        _vpn.OnDisconnected = [&](const std::string& reason)
        {
            if (OnDisconnected)
                OnDisconnected(reason);

            {
                std::lock_guard<std::mutex> lock2(_mtx);
                // If it was an intentional stop, phase will already be Stopping/Stopped.
                if (_state.phase == SessionPhase::Connected || _state.phase == SessionPhase::Connecting)
                    _state.phase = SessionPhase::Stopped;
            }

            if (OnStateChanged)
                OnStateChanged(GetState());
        };

        // 4) Start VPN (string-based API, no OpenVPN headers here)
        if (!_vpn.Start(ovpnPatched, outError))
        {
            SetError("vpn_start_failed", outError.empty() ? "VPN start failed" : outError, true);

            // cleanup bridge
            try
            {
                if (_bridge)
                {
                    _bridge->Stop();
                    delete _bridge;
                    _bridge = nullptr;
                }
            }
            catch (...)
            {
            }

            SetPhase(SessionPhase::Error);
            return false;
        }

        if (OnStateChanged)
            OnStateChanged(GetState());

        return true;
    }

    void SessionController::Stop()
    {
        std::lock_guard<std::mutex> lock(_mtx);

        if (!_state.IsRunning() && _state.phase != SessionPhase::Error)
            return;

        SetPhase(SessionPhase::Stopping);

        // Stop VPN
        try
        {
            _vpn.Stop();
        }
        catch (...)
        {
        }

        // Stop bridge
        try
        {
            if (_bridge)
            {
                _bridge->Stop();
                delete _bridge;
                _bridge = nullptr;
            }
        }
        catch (...)
        {
        }

        SetPhase(SessionPhase::Stopped);

        if (OnStateChanged)
            OnStateChanged(_state);
    }

    SessionState SessionController::GetState() const
    {
        std::lock_guard<std::mutex> lock(_mtx);
        return _state;
    }

    void SessionController::SetPhase(SessionPhase phase)
    {
        _state.phase = phase;

        if (OnStateChanged)
            OnStateChanged(_state);
    }

    void SessionController::SetError(const std::string& code, const std::string& message, bool /*fatal*/)
    {
        _state.lastErrorCode = code;
        _state.lastErrorMessage = message;

        if (OnError)
            OnError(code, message, true);

        if (OnStateChanged)
            OnStateChanged(_state);
    }
}
