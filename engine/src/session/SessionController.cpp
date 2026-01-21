#include "SessionController.h"

#include <sstream>

#include "../vpn/client/VpnClient.h"
#include "../bridge/client/WssTcpBridge.h"

#include <openvpn/common/exception.hpp>

namespace datagate::session
{
    SessionController::SessionController() = default;

    SessionController::~SessionController()
    {
        Stop();
    }

    SessionState SessionController::GetState() const
    {
        std::lock_guard<std::mutex> lock(_mtx);
        return _state;
    }

    void SessionController::SetPhase(SessionPhase phase)
    {
        SessionState snapshot;
        {
            std::lock_guard<std::mutex> lock(_mtx);
            _state.phase = phase;
            snapshot = _state;
        }
        if (OnStateChanged) OnStateChanged(snapshot);
    }

    void SessionController::SetError(const std::string& code, const std::string& message, bool fatal)
    {
        SessionState snapshot;
        {
            std::lock_guard<std::mutex> lock(_mtx);
            _state.phase = SessionPhase::Error;
            _state.lastErrorCode = code;
            _state.lastErrorMessage = message;
            snapshot = _state;
        }

        if (OnError) OnError(code, message, fatal);
        if (OnStateChanged) OnStateChanged(snapshot);
    }

    bool SessionController::Start(const StartOptions& opt, std::string& outError)
    {
        {
            std::lock_guard<std::mutex> lock(_mtx);
            if (_state.IsRunning())
            {
                outError = "Session already running";
                return false;
            }
        }

        _lastStart = opt;

        SetPhase(SessionPhase::Starting);

        try
        {
            // 1) Start bridge
            WssTcpBridge::Options bo;
            bo.host = opt.bridge.host;
            bo.port = opt.bridge.port;
            bo.path = opt.bridge.path;
            bo.sni  = opt.bridge.sni;
            bo.listenIp = opt.bridge.listenIp;
            bo.listenPort = opt.bridge.listenPort;
            bo.verifyServerCert = opt.bridge.verifyServerCert;
            bo.authorizationHeader = opt.bridge.authorizationHeader;

            _bridge = new WssTcpBridge(bo);
            _bridge->Start();

            if (OnLog)
            {
                std::ostringstream oss;
                oss << "[bridge] listening on " << bo.listenIp << ":" << bo.listenPort
                    << " -> wss://" << bo.host << bo.path;
                OnLog(oss.str());
            }

            // 2) Prepare OpenVPN config (content already provided by UI)
            openvpn::ClientAPI::Config cfg;
            cfg.content = opt.ovpnContentUtf8;
            cfg.content = ForceTcpToLocalBridge(cfg.content, bo.listenIp, bo.listenPort);

            // 3) Start VPN
            _vpn = new VpnClient();

            _vpn->OnConnected = [&](const VpnClient::ConnectedInfo& ci)
            {
                SetPhase(SessionPhase::Connected);

                if (OnConnected)
                {
                    ConnectedInfo x;
                    x.vpnIfIndex = ci.vpnIfIndex;
                    x.vpnIpv4 = ci.vpnIpv4;
                    OnConnected(x);
                }
            };

            _vpn->OnDisconnected = [&](const std::string& reason)
            {
                if (OnDisconnected) OnDisconnected(reason);
                SetPhase(SessionPhase::Stopped);
            };

            SetPhase(SessionPhase::Connecting);

            auto eval = _vpn->Eval(cfg);
            if (eval.error)
            {
                outError = "Config evaluation failed: " + eval.message;
                SetError("eval_failed", outError, true);
                Stop();
                return false;
            }

            auto status = _vpn->Connect();
            if (status.error)
            {
                outError = "Connect failed: " + status.message;
                SetError("connect_failed", outError, true);
                Stop();
                return false;
            }

            return true;
        }
        catch (const openvpn::Exception& e)
        {
            outError = std::string("openvpn::Exception: ") + e.what();
            SetError("openvpn_exception", outError, true);
            Stop();
            return false;
        }
        catch (const std::exception& e)
        {
            outError = std::string("std::exception: ") + e.what();
            SetError("std_exception", outError, true);
            Stop();
            return false;
        }
    }

    void SessionController::Stop()
    {
        // We intentionally allow Stop() to be called multiple times.
        SetPhase(SessionPhase::Stopping);

        if (_vpn)
        {
            try
            {
                _vpn->stop();
                _vpn->WaitDone();
            }
            catch (...)
            {
            }
            delete _vpn;
            _vpn = nullptr;
        }

        if (_bridge)
        {
            try
            {
                _bridge->Stop();
            }
            catch (...)
            {
            }
            delete _bridge;
            _bridge = nullptr;
        }

        // If we were in Error, keep it; otherwise mark stopped
        {
            std::lock_guard<std::mutex> lock(_mtx);
            if (_state.phase != SessionPhase::Error)
                _state.phase = SessionPhase::Stopped;
        }

        if (OnStateChanged) OnStateChanged(GetState());
    }

    std::string SessionController::ForceTcpToLocalBridge(const std::string& originalOvpn, const std::string& localHost, uint16_t localPort)
    {
        std::istringstream in(originalOvpn);
        std::ostringstream out;

        std::string line;
        bool replacedRemote = false;
        bool hasProto = false;

        while (std::getline(in, line))
        {
            std::string trimmed = line;
            while (!trimmed.empty() && (trimmed.back() == '\r' || trimmed.back() == '\n'))
                trimmed.pop_back();

            if (trimmed.rfind("remote ", 0) == 0)
            {
                if (!replacedRemote)
                {
                    out << "remote " << localHost << " " << localPort << "\n";
                    replacedRemote = true;
                }
                else
                {
                    out << "; " << trimmed << "\n";
                }
                continue;
            }

            if (trimmed.rfind("proto ", 0) == 0)
            {
                hasProto = true;
                out << "proto tcp-client\n";
                continue;
            }

            out << trimmed << "\n";
        }

        if (!replacedRemote)
        {
            out << "remote " << localHost << " " << localPort << "\n";
        }

        if (!hasProto)
        {
            out << "proto tcp-client\n";
        }

        return out.str();
    }
}
