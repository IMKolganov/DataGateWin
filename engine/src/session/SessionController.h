#pragma once

#include "SessionState.h"

#include <mutex>
#include <string>
#include <functional>

class VpnClient;      // from your existing codebase
class WssTcpBridge;   // from your existing codebase

namespace datagate::session
{
    struct BridgeOptions
    {
        std::string host;
        std::string port;
        std::string path;
        std::string sni;
        std::string listenIp;
        uint16_t listenPort = 0;
        bool verifyServerCert = false;
        std::string authorizationHeader;
    };

    struct StartOptions
    {
        std::string ovpnContentUtf8;
        BridgeOptions bridge;
    };

    struct ConnectedInfo
    {
        int vpnIfIndex = -1;
        std::string vpnIpv4;
    };

    using StateChangedCallback = std::function<void(const SessionState& state)>;
    using LogCallback          = std::function<void(const std::string& line)>;
    using ErrorCallback        = std::function<void(const std::string& code, const std::string& message, bool fatal)>;
    using ConnectedCallback    = std::function<void(const ConnectedInfo& ci)>;
    using DisconnectedCallback = std::function<void(const std::string& reason)>;

    class SessionController
    {
    public:
        SessionController();
        ~SessionController();

        SessionController(const SessionController&) = delete;
        SessionController& operator=(const SessionController&) = delete;

        // Wire callbacks (AppMain will connect these to IpcServer events)
        StateChangedCallback OnStateChanged;
        LogCallback          OnLog;
        ErrorCallback        OnError;
        ConnectedCallback    OnConnected;
        DisconnectedCallback OnDisconnected;

        // Main commands
        bool Start(const StartOptions& opt, std::string& outError);
        void Stop();

        SessionState GetState() const;

    private:
        void SetPhase(SessionPhase phase);
        void SetError(const std::string& code, const std::string& message, bool fatal);

        static std::string ForceTcpToLocalBridge(const std::string& originalOvpn, const std::string& localHost, uint16_t localPort);

    private:
        mutable std::mutex _mtx;
        SessionState _state;

        // Owned runtime objects
        WssTcpBridge* _bridge = nullptr;
        VpnClient* _vpn = nullptr;

        StartOptions _lastStart; // optional, if you want "reconnect" later
    };
}
