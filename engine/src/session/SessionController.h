// SessionController.h
#pragma once

#include "SessionState.h"
#include "vpn/VpnRunner.h"
#include "vpn/WintunHolder.h"

#include <cstdint>
#include <functional>
#include <memory>
#include <mutex>
#include <string>

class WssTcpBridge;

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

        StateChangedCallback OnStateChanged;
        LogCallback          OnLog;
        ErrorCallback        OnError;
        ConnectedCallback    OnConnected;
        DisconnectedCallback OnDisconnected;

        bool Start(const StartOptions& opt, std::string& outError);
        void Stop();

        SessionState GetState() const;

    private:
        static std::string PatchOvpnRemoteToLocal(const std::string& ovpn, const std::string& localHost, uint16_t localPort);
        static std::string PrependWindowsDriverWintun(const std::string& ovpn);

        void StopLockedNoCallbacks();
        void PublishState(const SessionState& snapshot);
        void PublishError(const std::string& code, const std::string& message, bool fatal);

        static std::string DefaultListenIp(const StartOptions& opt);
        static uint16_t DefaultListenPort(const StartOptions& opt);

    private:
        mutable std::mutex _mtx;
        SessionState _state{};

        std::unique_ptr<WssTcpBridge> _bridge;
        datagate::vpn::VpnRunner _vpn;

        StartOptions _lastStart{};

        datagate::wintun::WintunHolder _tun;
        bool _tunReady = false;

        // Deduplicate DISCONNECTED events (OpenVPN core can emit more than one per attempt)
        bool _disconnectEmitted = false;
    };
}
