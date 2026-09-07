#pragma once

#include "SessionState.h"

#include <cstdint>
#include <functional>
#include <string>

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

        std::string remoteHost;
        uint16_t remotePort = 0;
        std::string remoteProto; // "udp"

        bool verifyServerCert = false;

        std::string authorizationHeader;
    };

    struct StartOptions
    {
        /// "openvpn" (default) or "xray"
        std::string protocol = "openvpn";

        std::string ovpnContentUtf8;
        std::string guiVersion;
        BridgeOptions bridge;

        // When false, OpenVPN talks to remotes in the .ovpn as-is (imported profiles).
        // Default true: DataGate catalog path via local WSS bridge.
        bool useWssBridge = true;

        /// Share-link / subscription text (Xray). Used when xrayConfigJson is empty.
        std::string xrayShareLinks;
        /// Prebuilt outbounds JSON or full config fragment (Xray).
        std::string xrayConfigJson;
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
        void RefreshCallbacksToStore();
        bool StartOpenVpn(const StartOptions& opt, std::string& outError);
        bool StartXray(const StartOptions& opt, std::string& outError);

    private:
        class Impl;
        Impl* _impl;
    };
}
