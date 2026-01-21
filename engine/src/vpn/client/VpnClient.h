#pragma once

#include <atomic>
#include <condition_variable>
#include <functional>
#include <memory>
#include <mutex>
#include <string>

namespace datagate::vpn
{
    class VpnClient
    {
    public:
        struct ConnectedInfo
        {
            int vpnIfIndex = -1;
            std::string vpnIpv4;
            std::string rawInfo;
        };

        struct EvalResult
        {
            bool error = false;
            std::string message;
            std::string profileName;
            std::string friendlyName;
            bool autologin = false;
            std::string windowsDriver;
        };

        struct StatusResult
        {
            bool error = false;
            std::string status;
            std::string message;
        };

        std::function<void(const ConnectedInfo&)> OnConnected;
        std::function<void(const std::string& reason)> OnDisconnected;
        std::function<void(const std::string& line)> OnLog;

        VpnClient();
        ~VpnClient();

        VpnClient(const VpnClient&) = delete;
        VpnClient& operator=(const VpnClient&) = delete;

        EvalResult Eval(const std::string& ovpnContent);
        StatusResult Connect();

        void Stop();
        void WaitDone();

        bool IsConnected() const;
        std::string LastEventName() const;
        std::string LastEventInfo() const;

    private:
        class Impl;
        std::unique_ptr<Impl> _impl;
    };
}
