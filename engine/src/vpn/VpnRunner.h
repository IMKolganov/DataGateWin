#pragma once

#include <functional>
#include <memory>
#include <mutex>
#include <string>

namespace datagate::vpn
{
    class VpnClient;

    class VpnRunner
    {
    public:
        struct ConnectedInfo
        {
            int vpnIfIndex = -1;
            std::string vpnIpv4;
        };

        VpnRunner();
        ~VpnRunner();

        bool Start(const std::string& ovpnContentUtf8, std::string& outError);
        void Stop();

        bool IsConnected() const;
        std::string LastEventName() const;
        std::string LastEventInfo() const;

        std::function<void(const ConnectedInfo&)> OnConnected;
        std::function<void(const std::string& reason)> OnDisconnected;

    private:
        void ResetClient();

        mutable std::mutex _mtx{};
        std::unique_ptr<VpnClient> _client;
    };
}
