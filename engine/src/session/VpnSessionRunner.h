#pragma once

#include "vpn/VpnRunner.h"

#include <functional>
#include <string>

namespace datagate::session
{
    class VpnSessionRunner
    {
    public:
        using LogFn = std::function<void(const std::string& line)>;
        using ConnectedFn = std::function<void(const datagate::vpn::VpnRunner::ConnectedInfo& ci)>;
        using DisconnectedFn = std::function<void(const std::string& reason)>;

        void SetCallbacks(LogFn onLog, ConnectedFn onConnected, DisconnectedFn onDisconnected);

        bool Start(const std::string& config, std::string& outError);
        void Stop();

    private:
        datagate::vpn::VpnRunner _vpn;
    };
}
