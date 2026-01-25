#include "VpnSessionRunner.h"

namespace datagate::session
{
    void VpnSessionRunner::SetCallbacks(
        LogFn onLog,
        ConnectedFn onConnected,
        DisconnectedFn onDisconnected)
    {
        _vpn.OnLog = std::move(onLog);
        _vpn.OnConnected = std::move(onConnected);
        _vpn.OnDisconnected = std::move(onDisconnected);
    }

    bool VpnSessionRunner::Start(const std::string& config, std::string& outError)
    {
        return _vpn.Start(config, outError);
    }

    void VpnSessionRunner::Stop()
    {
        try { _vpn.Stop(); } catch (...) {}
    }
}
