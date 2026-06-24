#include "VpnSessionRunner.h"

#include "app/CrashReporter.h"

#include <exception>

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

    bool VpnSessionRunner::Start(const std::string& config, const std::string& guiVersion, std::string& outError)
    {
        return _vpn.Start(config, guiVersion, outError);
    }

    void VpnSessionRunner::Stop()
    {
        try { _vpn.Stop(); } catch (const std::exception& ex) { CrashReporter::ReportNonFatal("VpnSessionRunner.stop", ex.what()); } catch (...) { CrashReporter::ReportNonFatal("VpnSessionRunner.stop", "Unknown exception"); }
    }
}
