#include "BridgeManager.h"

#include "bridge/client/WssTcpBridge.h"
#include "SessionController.h"

#include <utility>

namespace datagate::session
{
    struct BridgeManager::Impl
    {
        std::unique_ptr<WssTcpBridge> bridge;
        std::string listenIp = "127.0.0.1";
        uint16_t listenPort = 18080;

        LogCallback log;
    };

    BridgeManager::BridgeManager()
        : _impl(std::make_unique<Impl>())
    {
    }

    BridgeManager::~BridgeManager()
    {
        Stop();
    }

    void BridgeManager::SetLog(LogCallback cb)
    {
        _impl->log = std::move(cb);

        if (_impl->bridge)
        {
            // Optional: keep bridge logging consistent if you ever recreate it.
            // WssTcpBridge does not expose changing Options at runtime.
        }
    }

    std::string BridgeManager::DefaultListenIp(const StartOptions& opt)
    {
        return opt.bridge.listenIp.empty() ? std::string("127.0.0.1") : opt.bridge.listenIp;
    }

    uint16_t BridgeManager::DefaultListenPort(const StartOptions& opt)
    {
        return opt.bridge.listenPort == 0 ? static_cast<uint16_t>(18080) : opt.bridge.listenPort;
    }

    bool BridgeManager::Activate(const StartOptions& opt, std::string& outError)
    {
        try
        {
            _impl->listenIp = DefaultListenIp(opt);
            _impl->listenPort = DefaultListenPort(opt);

            if (!_impl->bridge)
            {
                WssTcpBridge::Options wo;
                wo.listenIp = _impl->listenIp;
                wo.listenPort = _impl->listenPort;
                wo.log = _impl->log;

                _impl->bridge = std::make_unique<WssTcpBridge>(std::move(wo));
                _impl->bridge->Start();
            }

            WssTcpBridge::Target t;
            t.host = opt.bridge.host;
            t.port = opt.bridge.port;
            t.path = opt.bridge.path;
            t.sni = opt.bridge.sni;
            t.verifyServerCert = opt.bridge.verifyServerCert;
            t.authorizationHeader = opt.bridge.authorizationHeader;

            _impl->bridge->UpdateTarget(std::move(t));
            return true;
        }
        catch (...)
        {
            outError = "Failed to activate WSS TCP bridge";
            return false;
        }
    }

    void BridgeManager::Deactivate()
    {
        if (_impl->bridge)
        {
            try { _impl->bridge->ClearTarget(); } catch (...) {}
        }
    }

    void BridgeManager::Stop()
    {
        if (_impl->bridge)
        {
            try { _impl->bridge->Stop(); } catch (...) {}
            _impl->bridge.reset();
        }
    }

    bool BridgeManager::IsRunning() const
    {
        return _impl->bridge != nullptr && _impl->bridge->IsStarted();
    }

    std::string BridgeManager::ListenIp() const
    {
        return _impl->listenIp;
    }

    uint16_t BridgeManager::ListenPort() const
    {
        return _impl->listenPort;
    }
}
