#include "BridgeManager.h"

#include "bridge/client/WssTcpBridge.h"

#include <utility>

namespace datagate::session
{
    struct BridgeManager::Impl
    {
        std::unique_ptr<WssTcpBridge> bridge;
        std::string listenIp = "127.0.0.1";
        uint16_t listenPort = 18080;
    };

    BridgeManager::BridgeManager()
        : _impl(std::make_unique<Impl>())
    {
    }

    BridgeManager::~BridgeManager()
    {
        Stop();
    }

    std::string BridgeManager::DefaultListenIp(const StartOptions& opt)
    {
        return opt.bridge.listenIp.empty() ? std::string("127.0.0.1") : opt.bridge.listenIp;
    }

    uint16_t BridgeManager::DefaultListenPort(const StartOptions& opt)
    {
        return opt.bridge.listenPort == 0 ? static_cast<uint16_t>(18080) : opt.bridge.listenPort;
    }

    bool BridgeManager::Start(const StartOptions& opt, std::string& outError)
    {
        try
        {
            WssTcpBridge::Options bo;
            bo.host = opt.bridge.host;
            bo.port = opt.bridge.port;
            bo.path = opt.bridge.path;
            bo.sni = opt.bridge.sni;

            _impl->listenIp = DefaultListenIp(opt);
            _impl->listenPort = DefaultListenPort(opt);

            bo.listenIp = _impl->listenIp;
            bo.listenPort = _impl->listenPort;

            bo.verifyServerCert = opt.bridge.verifyServerCert;
            bo.authorizationHeader = opt.bridge.authorizationHeader;

            auto bridge = std::make_unique<WssTcpBridge>(std::move(bo));
            bridge->Start();

            _impl->bridge = std::move(bridge);
            return true;
        }
        catch (...)
        {
            outError = "Failed to start WSS TCP bridge";
            return false;
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
        return _impl->bridge != nullptr;
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
