#include "BridgeManager.h"

#include "SessionController.h"
#include "bridge/client/WssLocalBridge.h"

#include <memory>
#include <string>
#include <utility>
#include "OvpnTextUtils.h"

namespace datagate::session
{
    struct BridgeManager::Impl
    {
        std::unique_ptr<WssLocalBridge> bridge;
        std::string listenIp = "127.0.0.1";
        uint16_t listenPort = 18080;
        WssLocalBridge::Mode mode = WssLocalBridge::Mode::Tcp;
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

            const auto proto = ovpn::TryGetProtoFromOvpn(opt.ovpnContentUtf8);
            const bool useUdp = (proto == "udp");
            const auto desiredMode = useUdp ? WssLocalBridge::Mode::Udp : WssLocalBridge::Mode::Tcp;

            const bool needRecreate =
                !_impl->bridge ||
                _impl->mode != desiredMode ||
                _impl->listenIp != DefaultListenIp(opt) ||
                _impl->listenPort != DefaultListenPort(opt);

            if (needRecreate)
            {
                if (_impl->bridge)
                {
                    try { _impl->bridge->Stop(); } catch (...) {}
                    _impl->bridge.reset();
                }

                WssLocalBridge::Options wo;
                wo.listenIp = _impl->listenIp;
                wo.listenPort = _impl->listenPort;
                wo.mode = desiredMode;
                wo.log = _impl->log;

                _impl->bridge = std::make_unique<WssLocalBridge>(std::move(wo));
                _impl->bridge->Start();

                _impl->mode = desiredMode;
            }

            WssLocalBridge::Target t;
            t.host = opt.bridge.host;
            t.port = opt.bridge.port;
            t.path = opt.bridge.path;
            t.sni = opt.bridge.sni;
            t.verifyServerCert = opt.bridge.verifyServerCert;
            t.authorizationHeader = opt.bridge.authorizationHeader;

            if (useUdp)
            {
                t.path = ovpn::AppendQueryParam(std::move(t.path), "mode", "udp");

                t.remoteProto = opt.bridge.remoteProto.empty() ? "udp" : opt.bridge.remoteProto;
                t.remoteHost  = opt.bridge.remoteHost;
                t.remotePort  = opt.bridge.remotePort;
            }

            _impl->bridge->UpdateTarget(std::move(t));
            return true;
        }
        catch (...)
        {
            outError = "Failed to activate WSS bridge";
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
