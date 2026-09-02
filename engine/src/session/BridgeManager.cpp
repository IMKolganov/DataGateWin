#include "BridgeManager.h"

#include "SessionController.h"
#include "EnginePortDefaults.h"
#include "app/CrashReporter.h"
#include "bridge/client/WssLocalBridge.h"

#include <exception>
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
        uint16_t listenPort = kLocalBridgeDefaultListenPort;
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
        // Always loopback: IPC must not be able to bind the OpenVPN bridge on LAN interfaces.
        (void)opt;
        return "127.0.0.1";
    }

    uint16_t BridgeManager::DefaultListenPort(const StartOptions& opt)
    {
        return opt.bridge.listenPort == 0 ? kLocalBridgeDefaultListenPort : opt.bridge.listenPort;
    }

    bool BridgeManager::Activate(const StartOptions& opt, std::string& outError)
    {
        try
        {
            _impl->listenIp = DefaultListenIp(opt);

            const auto proto = ovpn::ResolveTransportProto(opt.ovpnContentUtf8);
            const bool useUdp = ovpn::IsUdpProto(proto);
            const auto desiredMode = useUdp ? WssLocalBridge::Mode::Udp : WssLocalBridge::Mode::Tcp;

            const uint16_t preferredPort = DefaultListenPort(opt);

            const bool needRecreate =
                !_impl->bridge ||
                !_impl->bridge->IsStarted() ||
                _impl->mode != desiredMode ||
                _impl->listenIp != DefaultListenIp(opt);

            if (needRecreate)
            {
                if (_impl->bridge)
                {
                    try { _impl->bridge->Stop(); } catch (const std::exception& ex) { CrashReporter::ReportNonFatal("BridgeManager.ActivateStop", ex.what()); } catch (...) { CrashReporter::ReportNonFatal("BridgeManager.ActivateStop", "Unknown exception"); }
                    _impl->bridge.reset();
                }

                bool bound = false;
                uint16_t boundPort = preferredPort;

                for (uint16_t attempt = 0; attempt < kLocalBridgeListenPortAttempts; ++attempt)
                {
                    const uint32_t candidate = static_cast<uint32_t>(preferredPort) + attempt;
                    if (candidate > 65535)
                        break;

                    const auto port = static_cast<uint16_t>(candidate);

                    WssLocalBridge::Options wo;
                    wo.listenIp = _impl->listenIp;
                    wo.listenPort = port;
                    wo.mode = desiredMode;
                    wo.log = _impl->log;

                    auto bridge = std::make_unique<WssLocalBridge>(std::move(wo));
                    if (!bridge->Start())
                    {
                        try { bridge->Stop(); } catch (...) {}
                        bridge.reset();
                        continue;
                    }

                    _impl->bridge = std::move(bridge);
                    boundPort = port;
                    bound = true;
                    break;
                }

                if (!bound)
                {
                    outError = "Failed to bind local WSS bridge (listen ports busy)";
                    return false;
                }

                _impl->listenPort = boundPort;
                _impl->mode = desiredMode;

                if (boundPort != preferredPort && _impl->log)
                {
                    _impl->log(
                        "[session] bridge listen port " + std::to_string(preferredPort) +
                        " busy; using " + std::to_string(boundPort));
                }
            }
            else
            {
                // Keep existing successful bind port.
                _impl->listenPort = _impl->bridge->ListenPort();
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

                // Handshake needs the real OpenVPN endpoint; UI/IPC often omit it.
                if (t.remoteHost.empty() || t.remotePort == 0)
                {
                    ovpn::OvpnRemote remote;
                    if (ovpn::TryGetFirstRemoteFromOvpn(opt.ovpnContentUtf8, remote))
                    {
                        if (t.remoteHost.empty())
                            t.remoteHost = remote.host;
                        if (t.remotePort == 0)
                            t.remotePort = remote.port;
                    }
                }
            }

            _impl->bridge->UpdateTarget(std::move(t));
            return true;
        }
        catch (const std::exception& ex)
        {
            CrashReporter::ReportNonFatal("BridgeManager.Activate", ex.what());
            outError = "Failed to activate WSS bridge";
            return false;
        }
        catch (...)
        {
            CrashReporter::ReportNonFatal("BridgeManager.Activate", "Unknown exception");
            outError = "Failed to activate WSS bridge";
            return false;
        }
    }

    void BridgeManager::Deactivate()
    {
        if (_impl->bridge)
        {
            try { _impl->bridge->ClearTarget(); } catch (const std::exception& ex) { CrashReporter::ReportNonFatal("BridgeManager.Deactivate", ex.what()); } catch (...) { CrashReporter::ReportNonFatal("BridgeManager.Deactivate", "Unknown exception"); }
        }
    }

    void BridgeManager::Stop()
    {
        if (_impl->bridge)
        {
            try { _impl->bridge->Stop(); } catch (const std::exception& ex) { CrashReporter::ReportNonFatal("BridgeManager.Stop", ex.what()); } catch (...) { CrashReporter::ReportNonFatal("BridgeManager.Stop", "Unknown exception"); }
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
