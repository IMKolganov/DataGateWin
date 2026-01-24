// SessionController.cpp
#include "SessionController.h"

#include "bridge/client/WssTcpBridge.h"
#include "vpn/VpnRunner.h"

#include <algorithm>
#include <sstream>
#include <utility>

namespace datagate::session
{
    std::string SessionController::PatchOvpnRemoteToLocal(const std::string& ovpn, const std::string& localHost, uint16_t localPort)
    {
        std::string patched;
        patched.reserve(ovpn.size() + 128);

        patched += "remote ";
        patched += localHost;
        patched += " ";
        patched += std::to_string(localPort);
        patched += "\n";

        patched += ovpn;
        return patched;
    }

    std::string SessionController::PrependWindowsDriverWintun(const std::string& ovpn)
    {
        std::string out;
        out.reserve(ovpn.size() + 64);
        out += "windows-driver wintun\n";
        out += ovpn;
        return out;
    }

    std::string SessionController::DefaultListenIp(const StartOptions& opt)
    {
        return opt.bridge.listenIp.empty() ? std::string("127.0.0.1") : opt.bridge.listenIp;
    }

    uint16_t SessionController::DefaultListenPort(const StartOptions& opt)
    {
        return opt.bridge.listenPort == 0 ? static_cast<uint16_t>(18080) : opt.bridge.listenPort;
    }

    static std::string FirstLines(const std::string& s, size_t maxLines, size_t maxChars)
    {
        std::string out;
        out.reserve(std::min(maxChars, s.size()));

        size_t lines = 0;
        for (size_t i = 0; i < s.size() && out.size() < maxChars; ++i)
        {
            const char c = s[i];
            out.push_back(c);
            if (c == '\n')
            {
                ++lines;
                if (lines >= maxLines)
                    break;
            }
        }
        return out;
    }

    static std::string ExtractLinesWithPrefix(const std::string& s, const char* prefix, size_t maxHits)
    {
        std::istringstream iss(s);
        std::string line;
        std::ostringstream out;

        size_t hits = 0;
        while (std::getline(iss, line))
        {
            if (line.rfind(prefix, 0) == 0)
            {
                out << line << "\n";
                if (++hits >= maxHits)
                    break;
            }
        }
        return out.str();
    }

    SessionController::SessionController()
    {
        // Forward OpenVPN/VpnRunner logs to SessionController log callback.
        _vpn.OnLog = [this](const std::string& line)
        {
            LogCallback onLog;
            {
                std::lock_guard<std::mutex> lock(_mtx);
                onLog = OnLog;
            }
            if (onLog)
                onLog("[ovpn] " + line);
        };

        _vpn.OnConnected = [this](const datagate::vpn::VpnRunner::ConnectedInfo& ci)
        {
            ConnectedCallback onConnected;
            StateChangedCallback onStateChanged;
            SessionState snapshot;

            {
                std::lock_guard<std::mutex> lock(_mtx);

                onConnected = OnConnected;
                onStateChanged = OnStateChanged;

                _disconnectEmitted = false; // new attempt, allow future disconnect emit

                if (_state.phase != SessionPhase::Connected)
                    _state.phase = SessionPhase::Connected;

                snapshot = _state;
            }

            if (onConnected)
            {
                ConnectedInfo x{};
                x.vpnIfIndex = ci.vpnIfIndex;
                x.vpnIpv4 = ci.vpnIpv4;
                onConnected(x);
            }

            if (onStateChanged)
                onStateChanged(snapshot);
        };

        _vpn.OnDisconnected = [this](const std::string& reason)
        {
            DisconnectedCallback onDisconnected;
            StateChangedCallback onStateChanged;

            SessionState snapshot;
            bool shouldEmitDisconnected = false;
            bool shouldEmitStateChanged = false;

            {
                std::lock_guard<std::mutex> lock(_mtx);

                onDisconnected = OnDisconnected;
                onStateChanged = OnStateChanged;

                // Emit Disconnected only once per attempt
                if (!_disconnectEmitted)
                {
                    _disconnectEmitted = true;
                    shouldEmitDisconnected = true;
                }

                // Change phase to Stopped only if it actually changes
                if (_state.phase == SessionPhase::Connected ||
                    _state.phase == SessionPhase::Connecting ||
                    _state.phase == SessionPhase::Starting)
                {
                    _state.phase = SessionPhase::Stopped;
                    shouldEmitStateChanged = true;
                }

                snapshot = _state;
            }

            if (shouldEmitDisconnected && onDisconnected)
                onDisconnected(reason);

            if (shouldEmitStateChanged && onStateChanged)
                onStateChanged(snapshot);
        };
    }

    SessionController::~SessionController()
    {
        Stop();
    }

    void SessionController::PublishState(const SessionState& snapshot)
    {
        StateChangedCallback cb;
        {
            std::lock_guard<std::mutex> lock(_mtx);
            cb = OnStateChanged;
        }
        if (cb) cb(snapshot);
    }

    void SessionController::PublishError(const std::string& code, const std::string& message, bool fatal)
    {
        ErrorCallback cb;
        {
            std::lock_guard<std::mutex> lock(_mtx);
            cb = OnError;
        }
        if (cb) cb(code, message, fatal);
    }

    bool SessionController::Start(const StartOptions& opt, std::string& outError)
    {
        StateChangedCallback onStateChanged;
        ErrorCallback onError;
        LogCallback onLog;

        {
            std::lock_guard<std::mutex> lock(_mtx);

            if (_state.IsRunning())
            {
                outError = "Session already running";
                return false;
            }

            _lastStart = opt;

            _state.lastErrorCode.clear();
            _state.lastErrorMessage.clear();
            _state.phase = SessionPhase::Starting;

            _disconnectEmitted = false; // reset per Start attempt

            onStateChanged = OnStateChanged;
            onError = OnError;
            onLog = OnLog;
        }

        if (onStateChanged) onStateChanged(GetState());

        // 0) Ensure Wintun adapter exists and is kept open for engine lifetime
        {
            std::string tunErr;
            const std::wstring adapterName = L"DataGate";
            const std::wstring tunnelType = L"DataGate";

            if (!_tun.EnsureAdapter(adapterName, tunnelType, tunErr))
            {
                const std::string code = "tun_init_failed";
                const std::string msg = "Failed to init Wintun adapter: " + tunErr;

                {
                    std::lock_guard<std::mutex> lock(_mtx);
                    _state.lastErrorCode = code;
                    _state.lastErrorMessage = msg;
                    _state.phase = SessionPhase::Error;
                }

                if (onError) onError(code, msg, true);
                if (onStateChanged) onStateChanged(GetState());

                outError = msg;
                return false;
            }

            _tunReady = true;

            if (onLog)
            {
                if (auto idx = _tun.GetIfIndex())
                    onLog("[session] wintun adapter ifIndex=" + std::to_string(*idx));
                else
                    onLog("[session] wintun adapter ifIndex=<unknown>");
            }
        }

        // 1) Start local WSS->TCP bridge
        try
        {
            WssTcpBridge::Options bo;
            bo.host = opt.bridge.host;
            bo.port = opt.bridge.port;
            bo.path = opt.bridge.path;
            bo.sni = opt.bridge.sni;
            bo.listenIp = DefaultListenIp(opt);
            bo.listenPort = DefaultListenPort(opt);
            bo.verifyServerCert = opt.bridge.verifyServerCert;
            bo.authorizationHeader = opt.bridge.authorizationHeader;

            auto bridge = std::make_unique<WssTcpBridge>(std::move(bo));
            bridge->Start();

            {
                std::lock_guard<std::mutex> lock(_mtx);
                _bridge = std::move(bridge);

                if (_state.phase != SessionPhase::Connecting)
                    _state.phase = SessionPhase::Connecting;
            }

            if (onStateChanged) onStateChanged(GetState());
        }
        catch (...)
        {
            const std::string code = "bridge_start_failed";
            const std::string msg = "Failed to start WSS TCP bridge";

            {
                std::lock_guard<std::mutex> lock(_mtx);
                _state.lastErrorCode = code;
                _state.lastErrorMessage = msg;
                _state.phase = SessionPhase::Error;
            }

            if (onError) onError(code, msg, true);
            if (onStateChanged) onStateChanged(GetState());

            outError = msg;
            return false;
        }

        // 2) Patch OVPN to point to local bridge
        auto ovpnPatched = PatchOvpnRemoteToLocal(
            opt.ovpnContentUtf8,
            DefaultListenIp(opt),
            DefaultListenPort(opt));

        // 2.1) Force driver hint for Windows
        ovpnPatched = PrependWindowsDriverWintun(ovpnPatched);

        auto has = [&](const char* x) { return ovpnPatched.find(x) != std::string::npos; };

        if (onLog)
        {
            const bool hasCert = has("<cert>");
            const bool hasKey = has("<key>");
            const bool hasCa = has("<ca>");

            onLog(std::string("[session] ovpn bytes=") + std::to_string(ovpnPatched.size())
                + " has<ca>=" + (hasCa ? "1" : "0")
                + " has<cert>=" + (hasCert ? "1" : "0")
                + " has<key>=" + (hasKey ? "1" : "0"));

            onLog(std::string("[session] has <ca>=") + (has("<ca>") ? "1" : "0") +
                " <cert>=" + (has("<cert>") ? "1" : "0") +
                " <key>=" + (has("<key>") ? "1" : "0") +
                " tls-crypt=" + (has("<tls-crypt>") ? "1" : "0"));

            // Show the first lines of the exact config passed to OpenVPN core.
            onLog("[session] ovpn preview (first lines) begin");
            onLog(FirstLines(ovpnPatched, /*maxLines*/ 40, /*maxChars*/ 2000));
            onLog("[session] ovpn preview (first lines) end");

            // Explicitly show all windows-driver lines (helps detect duplicates/overrides).
            const auto wdLines = ExtractLinesWithPrefix(ovpnPatched, "windows-driver", 8);
            if (!wdLines.empty())
            {
                onLog("[session] ovpn windows-driver lines:");
                onLog(wdLines);
            }
            else
            {
                onLog("[session] ovpn windows-driver lines: <none>");
            }

            // Optional: show dev/dev-type (helps detect layer2 vs layer3 intent).
            const auto devLines = ExtractLinesWithPrefix(ovpnPatched, "dev", 8);
            if (!devLines.empty())
            {
                onLog("[session] ovpn dev/dev-type lines:");
                onLog(devLines);
            }
        }

        // 3) Start VPN
        std::string vpnErr;
        if (!_vpn.Start(ovpnPatched, vpnErr))
        {
            const std::string code = "vpn_start_failed";
            const std::string msg = vpnErr.empty() ? std::string("VPN start failed") : vpnErr;

            {
                std::lock_guard<std::mutex> lock(_mtx);
                _state.lastErrorCode = code;
                _state.lastErrorMessage = msg;
                _state.phase = SessionPhase::Error;
            }

            if (onError) onError(code, msg, true);

            Stop();

            outError = msg;
            return false;
        }

        return true;
    }

    void SessionController::StopLockedNoCallbacks()
    {
        try { _vpn.Stop(); } catch (...) {}

        if (_bridge)
        {
            try { _bridge->Stop(); } catch (...) {}
            _bridge.reset();
        }
    }

    void SessionController::Stop()
    {
        StateChangedCallback onStateChanged;
        bool shouldEmitStopping = false;
        bool shouldEmitStopped = false;

        {
            std::lock_guard<std::mutex> lock(_mtx);

            onStateChanged = OnStateChanged;

            if (_state.IsRunning() || _state.phase == SessionPhase::Error)
            {
                if (_state.phase != SessionPhase::Stopping)
                {
                    _state.phase = SessionPhase::Stopping;
                    shouldEmitStopping = true;
                }
            }
            else
            {
                return; // already stopped/idle
            }
        }

        if (shouldEmitStopping && onStateChanged)
            onStateChanged(GetState());

        {
            std::lock_guard<std::mutex> lock(_mtx);
            StopLockedNoCallbacks();

            if (_state.phase != SessionPhase::Stopped)
            {
                _state.phase = SessionPhase::Stopped;
                shouldEmitStopped = true;
            }

            onStateChanged = OnStateChanged;
        }

        if (shouldEmitStopped && onStateChanged)
            onStateChanged(GetState());
    }

    SessionState SessionController::GetState() const
    {
        std::lock_guard<std::mutex> lock(_mtx);
        return _state;
    }
}
