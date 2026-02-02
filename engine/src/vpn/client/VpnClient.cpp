// src/vpn/client/VpnClient.cpp
#include "VpnClient.h"

// IMPORTANT: the only translation unit that includes OpenVPN Client API header.
#include <client/ovpncli.hpp>

#include <atomic>
#include <condition_variable>
#include <cctype>
#include <exception>
#include <mutex>
#include <sstream>
#include <string>
#include <utility>

namespace datagate::vpn
{
    static bool HasWindowsDriverWintun(const std::string& ovpn)
    {
        std::istringstream iss(ovpn);
        std::string line;

        while (std::getline(iss, line))
        {
            auto i = line.find_first_not_of(" \t\r\n");
            if (i == std::string::npos)
                continue;

            const char c = line[i];
            if (c == '#' || c == ';')
                continue;

            // Match: windows-driver <value>
            static constexpr const char* kKey = "windows-driver";
            static constexpr size_t kKeyLen = 14;

            if (line.size() < i + kKeyLen)
                continue;

            if (line.compare(i, kKeyLen, kKey) != 0)
                continue;

            auto j = line.find_first_not_of(" \t", i + kKeyLen);
            if (j == std::string::npos)
                return false;

            auto k = line.find_first_of(" \t\r\n", j);
            std::string val = (k == std::string::npos) ? line.substr(j) : line.substr(j, k - j);

            for (auto& ch : val)
                ch = static_cast<char>(std::tolower(static_cast<unsigned char>(ch)));

            return val == "wintun";
        }

        return false;
    }

    class VpnClient::Impl : public openvpn::ClientAPI::OpenVPNClient
    {
    public:
        explicit Impl(VpnClient& owner)
            : _owner(owner)
        {
        }

        bool pause_on_connection_timeout() override { return false; }

        void event(const openvpn::ClientAPI::Event& ev) override
        {
            {
                std::lock_guard<std::mutex> lock(_mtx);
                _lastEventName = ev.name;
                _lastEventInfo = ev.info;
            }

            if (ev.name == "CONNECTED")
            {
                _connected = true;

                ConnectedInfo ci{};
                try
                {
                    const auto info = connection_info();
                    ci.vpnIfIndex = -1;
                    ci.vpnIpv4 = info.vpnIp4;
                    ci.rawInfo = info.serverHost + ":" + info.serverPort + " proto=" + info.serverProto;
                }
                catch (...)
                {
                }

                if (_owner.OnConnected)
                    _owner.OnConnected(ci);
            }
            else if (ev.name == "DISCONNECTED" || ev.name == "EXITING" || ev.fatal)
            {
                _connected = false;

                if (_owner.OnDisconnected)
                    _owner.OnDisconnected(ev.info.empty() ? ev.name : ev.info);

                SignalDone();
            }
        }

        void acc_event(const openvpn::ClientAPI::AppCustomControlMessageEvent&) override
        {
            // Not used now
        }

        void log(const openvpn::ClientAPI::LogInfo& logInfo) override
        {
            if (!_owner.OnLog)
                return;

            _owner.OnLog(logInfo.text);
        }

        void external_pki_cert_request(openvpn::ClientAPI::ExternalPKICertRequest&) override {}
        void external_pki_sign_request(openvpn::ClientAPI::ExternalPKISignRequest&) override {}

        VpnClient::EvalResult Eval(const std::string& ovpnContent)
        {
            openvpn::ClientAPI::Config cfg;
            cfg.content = ovpnContent;

            // IMPORTANT: cfg.wintun must be set BEFORE eval_config(),
            // because eval_config() copies config into state->clientconf.
            cfg.wintun = HasWindowsDriverWintun(cfg.content);

            const auto ev = openvpn::ClientAPI::OpenVPNClient::eval_config(cfg);

            if (_owner.OnLog)
            {
                _owner.OnLog(std::string("[vpn][eval] cfg.wintun=") + (cfg.wintun ? "1" : "0"));
                _owner.OnLog(std::string("[vpn][eval] error=") + (ev.error ? "1" : "0") + " msg=" + ev.message);
                _owner.OnLog(std::string("[vpn][eval] windowsDriver=") + (ev.windowsDriver.empty() ? "<empty>" : ev.windowsDriver));
                _owner.OnLog(std::string("[vpn][eval] profileName=") + ev.profileName + " friendlyName=" + ev.friendlyName);
            }

            VpnClient::EvalResult r;
            r.error = ev.error;
            r.message = ev.message;
            r.profileName = ev.profileName;
            r.friendlyName = ev.friendlyName;
            r.autologin = ev.autologin;
            r.windowsDriver = ev.windowsDriver;
            return r;
        }

        VpnClient::StatusResult Connect()
        {
            VpnClient::StatusResult r;

            _done = false;
            _connected = false;

            try
            {
                const auto st = openvpn::ClientAPI::OpenVPNClient::connect();
                r.error = st.error;
                r.status = st.status;
                r.message = st.message;
            }
            catch (const std::exception& ex)
            {
                r.error = true;
                r.message = std::string("connect() threw: ") + ex.what();
            }
            catch (...)
            {
                r.error = true;
                r.message = "connect() threw: unknown exception";
            }

            _connected = false;
            SignalDone();
            return r;
        }

        void Stop()
        {
            try
            {
                openvpn::ClientAPI::OpenVPNClient::stop();
            }
            catch (...)
            {
            }
        }

        void WaitDone()
        {
            std::unique_lock<std::mutex> lock(_mtx);
            _cv.wait(lock, [&] { return _done.load(); });
        }

        bool IsConnected() const
        {
            return _connected.load();
        }

        std::string LastEventName() const
        {
            std::lock_guard<std::mutex> lock(_mtx);
            return _lastEventName;
        }

        std::string LastEventInfo() const
        {
            std::lock_guard<std::mutex> lock(_mtx);
            return _lastEventInfo;
        }

    private:
        void SignalDone()
        {
            {
                std::lock_guard<std::mutex> lock(_mtx);
                _done = true;
            }
            _cv.notify_all();
        }

    private:
        VpnClient& _owner;

        mutable std::mutex _mtx{};
        std::condition_variable _cv{};
        std::atomic<bool> _done{false};
        std::atomic<bool> _connected{false};

        std::string _lastEventName{};
        std::string _lastEventInfo{};
    };

    VpnClient::VpnClient()
        : _impl(std::make_unique<Impl>(*this))
    {
    }

    VpnClient::~VpnClient() = default;

    VpnClient::EvalResult VpnClient::Eval(const std::string& ovpnContent)
    {
        return _impl->Eval(ovpnContent);
    }

    VpnClient::StatusResult VpnClient::Connect()
    {
        return _impl->Connect();
    }

    void VpnClient::Stop()
    {
        _impl->Stop();
    }

    void VpnClient::WaitDone()
    {
        _impl->WaitDone();
    }

    bool VpnClient::IsConnected() const
    {
        return _impl->IsConnected();
    }

    std::string VpnClient::LastEventName() const
    {
        return _impl->LastEventName();
    }

    std::string VpnClient::LastEventInfo() const
    {
        return _impl->LastEventInfo();
    }
}
