#include "VpnRunner.h"

#include "vpn/client/VpnClient.h"

namespace datagate::vpn
{
    VpnRunner::VpnRunner() = default;

    VpnRunner::~VpnRunner()
    {
        Stop();
    }

    void VpnRunner::ResetClientLocked()
    {
        _client.reset();
    }

    bool VpnRunner::Start(const std::string& ovpnContentUtf8, std::string& outError)
    {
        std::unique_ptr<VpnClient> client = std::make_unique<VpnClient>();

        client->OnConnected = [this](const VpnClient::ConnectedInfo& ci)
        {
            std::function<void(const ConnectedInfo&)> cb;
            {
                std::lock_guard<std::mutex> lock(_mtx);
                cb = OnConnected;
            }

            if (!cb)
                return;

            ConnectedInfo x{};
            x.vpnIfIndex = ci.vpnIfIndex;
            x.vpnIpv4 = ci.vpnIpv4;
            cb(x);
        };

        client->OnDisconnected = [this](const std::string& reason)
        {
            std::function<void(const std::string&)> cb;
            {
                std::lock_guard<std::mutex> lock(_mtx);
                cb = OnDisconnected;
            }

            if (cb)
                cb(reason);
        };

        {
            std::lock_guard<std::mutex> lock(_mtx);
            if (_client)
            {
                outError = "VPN already started";
                return false;
            }
            _client = std::move(client);
        }

        VpnClient* c = nullptr;
        {
            std::lock_guard<std::mutex> lock(_mtx);
            c = _client.get();
        }

        auto eval = c->Eval(ovpnContentUtf8);
        if (eval.error)
        {
            outError = "Eval failed: " + eval.message;
            std::lock_guard<std::mutex> lock(_mtx);
            ResetClientLocked();
            return false;
        }

        auto status = c->Connect();
        if (status.error)
        {
            outError = "Connect failed: " + status.message;
            std::lock_guard<std::mutex> lock(_mtx);
            ResetClientLocked();
            return false;
        }

        return true;
    }

    void VpnRunner::Stop()
    {
        std::unique_ptr<VpnClient> local;

        {
            std::lock_guard<std::mutex> lock(_mtx);
            local = std::move(_client);
        }

        if (!local)
            return;

        try { local->Stop(); } catch (...) {}

        try { local->WaitDone(); } catch (...) {}
    }

    bool VpnRunner::IsConnected() const
    {
        std::lock_guard<std::mutex> lock(_mtx);
        return _client ? _client->IsConnected() : false;
    }

    std::string VpnRunner::LastEventName() const
    {
        std::lock_guard<std::mutex> lock(_mtx);
        return _client ? _client->LastEventName() : std::string();
    }

    std::string VpnRunner::LastEventInfo() const
    {
        std::lock_guard<std::mutex> lock(_mtx);
        return _client ? _client->LastEventInfo() : std::string();
    }
}
