#include "VpnRunner.h"

#include "vpn/client/VpnClient.h"

namespace datagate::vpn
{
    VpnRunner::VpnRunner() = default;

    VpnRunner::~VpnRunner()
    {
        Stop();
    }

    void VpnRunner::ResetClient()
    {
        _client.reset();
    }

    bool VpnRunner::Start(const std::string& ovpnContentUtf8, std::string& outError)
    {
        std::lock_guard<std::mutex> lock(_mtx);

        if (_client)
        {
            outError = "VPN already started";
            return false;
        }

        _client = std::make_unique<VpnClient>();

        _client->OnConnected = [&](const VpnClient::ConnectedInfo& ci)
        {
            if (!OnConnected)
                return;

            ConnectedInfo x;
            x.vpnIfIndex = ci.vpnIfIndex;
            x.vpnIpv4 = ci.vpnIpv4;
            OnConnected(x);
        };

        _client->OnDisconnected = [&](const std::string& reason)
        {
            if (OnDisconnected)
                OnDisconnected(reason);
        };

        auto eval = _client->Eval(ovpnContentUtf8);
        if (eval.error)
        {
            outError = "Eval failed: " + eval.message;
            ResetClient();
            return false;
        }

        auto status = _client->Connect();
        if (status.error)
        {
            outError = "Connect failed: " + status.message;
            ResetClient();
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

        try
        {
            local->Stop();
        }
        catch (...)
        {
        }

        try
        {
            local->WaitDone();
        }
        catch (...)
        {
        }
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
