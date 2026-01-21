#pragma once

#include <functional>
#include <string>

#include "../openvpn_clientapi_fwd.h"

class VpnClient
{
public:
    struct ConnectedInfo
    {
        int vpnIfIndex = -1;
        std::string vpnIpv4;
    };

    std::function<void(const ConnectedInfo&)> OnConnected;
    std::function<void(const std::string&)> OnDisconnected;

public:
    VpnClient();
    ~VpnClient();

    openvpn::ClientAPI::EvalConfig Eval(const openvpn::ClientAPI::Config& cfg);
    openvpn::ClientAPI::Status Connect();

    void Stop();
    void WaitDone();

    bool IsConnected() const;
    std::string LastEventName() const;
    std::string LastEventInfo() const;

private:
    // Keep your internal fields here (pImpl, flags, threads, etc.)
};
