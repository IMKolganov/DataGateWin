#pragma once

#include <atomic>
#include <condition_variable>
#include <functional>
#include <mutex>
#include <string>

#include <client/ovpncli.hpp>

class VpnClient : public openvpn::ClientAPI::OpenVPNClient
{
public:
    struct ConnectedInfo
    {
        int vpnIfIndex = -1;
        std::string vpnIpv4;
        std::string rawInfo;
    };

    std::function<void(const ConnectedInfo&)> OnConnected;
    std::function<void(const std::string& reason)> OnDisconnected;

    bool pause_on_connection_timeout() override { return false; }

    void event(const openvpn::ClientAPI::Event& ev) override;
    void acc_event(const openvpn::ClientAPI::AppCustomControlMessageEvent&) override;
    void log(const openvpn::ClientAPI::LogInfo& log) override;

    void external_pki_cert_request(openvpn::ClientAPI::ExternalPKICertRequest&) override {}
    void external_pki_sign_request(openvpn::ClientAPI::ExternalPKISignRequest&) override {}

public:
    openvpn::ClientAPI::EvalConfig Eval(openvpn::ClientAPI::Config& cfg);
    openvpn::ClientAPI::Status Connect();
    void WaitDone();

    bool IsConnected() const { return connected_; }
    std::string LastEventName() const { return lastEventName_; }
    std::string LastEventInfo() const { return lastEventInfo_; }

private:
    mutable std::mutex mtx_{};
    std::condition_variable cv_{};
    std::atomic<bool> done_{false};
    bool connected_ = false;
    std::string lastEventName_{};
    std::string lastEventInfo_{};
};
