#include "VpnClient.h"

#include <cctype>
#include <iostream>

namespace
{
static std::string Trim(const std::string& s)
{
    size_t b = 0;
    while (b < s.size() && (s[b] == ' ' || s[b] == '\t' || s[b] == '\r' || s[b] == '\n')) b++;
    size_t e = s.size();
    while (e > b && (s[e - 1] == ' ' || s[e - 1] == '\t' || s[e - 1] == '\r' || s[e - 1] == '\n')) e--;
    return s.substr(b, e - b);
}

static bool TryParseIntAfter(const std::string& text, const std::string& key, int& value)
{
    auto pos = text.find(key);
    if (pos == std::string::npos) return false;
    pos += key.size();

    size_t end = pos;
    while (end < text.size() && std::isdigit((unsigned char)text[end])) end++;

    if (end == pos) return false;
    value = std::stoi(text.substr(pos, end - pos));
    return true;
}

static bool TryParseIpv4After(const std::string& text, const std::string& key, std::string& ip)
{
    auto pos = text.find(key);
    if (pos == std::string::npos) return false;
    pos += key.size();

    size_t end = pos;
    while (end < text.size())
    {
        char c = text[end];
        if (!(std::isdigit((unsigned char)c) || c == '.')) break;
        end++;
    }

    if (end == pos) return false;
    ip = Trim(text.substr(pos, end - pos));
    return !ip.empty();
}
} // namespace

void VpnClient::event(const openvpn::ClientAPI::Event& ev)
{
    {
        std::lock_guard<std::mutex> lock(mtx_);
        lastEventName_ = ev.name;
        lastEventInfo_ = ev.info;

        std::cout << "[event] name=" << ev.name << " info=" << ev.info << std::endl;

        if (ev.name == "CONNECTED")
        {
            connected_ = true;
            done_.store(true);

            ConnectedInfo ci{};
            ci.rawInfo = ev.info;

            int ifidx = -1;
            if (TryParseIntAfter(ev.info, "vpn_interface_index=", ifidx))
                ci.vpnIfIndex = ifidx;

            std::string ip;
            if (TryParseIpv4After(ev.info, "TUN_WIN/", ip))
                ci.vpnIpv4 = ip;
            else if (TryParseIpv4After(ev.info, "TAP_WIN/", ip))
                ci.vpnIpv4 = ip;

            if (OnConnected)
                OnConnected(ci);
        }
        else if (ev.name == "DISCONNECTED" || ev.name == "AUTH_FAILED")
        {
            connected_ = false;
            done_.store(true);
            if (OnDisconnected)
                OnDisconnected(ev.name);
        }
    }
    cv_.notify_all();
}

void VpnClient::acc_event(const openvpn::ClientAPI::AppCustomControlMessageEvent&)
{
    std::cout << "[acc_event]" << std::endl;
}

void VpnClient::log(const openvpn::ClientAPI::LogInfo& log)
{
    std::cout << "[log] " << log.text << std::endl;
}

openvpn::ClientAPI::EvalConfig VpnClient::Eval(openvpn::ClientAPI::Config& cfg)
{
    return eval_config(cfg);
}

openvpn::ClientAPI::Status VpnClient::Connect()
{
    done_.store(false);
    connected_ = false;
    return connect();
}

void VpnClient::WaitDone()
{
    std::unique_lock<std::mutex> lock(mtx_);
    cv_.wait(lock, [&] { return done_.load(); });
}
