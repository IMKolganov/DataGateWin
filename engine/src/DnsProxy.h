#pragma once

#include <atomic>
#include <cstdint>
#include <string>
#include <thread>

class DnsProxy
{
public:
    struct Config
    {
        std::string listenIp = "127.0.0.1";
        uint16_t listenPort = 53;

        std::string upstreamIp = "8.8.8.8";
        uint16_t upstreamPort = 53;

        std::string vpnBindIp; // required
    };

    DnsProxy() = default;
    ~DnsProxy();

    bool Start(const Config& cfg);
    void Stop();

private:
    void WorkerLoop();

private:
    Config cfg_{};
    std::atomic<bool> running_{false};
    std::thread worker_{};
};
