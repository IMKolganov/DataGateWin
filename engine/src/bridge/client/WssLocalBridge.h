#pragma once

#include "WssBridgeCommon.h"
#include "TcpWssBridge.h"
#include "UdpWssBridge.h"

#include <atomic>
#include <cstdint>
#include <mutex>
#include <optional>
#include <thread>

class WssLocalBridge
{
public:
    enum class Mode { Tcp, Udp };

    struct Options
    {
        std::string listenIp = "127.0.0.1";
        uint16_t listenPort = 0;

        Mode mode = Mode::Tcp;

        uint32_t logMask = ToU32(LogMask::Default);
        std::function<void(const std::string&)> log;

        size_t maxWsQueueBytes = 0;
        bool dropWsOnOverflow = true;
    };

    struct Target
    {
        std::string host;
        std::string port;
        std::string path;
        std::string sni;
        bool verifyServerCert = true;

        std::string remoteHost;
        uint16_t remotePort = 0;
        std::string remoteProto;
        std::string authorizationHeader;
    };

public:
    explicit WssLocalBridge(Options opt);
    ~WssLocalBridge();

    void Start();
    void Stop();

    bool IsStarted() const;

    std::string ListenIp() const;
    uint16_t ListenPort() const;

    void UpdateTarget(Target t);
    void ClearTarget();

    static void SetGlobalLogMask(uint32_t mask);
    static uint32_t GetGlobalLogMask();

private:
    struct Impl;
    Options opt_;
    Impl* impl_{nullptr};
};