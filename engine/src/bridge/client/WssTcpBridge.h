#pragma once

#include <cstdint>
#include <functional>
#include <memory>
#include <string>

class WssTcpBridge
{
public:
    struct Target
    {
        std::string host;
        std::string port;
        std::string path;
        std::string sni;
        bool verifyServerCert = false;
        std::string authorizationHeader;
    };

    struct Options
    {
        std::string listenIp = "127.0.0.1";
        uint16_t listenPort = 18080;
        std::function<void(const std::string&)> log;
    };

public:
    explicit WssTcpBridge(Options opt);
    ~WssTcpBridge();

    void Start();
    void Stop();

    bool IsStarted() const;

    void UpdateTarget(Target t);
    void ClearTarget();

    std::string ListenIp() const;
    uint16_t ListenPort() const;

private:
    void DoAccept();
    void HandleClient(void* nativeSocket);

private:
    Options opt_;
    struct Impl;
    Impl* impl_ = nullptr;
};
