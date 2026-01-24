#pragma once

#include <cstdint>
#include <functional>
#include <string>

class WssTcpBridge
{
public:
    struct Options
    {
        std::string host;
        std::string port;
        std::string path;
        std::string sni;

        std::string listenIp;
        uint16_t listenPort = 0;

        bool verifyServerCert = false;
        std::string authorizationHeader;

        std::function<void(const std::string&)> log;
    };

    explicit WssTcpBridge(Options opt);
    ~WssTcpBridge();

    void Start();
    void Stop();

private:
    void DoAccept();
    void HandleClient(void* nativeSocket);

private:
    Options opt_;
    struct Impl;
    Impl* impl_;
};
