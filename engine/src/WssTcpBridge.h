#pragma once

#include <string>
#include <atomic>
#include <thread>
#include <cstdint>

class WssTcpBridge
{
public:
    struct Options
    {
        std::string host;        // dev-s1.datagateapp.com
        std::string port = "443";
        std::string path = "/api/proxy";
        std::string sni;         // dev-s1.datagateapp.com
        std::string listenIp = "127.0.0.1";
        uint16_t listenPort = 18080;

        bool verifyServerCert = true;
        std::string authorizationHeader;
    };

    explicit WssTcpBridge(Options opt);
    ~WssTcpBridge();

    void Start();
    void Stop();

private:
    void DoAccept();
    void HandleClient(void* nativeSocket); // opaque to avoid asio in header

private:
    Options opt_;

    struct Impl;
    Impl* impl_; // pImpl to hide Boost/OpenSSL
};
