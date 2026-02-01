#pragma once

#include <cstdint>
#include <functional>
#include <string>

class WssTcpBridge
{
public:
    enum class Mode
    {
        Tcp = 0,
        Udp = 1
    };

    struct Target
    {
        std::string host;
        std::string port;
        std::string path;
        std::string sni;
        bool verifyServerCert = false;
        std::string authorizationHeader;

        // Used only in UDP-over-WS mode (app-level connect handshake)
        std::string remoteHost;
        uint16_t remotePort = 0;
        std::string remoteProto; // "udp"
    };

    struct Options
    {
        std::string listenIp = "127.0.0.1";
        uint16_t listenPort = 18080;
        Mode mode = Mode::Tcp;
        std::function<void(const std::string&)> log;

        uint32_t logMask = 0xFFFFFFFFu; // or (Error|Info|Stats), see below

        size_t maxWsQueueBytes = 4 * 1024 * 1024;
        bool dropWsOnOverflow = true; // meaningful for UDP mode
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

    static void SetGlobalLogMask(uint32_t mask);
    static uint32_t GetGlobalLogMask();

private:
    void DoAccept();
    void HandleClient(void* nativeSocket);

    void StartUdpSessionDetached(); // <-- IMPORTANT: declare it

private:
    Options opt_;
    struct Impl;
    Impl* impl_ = nullptr;
};
