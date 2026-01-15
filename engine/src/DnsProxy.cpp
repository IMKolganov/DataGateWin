#include "DnsProxy.h"

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>

#include <atomic>
#include <chrono>
#include <cstdint>
#include <iostream>
#include <random>
#include <thread>
#include <unordered_map>
#include <vector>

#pragma comment(lib, "Ws2_32.lib")

namespace
{
struct Pending
{
    sockaddr_in client{};
    uint16_t originalTxId{};
    std::chrono::steady_clock::time_point ts{};
};

static bool IsLikelyDnsPacket(const uint8_t* buf, int len)
{
    return len >= 12;
}

static uint16_t ReadTxId(const uint8_t* buf, int len)
{
    if (len < 2) return 0;
    return (static_cast<uint16_t>(buf[0]) << 8) | static_cast<uint16_t>(buf[1]);
}

static void WriteTxId(uint8_t* buf, int len, uint16_t txid)
{
    if (len < 2) return;
    buf[0] = static_cast<uint8_t>((txid >> 8) & 0xFF);
    buf[1] = static_cast<uint8_t>(txid & 0xFF);
}

static void SockaddrToIpPort(const sockaddr_in& a, char* ipBuf, size_t ipBufLen, uint16_t& portOut)
{
    ipBuf[0] = '\0';
    inet_ntop(AF_INET, &a.sin_addr, ipBuf, (socklen_t)ipBufLen);
    portOut = ntohs(a.sin_port);
}

class TxIdGenerator
{
public:
    TxIdGenerator()
    {
        std::random_device rd;
        rng_.seed(rd());
    }

    uint16_t Next()
    {
        return static_cast<uint16_t>(dist_(rng_));
    }

private:
    std::mt19937 rng_{};
    std::uniform_int_distribution<uint32_t> dist_{1u, 65535u};
};
} // namespace

DnsProxy::~DnsProxy()
{
    Stop();
}

bool DnsProxy::Start(const Config& cfg)
{
    Stop();

    cfg_ = cfg;
    if (cfg_.vpnBindIp.empty())
    {
        std::cerr << "[dns] vpnBindIp is empty" << std::endl;
        return false;
    }

    running_.store(true);
    worker_ = std::thread([this]() { WorkerLoop(); });
    return true;
}

void DnsProxy::Stop()
{
    running_.store(false);
    if (worker_.joinable())
        worker_.join();
}

void DnsProxy::WorkerLoop()
{
    WSADATA wsa{};
    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0)
    {
        std::cerr << "[dns] WSAStartup failed" << std::endl;
        return;
    }

    SOCKET sListen = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (sListen == INVALID_SOCKET)
    {
        std::cerr << "[dns] socket(listen) failed err=" << WSAGetLastError() << std::endl;
        WSACleanup();
        return;
    }

    {
        BOOL reuse = TRUE;
        setsockopt(sListen, SOL_SOCKET, SO_REUSEADDR, (const char*)&reuse, sizeof(reuse));
    }

    sockaddr_in listenAddr{};
    listenAddr.sin_family = AF_INET;
    listenAddr.sin_port = htons(cfg_.listenPort);
    inet_pton(AF_INET, cfg_.listenIp.c_str(), &listenAddr.sin_addr);

    if (bind(sListen, (sockaddr*)&listenAddr, sizeof(listenAddr)) != 0)
    {
        std::cerr << "[dns] bind(listen) failed ip=" << cfg_.listenIp
                  << " port=" << cfg_.listenPort
                  << " err=" << WSAGetLastError() << std::endl;
        closesocket(sListen);
        WSACleanup();
        return;
    }

    SOCKET sUp = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (sUp == INVALID_SOCKET)
    {
        std::cerr << "[dns] socket(upstream) failed err=" << WSAGetLastError() << std::endl;
        closesocket(sListen);
        WSACleanup();
        return;
    }

    sockaddr_in vpnAddr{};
    vpnAddr.sin_family = AF_INET;
    vpnAddr.sin_port = htons(0);
    inet_pton(AF_INET, cfg_.vpnBindIp.c_str(), &vpnAddr.sin_addr);

    if (bind(sUp, (sockaddr*)&vpnAddr, sizeof(vpnAddr)) != 0)
    {
        std::cerr << "[dns] bind(upstream to vpn ip) failed ip=" << cfg_.vpnBindIp
                  << " err=" << WSAGetLastError() << std::endl;
        closesocket(sUp);
        closesocket(sListen);
        WSACleanup();
        return;
    }

    sockaddr_in upAddr{};
    upAddr.sin_family = AF_INET;
    upAddr.sin_port = htons(cfg_.upstreamPort);
    inet_pton(AF_INET, cfg_.upstreamIp.c_str(), &upAddr.sin_addr);

    std::vector<uint8_t> buf(4096);
    std::unordered_map<uint16_t, Pending> pending;
    TxIdGenerator txgen;

    auto cleanup = [&]()
    {
        auto now = std::chrono::steady_clock::now();
        for (auto it = pending.begin(); it != pending.end();)
        {
            if ((now - it->second.ts) > std::chrono::seconds(10))
            {
                std::cout << "[dns] pending timeout newtxid=" << it->first << std::endl;
                it = pending.erase(it);
            }
            else
            {
                ++it;
            }
        }
    };

    auto allocateTxId = [&]() -> uint16_t
    {
        for (int i = 0; i < 64; ++i)
        {
            uint16_t id = txgen.Next();
            if (pending.find(id) == pending.end())
                return id;
        }
        return txgen.Next();
    };

    std::cout << "[dns] started listen=" << cfg_.listenIp << ":" << cfg_.listenPort
              << " upstream=" << cfg_.upstreamIp << ":" << cfg_.upstreamPort
              << " vpnBindIp=" << cfg_.vpnBindIp
              << std::endl;

    while (running_.load())
    {
        fd_set readfds;
        FD_ZERO(&readfds);
        FD_SET(sListen, &readfds);
        FD_SET(sUp, &readfds);

        timeval tv{};
        tv.tv_sec = 1;
        tv.tv_usec = 0;

        int r = select(0, &readfds, nullptr, nullptr, &tv);
        if (r == SOCKET_ERROR)
        {
            std::cerr << "[dns] select failed err=" << WSAGetLastError() << std::endl;
            break;
        }

        if (r == 0)
        {
            cleanup();
            continue;
        }

        if (FD_ISSET(sListen, &readfds))
        {
            sockaddr_in client{};
            int clen = sizeof(client);

            int n = recvfrom(sListen, (char*)buf.data(), (int)buf.size(), 0, (sockaddr*)&client, &clen);
            if (n > 0)
            {
                if (!IsLikelyDnsPacket(buf.data(), n))
                {
                    std::cout << "[dns] q drop non-dns len=" << n << std::endl;
                    continue;
                }

                uint16_t originalTxId = ReadTxId(buf.data(), n);
                uint16_t newTxId = allocateTxId();

                char clientIp[INET_ADDRSTRLEN]{};
                uint16_t clientPort = 0;
                SockaddrToIpPort(client, clientIp, sizeof(clientIp), clientPort);

                std::cout << "[dns] q from " << clientIp << ":" << clientPort
                          << " len=" << n
                          << " txid=" << originalTxId
                          << " newtxid=" << newTxId
                          << std::endl;

                WriteTxId(buf.data(), n, newTxId);
                pending[newTxId] = Pending{ client, originalTxId, std::chrono::steady_clock::now() };

                int sent = sendto(sUp, (const char*)buf.data(), n, 0, (sockaddr*)&upAddr, sizeof(upAddr));
                if (sent <= 0)
                {
                    int err = WSAGetLastError();
                    pending.erase(newTxId);
                    std::cerr << "[dns] sendto upstream failed err=" << err
                              << " len=" << n
                              << " newtxid=" << newTxId
                              << std::endl;
                }
                else
                {
                    std::cout << "[dns] sent to upstream len=" << sent
                              << " newtxid=" << newTxId
                              << std::endl;
                }
            }
            else if (n == SOCKET_ERROR)
            {
                std::cerr << "[dns] recvfrom listen failed err=" << WSAGetLastError() << std::endl;
            }
        }

        if (FD_ISSET(sUp, &readfds))
        {
            sockaddr_in from{};
            int flen = sizeof(from);

            int n = recvfrom(sUp, (char*)buf.data(), (int)buf.size(), 0, (sockaddr*)&from, &flen);
            if (n > 0)
            {
                if (!IsLikelyDnsPacket(buf.data(), n))
                {
                    std::cout << "[dns] r drop non-dns len=" << n << std::endl;
                    continue;
                }

                uint16_t newTxId = ReadTxId(buf.data(), n);

                char fromIp[INET_ADDRSTRLEN]{};
                uint16_t fromPort = 0;
                SockaddrToIpPort(from, fromIp, sizeof(fromIp), fromPort);

                std::cout << "[dns] r from " << fromIp << ":" << fromPort
                          << " len=" << n
                          << " newtxid=" << newTxId
                          << std::endl;

                auto it = pending.find(newTxId);
                if (it == pending.end())
                {
                    std::cout << "[dns] r dropped no pending newtxid=" << newTxId << std::endl;
                    continue;
                }

                sockaddr_in client = it->second.client;
                uint16_t originalTxId = it->second.originalTxId;
                pending.erase(it);

                WriteTxId(buf.data(), n, originalTxId);

                char clientIp[INET_ADDRSTRLEN]{};
                uint16_t clientPort = 0;
                SockaddrToIpPort(client, clientIp, sizeof(clientIp), clientPort);

                int sent = sendto(sListen, (const char*)buf.data(), n, 0, (sockaddr*)&client, sizeof(client));
                if (sent <= 0)
                {
                    int err = WSAGetLastError();
                    std::cerr << "[dns] sendto client failed err=" << err
                              << " len=" << n
                              << " client=" << clientIp << ":" << clientPort
                              << std::endl;
                }
                else
                {
                    std::cout << "[dns] sent to client len=" << sent
                              << " client=" << clientIp << ":" << clientPort
                              << " txid=" << originalTxId
                              << std::endl;
                }
            }
            else if (n == SOCKET_ERROR)
            {
                std::cerr << "[dns] recvfrom upstream failed err=" << WSAGetLastError() << std::endl;
            }
        }
    }

    std::cout << "[dns] stopping..." << std::endl;
    closesocket(sUp);
    closesocket(sListen);
    WSACleanup();
    std::cout << "[dns] stopped" << std::endl;
}
