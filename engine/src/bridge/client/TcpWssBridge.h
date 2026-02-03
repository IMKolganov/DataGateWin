#pragma once

#include "WssBridgeCommon.h"

#include <atomic>
#include <cstdint>
#include <mutex>
#include <optional>
#include <thread>
#include <vector>

#include "WssBridgeOptionsView.h"

struct WssTcpBridgeOptionsView;

class TcpWssBridge
{
public:
    TcpWssBridge(
        WssTcpBridgeOptionsView opt,
        uint32_t globalMask,
        basio::io_context& ioc,
        std::atomic<bool>& stopped,
        std::mutex& targetMtx,
        std::optional<BridgeTargetView>& target,
        std::atomic<uint64_t>& activeSessions);

    ~TcpWssBridge();

    void Start();
    void Stop();

private:
    void RunAcceptLoop();
    void DoAcceptOnce();

    void HandleClient(btcp::socket socket);

private:
    WssTcpBridgeOptionsView opt_;
    uint32_t globalMask_;
    basio::io_context& ioc_;
    std::atomic<bool>& stopped_;

    std::mutex& targetMtx_;
    std::optional<BridgeTargetView>& target_;

    std::atomic<uint64_t>& activeSessions_;

    btcp::acceptor acceptor_;

    std::atomic<bool> stopRequested_{false};

    std::thread sessionThread_;
    std::atomic<bool> sessionThreadStarted_{false};

    std::mutex clientsMtx_;
    std::vector<std::thread> clientThreads_;
};