#pragma once

#include "WssBridgeCommon.h"

#include <atomic>
#include <condition_variable>
#include <cstdint>
#include <deque>
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

    void Start();
    void Stop();

private:
    void DoAccept();
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
};
