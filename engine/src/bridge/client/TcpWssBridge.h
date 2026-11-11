#pragma once

#include "WssBridgeCommon.h"

#include <atomic>
#include <cstdint>
#include <mutex>
#include <memory>
#include <optional>

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

    ~TcpWssBridge() { callbackLifetime_->store(false); }

    // Returns true if bind+listen succeeded.
    bool Start();
    void Stop();

private:
    void DoAccept();

private:
    WssTcpBridgeOptionsView opt_;
    uint32_t globalMask_;
    basio::io_context& ioc_;
    std::atomic<bool>& stopped_;

    std::mutex& targetMtx_;
    std::optional<BridgeTargetView>& target_;

    std::atomic<uint64_t>& activeSessions_;

    btcp::acceptor acceptor_;
    std::shared_ptr<std::atomic<bool>> callbackLifetime_ = std::make_shared<std::atomic<bool>>(true);
};