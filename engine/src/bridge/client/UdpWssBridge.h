#pragma once

#include "WssBridgeCommon.h"

#include <atomic>
#include <mutex>
#include <optional>
#include <thread>
#include "WssBridgeOptionsView.h"

struct WssTcpBridgeOptionsView;

class UdpWssBridge
{
public:
    UdpWssBridge(
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
    void StartUdpSessionDetached();

private:
    WssTcpBridgeOptionsView opt_;
    uint32_t globalMask_;
    basio::io_context& ioc_;
    std::atomic<bool>& stopped_;

    std::mutex& targetMtx_;
    std::optional<BridgeTargetView>& target_;

    std::atomic<uint64_t>& activeSessions_;

    budp::socket udpSock_;
    std::atomic<bool> udpBound_{false};

    std::mutex udpPeerMtx_;
    std::optional<budp::endpoint> udpLastPeer_;
};