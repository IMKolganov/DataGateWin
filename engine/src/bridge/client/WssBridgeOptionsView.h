#pragma once

#include <cstdint>
#include <functional>
#include <string>

#include "WssBridgeCommon.h"

struct WssTcpBridgeOptionsView
{
    std::string listenIp;
    uint16_t listenPort = 0;

    uint32_t logMask = ToU32(LogMask::Default);
    std::function<void(const std::string&)> log;

    size_t maxWsQueueBytes = 0;
    bool dropWsOnOverflow = true;
};

// Convenience wrappers to keep legacy call sites simple.

inline void EmitLogMasked(
    const WssTcpBridgeOptionsView& opt,
    uint32_t globalMask,
    LogMask m,
    const std::string& s)
{
    EmitLogMasked(opt.log, globalMask, opt.logMask, m, s);
}

inline void LogEc(
    const WssTcpBridgeOptionsView& opt,
    uint32_t globalMask,
    const char* where,
    const boost::system::error_code& ec)
{
    LogEc(opt.log, globalMask, opt.logMask, where, ec);
}

inline void DrainOpenSslErrors(
    const WssTcpBridgeOptionsView& opt,
    uint32_t globalMask,
    const char* where)
{
    DrainOpenSslErrors(opt.log, globalMask, opt.logMask, where);
}