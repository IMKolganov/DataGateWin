#pragma once

#include <atomic>
#include <cstdint>
#include <functional>
#include <memory>
#include <optional>
#include <string>
#include <vector>

#if defined(_WIN32)
#ifndef NOMINMAX
#define NOMINMAX
#endif
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#endif

#include <boost/asio.hpp>
#include <boost/asio/ssl.hpp>
#include <boost/beast.hpp>
#include <boost/beast/ssl.hpp>
#include <boost/beast/websocket.hpp>

#include <openssl/err.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

namespace basio  = boost::asio;
namespace bssl   = basio::ssl;
namespace bbeast = boost::beast;
namespace bws    = bbeast::websocket;

using btcp = basio::ip::tcp;
using budp = basio::ip::udp;

class WssLocalBridge;

enum class LogMask : uint32_t
{
    Error  = 1u << 0,
    Info   = 1u << 1,
    Debug  = 1u << 2,
    Trace  = 1u << 3,
    Stats  = 1u << 4,
    Packet = 1u << 5,

    Default = Error | Info | Stats
};

uint32_t ToU32(LogMask m);

std::string Tid();

struct BridgeLogApi
{
    static void EmitLog(const std::function<void(const std::string&)>& logFn, const std::string& s);
};

bool ShouldLog(uint32_t globalMask, uint32_t localMask, LogMask m);

void EmitLogMasked(
    const std::function<void(const std::string&)>& logFn,
    uint32_t globalMask,
    uint32_t localMask,
    LogMask m,
    const std::string& s);

void DrainOpenSslErrors(
    const std::function<void(const std::string&)>& logFn,
    uint32_t globalMask,
    uint32_t localMask,
    const char* where);

void LogEc(
    const std::function<void(const std::string&)>& logFn,
    uint32_t globalMask,
    uint32_t localMask,
    const char* where,
    const boost::system::error_code& ec);

struct BridgeTargetView
{
    std::string host;
    std::string port;
    std::string path;
    std::string sni;
    bool verifyServerCert = true;

    std::string remoteHost;
    uint16_t remotePort = 0;
    std::string remoteProto;

    std::string authorizationHeader;
};

std::string EffectiveSni(const BridgeTargetView& t);
std::string JsonEscape(const std::string& s);
std::string HexPrefix(const uint8_t* p, size_t n, size_t maxBytes = 32);
uint64_t NowMs();
std::string EpToString(const budp::endpoint& ep);

void AppendU16Be(std::vector<uint8_t>& v, uint16_t x);
bool TryReadU16Be(const uint8_t* p, size_t n, uint16_t& out);

struct WsConnection
{
    bssl::context sslCtx;
    bbeast::ssl_stream<bbeast::tcp_stream> tls;
    bws::stream<bbeast::ssl_stream<bbeast::tcp_stream>> ws;

    explicit WsConnection(basio::io_context& ioc);
};

std::shared_ptr<WsConnection> ConnectTlsWs(
    const std::function<void(const std::string&)>& logFn,
    uint32_t globalMask,
    uint32_t localMask,
    basio::io_context& ioc,
    const BridgeTargetView& t,
    const char* tlsLogWhere);