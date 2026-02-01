#include "../client/WssTcpBridge.h"

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

#include <algorithm>
#include <array>
#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstdint>
#include <deque>
#include <iomanip>
#include <iostream>
#include <memory>
#include <mutex>
#include <optional>
#include <sstream>
#include <thread>
#include <vector>

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

// ------------------------------------------------------------
// Logging
// ------------------------------------------------------------

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

static uint32_t ToU32(LogMask m) { return static_cast<uint32_t>(m); }

static std::atomic<uint32_t> g_globalLogMask{ static_cast<uint32_t>(LogMask::Default) };

static std::string Tid()
{
    std::ostringstream oss;
    oss << std::this_thread::get_id();
    return oss.str();
}

static void EmitLog(const WssTcpBridge::Options& opt, const std::string& s)
{
    if (opt.log)
    {
        opt.log(s);
        return;
    }

    static std::mutex mu;
    std::lock_guard<std::mutex> lock(mu);
    std::cerr << s << std::endl;
}

static bool ShouldLog(const WssTcpBridge::Options& opt, LogMask m)
{
    const uint32_t g = g_globalLogMask.load(std::memory_order_relaxed);
    const uint32_t l = opt.logMask;
    return ((g & l) & ToU32(m)) != 0;
}

static void EmitLogMasked(const WssTcpBridge::Options& opt, LogMask m, const std::string& s)
{
    if (!ShouldLog(opt, m))
        return;
    EmitLog(opt, s);
}

void WssTcpBridge::SetGlobalLogMask(uint32_t mask)
{
    g_globalLogMask.store(mask, std::memory_order_relaxed);
}

uint32_t WssTcpBridge::GetGlobalLogMask()
{
    return g_globalLogMask.load(std::memory_order_relaxed);
}

static void DrainOpenSslErrors(const WssTcpBridge::Options& opt, const char* where)
{
    unsigned long e = 0;
    bool any = false;

    while ((e = ::ERR_get_error()) != 0)
    {
        any = true;

        char buf[256]{};
        ::ERR_error_string_n(e, buf, sizeof(buf));

        std::ostringstream oss;
        oss << "[wss-bridge] " << where
            << " tid=" << Tid()
            << " openssl_error=0x" << std::hex << std::uppercase << e
            << " text=" << buf;

        EmitLogMasked(opt, LogMask::Error, oss.str());
    }

    if (!any)
        EmitLogMasked(opt, LogMask::Debug,
            std::string("[wss-bridge] ") + where + " tid=" + Tid() + " openssl_error_queue=<empty>");
}

static void LogEc(const WssTcpBridge::Options& opt, const char* where, const boost::system::error_code& ec)
{
    if (!ec) return;

    std::ostringstream oss;
    oss << "[wss-bridge] " << where
        << " tid=" << Tid()
        << " ec=" << ec.value()
        << " category=" << ec.category().name()
        << " message=" << ec.message();

    EmitLogMasked(opt, LogMask::Error, oss.str());

    if (ec.category() == basio::error::get_ssl_category())
        DrainOpenSslErrors(opt, where);
}

static std::string X509NameToString(X509_NAME* name)
{
    if (!name) return "<null>";

    char buf[1024]{};
    ::X509_NAME_oneline(name, buf, static_cast<int>(sizeof(buf)));
    return std::string(buf);
}

static void LogTlsInfo(const WssTcpBridge::Options& opt, SSL* ssl, const char* where)
{
    if (!ssl)
    {
        EmitLogMasked(opt, LogMask::Info,
            std::string("[wss-bridge] ") + where + " tid=" + Tid() + " tls ssl=<null>");
        return;
    }

    const char* ver = ::SSL_get_version(ssl);
    const char* cip = ::SSL_get_cipher_name(ssl);
    long vr = ::SSL_get_verify_result(ssl);

    {
        std::ostringstream oss;
        oss << "[wss-bridge] " << where
            << " tid=" << Tid()
            << " ssl=" << (void*)ssl
            << " tls_version=" << (ver ? ver : "<null>")
            << " cipher=" << (cip ? cip : "<null>")
            << " verify_result=" << vr
            << " verify_text=" << ::X509_verify_cert_error_string(vr);

        EmitLogMasked(opt, LogMask::Info, oss.str());
    }

    X509* cert = ::SSL_get_peer_certificate(ssl);
    if (!cert)
    {
        EmitLogMasked(opt, LogMask::Info,
            std::string("[wss-bridge] ") + where + " tid=" + Tid() + " peer_cert=<null>");
        return;
    }

    X509_NAME* subj = ::X509_get_subject_name(cert);
    X509_NAME* iss  = ::X509_get_issuer_name(cert);

    EmitLogMasked(opt, LogMask::Info,
        std::string("[wss-bridge] ") + where + " tid=" + Tid() + " peer_subject=" + X509NameToString(subj));
    EmitLogMasked(opt, LogMask::Info,
        std::string("[wss-bridge] ") + where + " tid=" + Tid() + " peer_issuer=" + X509NameToString(iss));

    ::X509_free(cert);
}

// ------------------------------------------------------------
// Utils
// ------------------------------------------------------------

static std::string EffectiveSni(const WssTcpBridge::Target& t)
{
    return t.sni.empty() ? t.host : t.sni;
}

static std::string JsonEscape(const std::string& s)
{
    std::string out;
    out.reserve(s.size() + 8);
    for (char c : s)
    {
        switch (c)
        {
        case '\\': out += "\\\\"; break;
        case '"':  out += "\\\""; break;
        case '\n': out += "\\n"; break;
        case '\r': out += "\\r"; break;
        case '\t': out += "\\t"; break;
        default:   out += c; break;
        }
    }
    return out;
}

static std::string EpToString(const budp::endpoint& ep)
{
    std::ostringstream oss;
    oss << ep.address().to_string() << ":" << ep.port();
    return oss.str();
}

static std::string HexPrefix(const uint8_t* p, size_t n, size_t maxBytes = 32)
{
    const size_t m = std::min(n, maxBytes);

    std::ostringstream oss;
    oss << "len=" << n << " hex=";

    oss << std::hex << std::setfill('0');
    for (size_t i = 0; i < m; i++)
    {
        oss << std::setw(2) << static_cast<unsigned>(p[i]);
        if (i + 1 < m) oss << " ";
    }

    oss << " ascii=\"";
    for (size_t i = 0; i < m; i++)
    {
        const unsigned char c = static_cast<unsigned char>(p[i]);
        if (c >= 32 && c <= 126) oss << static_cast<char>(c);
        else oss << '.';
    }
    oss << "\"";

    if (m < n) oss << " (+more)";
    return oss.str();
}

// Datagram framing: [uint16_be length][payload]
static void AppendU16Be(std::vector<uint8_t>& v, uint16_t x)
{
    v.push_back(static_cast<uint8_t>((x >> 8) & 0xFF));
    v.push_back(static_cast<uint8_t>(x & 0xFF));
}

static bool TryReadU16Be(const uint8_t* p, size_t n, uint16_t& out)
{
    if (n < 2) return false;
    out = static_cast<uint16_t>((static_cast<uint16_t>(p[0]) << 8) | static_cast<uint16_t>(p[1]));
    return true;
}

static uint64_t NowMs()
{
    return static_cast<uint64_t>(
        std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now().time_since_epoch()
        ).count()
    );
}

// ------------------------------------------------------------
// TLS+WS connect helper
// ------------------------------------------------------------

struct WsConnection
{
    bssl::context sslCtx;
    bbeast::ssl_stream<bbeast::tcp_stream> tls;
    bws::stream<bbeast::ssl_stream<bbeast::tcp_stream>> ws;

    explicit WsConnection(basio::io_context& ioc)
        : sslCtx(bssl::context::tls_client),
          tls(ioc, sslCtx),
          ws(std::move(tls))
    {
    }
};

static std::shared_ptr<WsConnection> ConnectTlsWs(
    const WssTcpBridge::Options& opt,
    basio::io_context& ioc,
    const WssTcpBridge::Target& t,
    const char* tlsLogWhere)
{
    auto c = std::make_shared<WsConnection>(ioc);

    boost::system::error_code ec;

    c->sslCtx.set_default_verify_paths(ec);
    LogEc(opt, "sslCtx.set_default_verify_paths", ec);
    if (ec) throw boost::system::system_error(ec);

    c->sslCtx.set_verify_mode(t.verifyServerCert ? bssl::verify_peer : bssl::verify_none);

    btcp::resolver resolver(ioc);
    auto results = resolver.resolve(t.host, t.port, ec);
    LogEc(opt, "resolver.resolve", ec);
    if (ec) throw boost::system::system_error(ec);

    const std::string sni = EffectiveSni(t);
    if (!::SSL_set_tlsext_host_name(c->ws.next_layer().native_handle(), sni.c_str()))
    {
        DrainOpenSslErrors(opt, "SSL_set_tlsext_host_name");
        EmitLogMasked(opt, LogMask::Error,
            std::string("[wss-bridge] SSL_set_tlsext_host_name failed tid=") + Tid() + " sni=" + sni);
    }

    bbeast::get_lowest_layer(c->ws).connect(results, ec);
    LogEc(opt, "tcp.connect", ec);
    if (ec) throw boost::system::system_error(ec);

    c->ws.next_layer().handshake(bssl::stream_base::client, ec);
    LogEc(opt, "tls.handshake", ec);
    if (ec) throw boost::system::system_error(ec);

    LogTlsInfo(opt, c->ws.next_layer().native_handle(), tlsLogWhere);
    DrainOpenSslErrors(opt, tlsLogWhere);

    c->ws.binary(true);

    c->ws.control_callback(
        [&opt](bws::frame_type kind, bbeast::string_view payload)
        {
            std::string k = "unknown";
            switch (kind)
            {
            case bws::frame_type::close: k = "close"; break;
            case bws::frame_type::ping:  k = "ping";  break;
            case bws::frame_type::pong:  k = "pong";  break;
            default: break;
            }

            std::ostringstream oss;
            oss << "[wss-bridge] ws control tid=" << Tid()
                << " kind=" << k
                << " payload=" << std::string(payload);
            EmitLogMasked(opt, LogMask::Info, oss.str());
        });

    // Compatible with older Boost: use suggested(...) (no timeout::none()).
    auto to = bws::stream_base::timeout::suggested(bbeast::role_type::client);
    c->ws.set_option(to);

    // Also enable TCP keepalive on the underlying socket (helps with NAT/LB)
    boost::system::error_code tec;
    auto& sock = bbeast::get_lowest_layer(c->ws).socket();
    sock.set_option(basio::socket_base::keep_alive(true), tec);
    LogEc(opt, "tcp.keep_alive", tec);

    sock.set_option(btcp::no_delay(true), tec);
    LogEc(opt, "tcp.no_delay", tec);

    bbeast::http::response<bbeast::http::string_body> res;
    c->ws.handshake(res, t.host, t.path, ec);
    LogEc(opt, "ws.handshake", ec);
    if (ec) throw boost::system::system_error(ec);

    {
        std::ostringstream oss;
        oss << "[wss-bridge] ws_handshake_response tid=" << Tid()
            << " status=" << res.result_int()
            << " reason=" << res.reason();
        EmitLogMasked(opt, LogMask::Info, oss.str());
    }

    return c;
}

// ------------------------------------------------------------
// Bridge internal state
// ------------------------------------------------------------

struct WssTcpBridge::Impl
{
    basio::io_context ioc{1};

    using WorkGuard = basio::executor_work_guard<basio::io_context::executor_type>;
    std::optional<WorkGuard> work{ basio::make_work_guard(ioc) };

    // TCP mode
    btcp::acceptor acceptor{ioc};

    // UDP mode
    budp::socket udpSock{ioc};
    std::atomic<bool> udpBound{false};

    std::mutex udpPeerMtx;
    std::optional<budp::endpoint> udpLastPeer;

    std::thread worker;

    std::atomic<bool> started{false};
    std::atomic<bool> stopped{false};

    std::atomic<uint64_t> activeSessions{0};

    std::mutex targetMtx;
    std::optional<Target> target;
};

// ------------------------------------------------------------
// WssTcpBridge public
// ------------------------------------------------------------

WssTcpBridge::WssTcpBridge(Options opt)
    : opt_(std::move(opt)),
      impl_(new Impl())
{
    EmitLogMasked(opt_, LogMask::Info, std::string("[wss-bridge] ctor tid=") + Tid());
}

WssTcpBridge::~WssTcpBridge()
{
    Stop();
    delete impl_;
    impl_ = nullptr;
}

bool WssTcpBridge::IsStarted() const
{
    return impl_ && impl_->started.load();
}

std::string WssTcpBridge::ListenIp() const
{
    return opt_.listenIp;
}

uint16_t WssTcpBridge::ListenPort() const
{
    return opt_.listenPort;
}

void WssTcpBridge::UpdateTarget(Target t)
{
    if (!impl_) return;

    {
        std::lock_guard<std::mutex> lock(impl_->targetMtx);
        impl_->target = std::move(t);
    }

    EmitLogMasked(opt_, LogMask::Info, std::string("[wss-bridge] target updated tid=") + Tid());
}

void WssTcpBridge::ClearTarget()
{
    if (!impl_) return;

    {
        std::lock_guard<std::mutex> lock(impl_->targetMtx);
        impl_->target.reset();
    }

    EmitLogMasked(opt_, LogMask::Info, std::string("[wss-bridge] target cleared tid=") + Tid());
}

void WssTcpBridge::Start()
{
    if (!impl_) return;

    bool expected = false;
    if (!impl_->started.compare_exchange_strong(expected, true))
    {
        EmitLogMasked(opt_, LogMask::Info, std::string("[wss-bridge] Start skipped (already started) tid=") + Tid());
        return;
    }

    impl_->stopped.store(false);

    EmitLogMasked(opt_, LogMask::Info,
        std::string("[wss-bridge] Start ENTER tid=") + Tid() +
        " listen=" + opt_.listenIp + ":" + std::to_string(opt_.listenPort) +
        " mode=" + std::string(opt_.mode == WssTcpBridge::Mode::Udp ? "udp" : "tcp"));

    // Ensure io_context stays alive
    if (!impl_->work.has_value())
        impl_->work.emplace(basio::make_work_guard(impl_->ioc));

    boost::system::error_code ec;

    if (opt_.mode == WssTcpBridge::Mode::Udp)
    {
        budp::endpoint ep(basio::ip::make_address(opt_.listenIp, ec), opt_.listenPort);
        LogEc(opt_, "udp.make_address", ec);
        if (ec) { impl_->started.store(false); return; }

        impl_->udpSock.open(ep.protocol(), ec);
        LogEc(opt_, "udp.open", ec);
        if (ec) { impl_->started.store(false); return; }

        impl_->udpSock.set_option(basio::socket_base::reuse_address(true), ec);
        LogEc(opt_, "udp.reuse_address", ec);

        impl_->udpSock.bind(ep, ec);
        LogEc(opt_, "udp.bind", ec);
        if (ec) { impl_->started.store(false); return; }

        impl_->udpBound.store(true);

        impl_->worker = std::thread([this]
        {
            EmitLogMasked(opt_, LogMask::Info, std::string("[wss-bridge] io_context.run BEGIN tid=") + Tid());

            try
            {
                impl_->ioc.run();
            }
            catch (const std::exception& e)
            {
                EmitLogMasked(opt_, LogMask::Error,
                    std::string("[wss-bridge] ioc.run exception tid=") + Tid() + " what=" + e.what());
                DrainOpenSslErrors(opt_, "ioc.run exception");
            }

            EmitLogMasked(opt_, LogMask::Info, std::string("[wss-bridge] io_context.run END tid=") + Tid());
        });

        StartUdpSessionDetached();
        EmitLogMasked(opt_, LogMask::Info, std::string("[wss-bridge] Start OK tid=") + Tid());
        return;
    }

    // TCP mode
    btcp::endpoint ep(basio::ip::make_address(opt_.listenIp, ec), opt_.listenPort);
    LogEc(opt_, "tcp.make_address", ec);
    if (ec) { impl_->started.store(false); return; }

    impl_->acceptor.open(ep.protocol(), ec);
    LogEc(opt_, "acceptor.open", ec);
    if (ec) { impl_->started.store(false); return; }

    impl_->acceptor.set_option(basio::socket_base::reuse_address(true), ec);
    LogEc(opt_, "acceptor.reuse_address", ec);

    impl_->acceptor.bind(ep, ec);
    LogEc(opt_, "acceptor.bind", ec);
    if (ec) { impl_->started.store(false); return; }

    impl_->acceptor.listen(basio::socket_base::max_listen_connections, ec);
    LogEc(opt_, "acceptor.listen", ec);
    if (ec) { impl_->started.store(false); return; }

    DoAccept();

    impl_->worker = std::thread([this]
    {
        EmitLogMasked(opt_, LogMask::Info, std::string("[wss-bridge] io_context.run BEGIN tid=") + Tid());

        try
        {
            impl_->ioc.run();
        }
        catch (const std::exception& e)
        {
            EmitLogMasked(opt_, LogMask::Error,
                std::string("[wss-bridge] ioc.run exception tid=") + Tid() + " what=" + e.what());
            DrainOpenSslErrors(opt_, "ioc.run exception");
        }

        EmitLogMasked(opt_, LogMask::Info, std::string("[wss-bridge] io_context.run END tid=") + Tid());
    });

    EmitLogMasked(opt_, LogMask::Info, std::string("[wss-bridge] Start OK tid=") + Tid());
}

void WssTcpBridge::Stop()
{
    if (!impl_) return;

    const bool wasStopped = impl_->stopped.exchange(true);
    if (wasStopped)
        return;

    EmitLogMasked(opt_, LogMask::Info,
        std::string("[wss-bridge] Stop ENTER tid=") + Tid() +
        " activeSessions=" + std::to_string(impl_->activeSessions.load()));

    boost::system::error_code ec;

    if (impl_->acceptor.is_open())
    {
        impl_->acceptor.cancel(ec);
        LogEc(opt_, "acceptor.cancel", ec);

        impl_->acceptor.close(ec);
        LogEc(opt_, "acceptor.close", ec);
    }

    if (impl_->udpSock.is_open())
    {
        impl_->udpSock.close(ec);
        LogEc(opt_, "udp.close", ec);
    }

    if (impl_->work.has_value())
        impl_->work.reset();

    impl_->ioc.stop();

    if (impl_->worker.joinable())
        impl_->worker.join();

    impl_->started.store(false);

    EmitLogMasked(opt_, LogMask::Info,
        std::string("[wss-bridge] Stop OK tid=") + Tid() +
        " activeSessions=" + std::to_string(impl_->activeSessions.load()));
}

void WssTcpBridge::DoAccept()
{
    impl_->acceptor.async_accept(
        [this](bbeast::error_code ec, btcp::socket socket)
        {
            if (!ec && !impl_->stopped.load())
            {
                auto* psock = new std::shared_ptr<btcp::socket>(
                    std::make_shared<btcp::socket>(std::move(socket))
                );

                std::thread([this, psock]()
                {
                    HandleClient(reinterpret_cast<void*>(psock));
                }).detach();
            }
            else
            {
                if (ec && !impl_->stopped.load())
                    LogEc(opt_, "accept", ec);
            }

            if (!impl_->stopped.load())
                DoAccept();
        }
    );
}

// ------------------------------------------------------------
// UDP session (FIXED: all ws read/write serialized on one strand via async ops)
// ------------------------------------------------------------

struct UdpWsSession : public std::enable_shared_from_this<UdpWsSession>
{
    WssTcpBridge* self;
    WssTcpBridge::Options opt;
    WssTcpBridge::Target target;

    basio::io_context& ioc;
    budp::socket& udpSock;

    std::atomic<bool>& stopped;
    std::mutex& udpPeerMtx;
    std::optional<budp::endpoint>& udpLastPeer;

    std::shared_ptr<WsConnection> conn;
    bws::stream<bbeast::ssl_stream<bbeast::tcp_stream>>* ws{nullptr};

    basio::strand<basio::io_context::executor_type> strand;

    std::array<uint8_t, 64 * 1024> udpBuf{};
    budp::endpoint udpPeerTmp{};

    bbeast::flat_buffer wsInBuf{};

    std::deque<std::vector<uint8_t>> wsOutQ;
    size_t wsOutBytes{0};
    size_t wsOutMax{4 * 1024 * 1024};
    bool dropOnOverflow{true};
    bool wsWriteInProgress{false};

    std::atomic<bool> done{false};

    // Counters
    std::atomic<uint64_t> udpRxPackets{0};
    std::atomic<uint64_t> udpRxBytes{0};

    std::atomic<uint64_t> wsTxMsgs{0};
    std::atomic<uint64_t> wsTxBytes{0};

    std::atomic<uint64_t> wsRxMsgs{0};
    std::atomic<uint64_t> wsRxBytes{0};

    std::atomic<uint64_t> udpTxPackets{0};
    std::atomic<uint64_t> udpTxBytes{0};

    std::atomic<uint64_t> parseErrors{0};
    std::atomic<uint64_t> udpPeerChanges{0};
    std::atomic<uint64_t> wsDrops{0};

    basio::steady_timer statsTimer;
    uint64_t startMs{0};

    UdpWsSession(WssTcpBridge* s,
                 WssTcpBridge::Options o,
                 WssTcpBridge::Target t,
                 basio::io_context& io,
                 budp::socket& us,
                 std::atomic<bool>& stoppedFlag,
                 std::mutex& peerMtx,
                 std::optional<budp::endpoint>& lastPeer)
        : self(s),
          opt(std::move(o)),
          target(std::move(t)),
          ioc(io),
          udpSock(us),
          stopped(stoppedFlag),
          udpPeerMtx(peerMtx),
          udpLastPeer(lastPeer),
          strand(basio::make_strand(io)),
          statsTimer(io)
    {
    }

    void Start()
    {
        startMs = NowMs();

        // Connect TLS+WS synchronously before starting async loops.
        conn = ConnectTlsWs(opt, ioc, target, "udp_after_tls_handshake");
        ws = &conn->ws;

        // App-level connect handshake (text) - synchronous (safe, happens before async loops).
        {
            const std::string proto = target.remoteProto.empty() ? std::string("udp") : target.remoteProto;

            std::ostringstream j;
            j << "{"
              << "\"type\":\"connect\","
              << "\"proto\":\"" << JsonEscape(proto) << "\","
              << "\"host\":\"" << JsonEscape(target.remoteHost) << "\","
              << "\"port\":" << target.remotePort
              << "}";

            boost::system::error_code wec;
            ws->text(true);
            ws->write(basio::buffer(j.str()), wec);
            ws->text(false);

            if (wec)
            {
                LogEc(opt, "udp connect-handshake ws.write(text)", wec);
                throw boost::system::system_error(wec);
            }

            EmitLogMasked(opt, LogMask::Info,
                std::string("[wss-bridge] udp connect-handshake sent tid=") + Tid() + " json=" + j.str());
        }

        // Settings
        wsOutMax = (opt.maxWsQueueBytes > 0) ? opt.maxWsQueueBytes : (4 * 1024 * 1024);
        dropOnOverflow = opt.dropWsOnOverflow;

        // Start async loops on strand.
        basio::dispatch(strand, [sp = shared_from_this()]()
        {
            sp->DoUdpReceive();
            sp->DoWsRead();
            sp->ScheduleStats();
        });
    }

    void Stop()
    {
        if (done.exchange(true))
            return;

        basio::dispatch(strand, [sp = shared_from_this()]()
        {
            boost::system::error_code ec;

            // Compatible with older Asio: cancel() without error_code.
            sp->statsTimer.cancel();

            if (sp->ws && sp->ws->is_open())
                sp->ws->close(bws::close_code::normal, ec);

            LogEc(sp->opt, "udp session ws.close", ec);

            sp->wsOutQ.clear();
            sp->wsOutBytes = 0;
            sp->wsWriteInProgress = false;
        });
    }

    size_t QueueBytes() const { return wsOutBytes; }

    void EnqueueWsBinary(std::vector<uint8_t>&& msg)
    {
        const size_t sz = msg.size();

        if (wsOutBytes + sz > wsOutMax)
        {
            if (dropOnOverflow)
            {
                wsDrops.fetch_add(1);
                return;
            }

            // In UDP mode we avoid blocking producer threads.
            wsDrops.fetch_add(1);
            return;
        }

        wsOutBytes += sz;
        wsOutQ.emplace_back(std::move(msg));

        if (!wsWriteInProgress)
            DoWsWrite();
    }

    void DoWsWrite()
    {
        if (done.load() || stopped.load())
            return;

        if (wsOutQ.empty())
        {
            wsWriteInProgress = false;
            return;
        }

        wsWriteInProgress = true;

        auto& front = wsOutQ.front();
        ws->binary(true);

        ws->async_write(
            basio::buffer(front.data(), front.size()),
            basio::bind_executor(
                strand,
                [sp = shared_from_this()](boost::system::error_code ec, std::size_t bytes)
                {
                    if (ec)
                    {
                        LogEc(sp->opt, "udp ws async_write", ec);
                        sp->Stop();
                        return;
                    }

                    sp->wsTxMsgs.fetch_add(1);
                    sp->wsTxBytes.fetch_add(static_cast<uint64_t>(bytes));

                    if (!sp->wsOutQ.empty())
                    {
                        sp->wsOutBytes -= sp->wsOutQ.front().size();
                        sp->wsOutQ.pop_front();
                    }

                    sp->DoWsWrite();
                }
            )
        );
    }

    void DoWsRead()
    {
        if (done.load() || stopped.load())
            return;

        wsInBuf.clear();

        ws->async_read(
            wsInBuf,
            basio::bind_executor(
                strand,
                [sp = shared_from_this()](boost::system::error_code ec, std::size_t bytes)
                {
                    if (ec)
                    {
                        LogEc(sp->opt, "udp ws async_read", ec);
                        sp->Stop();
                        return;
                    }

                    const bool gotText = sp->ws->got_text();
                    sp->wsRxMsgs.fetch_add(1);
                    sp->wsRxBytes.fetch_add(static_cast<uint64_t>(bytes));

                    const auto data = sp->wsInBuf.data();
                    const uint8_t* p = static_cast<const uint8_t*>(data.data());
                    const size_t n = data.size();

                    const uint64_t msg = sp->wsRxMsgs.load();
                    if (ShouldLog(sp->opt, LogMask::Packet) && (msg <= 10 || (msg % 500 == 0)))
                    {
                        EmitLogMasked(sp->opt, LogMask::Packet,
                            std::string("[wss-bridge] ws->udp ws recv tid=") + Tid() +
                            " type=" + std::string(gotText ? "Text" : "Binary") +
                            " " + HexPrefix(p, n, 24));
                    }

                    if (gotText)
                    {
                        try
                        {
                            std::string s(static_cast<const char*>(data.data()), data.size());
                            EmitLogMasked(sp->opt, LogMask::Debug,
                                std::string("[wss-bridge] ws->udp text msg tid=") + Tid() + " text=" + s);
                        }
                        catch (...)
                        {
                            EmitLogMasked(sp->opt, LogMask::Debug,
                                std::string("[wss-bridge] ws->udp text msg tid=") + Tid() + " text=<failed_to_copy>");
                        }

                        sp->DoWsRead();
                        return;
                    }

                    std::optional<budp::endpoint> peer;
                    {
                        std::lock_guard<std::mutex> lock(sp->udpPeerMtx);
                        peer = sp->udpLastPeer;
                    }

                    if (!peer.has_value())
                    {
                        sp->DoWsRead();
                        return;
                    }

                    size_t off = 0;
                    uint64_t dgrams = 0;
                    bool parseOk = true;

                    while (off < n)
                    {
                        if (off + 2 > n) { parseOk = false; break; }

                        uint16_t len = 0;
                        if (!TryReadU16Be(p + off, n - off, len)) { parseOk = false; break; }
                        off += 2;

                        if (off + static_cast<size_t>(len) > n) { parseOk = false; break; }

                        boost::system::error_code sec;
                        sp->udpSock.send_to(basio::buffer(p + off, len), *peer, 0, sec);
                        if (sec)
                        {
                            LogEc(sp->opt, "udp ws->udp udp send_to", sec);
                            parseOk = false;
                            break;
                        }

                        sp->udpTxPackets.fetch_add(1);
                        sp->udpTxBytes.fetch_add(static_cast<uint64_t>(len));

                        off += len;
                        dgrams++;
                    }

                    if (!parseOk)
                    {
                        sp->parseErrors.fetch_add(1);

                        std::ostringstream oss;
                        oss << "[wss-bridge] ws->udp parse error tid=" << Tid()
                            << " msg_bytes=" << n
                            << " parsed_off=" << off
                            << " dgrams=" << dgrams
                            << " peer=" << EpToString(*peer);

                        EmitLogMasked(sp->opt, LogMask::Error, oss.str());
                    }

                    sp->DoWsRead();
                }
            )
        );
    }

    void DoUdpReceive()
    {
        if (done.load() || stopped.load())
            return;

        udpSock.async_receive_from(
            basio::buffer(udpBuf),
            udpPeerTmp,
            basio::bind_executor(
                strand,
                [sp = shared_from_this()](boost::system::error_code ec, std::size_t n)
                {
                    if (ec)
                    {
                        LogEc(sp->opt, "udp async_receive_from", ec);
                        sp->Stop();
                        return;
                    }

                    if (n == 0)
                    {
                        sp->DoUdpReceive();
                        return;
                    }

                    sp->udpRxPackets.fetch_add(1);
                    sp->udpRxBytes.fetch_add(static_cast<uint64_t>(n));

                    // Track last peer
                    {
                        std::lock_guard<std::mutex> lock(sp->udpPeerMtx);
                        const bool changed = !sp->udpLastPeer.has_value() ||
                                             (sp->udpLastPeer.value() != sp->udpPeerTmp);

                        sp->udpLastPeer = sp->udpPeerTmp;

                        if (changed)
                        {
                            sp->udpPeerChanges.fetch_add(1);
                            EmitLogMasked(sp->opt, LogMask::Info,
                                std::string("[wss-bridge] udp peer updated tid=") + Tid() +
                                " peer=" + EpToString(sp->udpPeerTmp));
                        }
                    }

                    const uint64_t pkt = sp->udpRxPackets.load();
                    if (ShouldLog(sp->opt, LogMask::Packet) && (pkt <= 10 || (pkt % 500 == 0)))
                    {
                        EmitLogMasked(sp->opt, LogMask::Packet,
                            std::string("[wss-bridge] udp->ws udp recv tid=") + Tid() +
                            " peer=" + EpToString(sp->udpPeerTmp) + " " +
                            HexPrefix(sp->udpBuf.data(), n, 24));
                    }

                    if (n <= 65535)
                    {
                        std::vector<uint8_t> framed;
                        framed.reserve(2 + n);
                        AppendU16Be(framed, static_cast<uint16_t>(n));
                        framed.insert(framed.end(), sp->udpBuf.data(), sp->udpBuf.data() + n);

                        sp->EnqueueWsBinary(std::move(framed));
                    }

                    sp->DoUdpReceive();
                }
            )
        );
    }

    void ScheduleStats()
    {
        if (done.load() || stopped.load())
            return;

        statsTimer.expires_after(std::chrono::seconds(1));
        statsTimer.async_wait(
            basio::bind_executor(
                strand,
                [sp = shared_from_this()](boost::system::error_code ec)
                {
                    if (ec)
                        return;

                    if (sp->done.load() || sp->stopped.load())
                        return;

                    const uint64_t tnow = NowMs();

                    std::ostringstream oss;
                    oss << "[wss-bridge] udp stats tid=" << Tid()
                        << " up_ms=" << (tnow - sp->startMs)
                        << " udp_rx_pkts=" << sp->udpRxPackets.load()
                        << " udp_rx_bytes=" << sp->udpRxBytes.load()
                        << " ws_tx_msgs=" << sp->wsTxMsgs.load()
                        << " ws_tx_bytes=" << sp->wsTxBytes.load()
                        << " ws_rx_msgs=" << sp->wsRxMsgs.load()
                        << " ws_rx_bytes=" << sp->wsRxBytes.load()
                        << " udp_tx_pkts=" << sp->udpTxPackets.load()
                        << " udp_tx_bytes=" << sp->udpTxBytes.load()
                        << " parse_errors=" << sp->parseErrors.load()
                        << " peer_changes=" << sp->udpPeerChanges.load()
                        << " ws_drops=" << sp->wsDrops.load()
                        << " ws_q_bytes=" << sp->wsOutBytes;

                    {
                        std::optional<budp::endpoint> peer;
                        std::lock_guard<std::mutex> lock(sp->udpPeerMtx);
                        peer = sp->udpLastPeer;
                        if (peer.has_value())
                            oss << " last_peer=" << EpToString(*peer);
                        else
                            oss << " last_peer=<none>";
                    }

                    EmitLogMasked(sp->opt, LogMask::Stats, oss.str());

                    sp->ScheduleStats();
                }
            )
        );
    }
};

void WssTcpBridge::StartUdpSessionDetached()
{
    std::thread([this]()
    {
        impl_->activeSessions.fetch_add(1);
        EmitLogMasked(opt_, LogMask::Info, std::string("[wss-bridge] udp session BEGIN tid=") + Tid());

        std::optional<Target> target;
        {
            std::lock_guard<std::mutex> lock(impl_->targetMtx);
            target = impl_->target;
        }

        if (!target.has_value())
        {
            EmitLogMasked(opt_, LogMask::Info, std::string("[wss-bridge] udp no target, stopping udp session tid=") + Tid());
            impl_->activeSessions.fetch_sub(1);
            return;
        }

        try
        {
            // Apply fallback for app-level remote target (OpenVPN original remote)
            auto fixed = *target;
            if (fixed.remoteHost.empty() || fixed.remotePort == 0)
            {
                fixed.remoteHost  = "185.70.197.119";
                fixed.remotePort  = 1299;
                fixed.remoteProto = "udp";
            }

            {
                std::ostringstream oss;
                oss << "[wss-bridge] udp target"
                    << " tid=" << Tid()
                    << " host=" << fixed.host
                    << " port=" << fixed.port
                    << " path=" << fixed.path
                    << " sni=" << EffectiveSni(fixed)
                    << " verifyServerCert=" << (fixed.verifyServerCert ? "true" : "false")
                    << " remoteHost=" << fixed.remoteHost
                    << " remotePort=" << fixed.remotePort
                    << " remoteProto=" << fixed.remoteProto;
                EmitLogMasked(opt_, LogMask::Info, oss.str());
            }

            auto session = std::make_shared<UdpWsSession>(
                this,
                opt_,
                fixed,
                impl_->ioc,
                impl_->udpSock,
                impl_->stopped,
                impl_->udpPeerMtx,
                impl_->udpLastPeer
            );

            session->Start();

            // Keep this thread alive while session is active by polling stopped flag.
            // Actual work is on io_context thread; this thread is only a lifetime guard.
            while (!impl_->stopped.load())
                std::this_thread::sleep_for(std::chrono::milliseconds(200));

            session->Stop();

            EmitLogMasked(opt_, LogMask::Info, std::string("[wss-bridge] udp session done tid=") + Tid());
        }
        catch (const boost::system::system_error& e)
        {
            std::ostringstream oss;
            oss << "[wss-bridge] udp error tid=" << Tid()
                << " code=" << e.code().value()
                << " category=" << e.code().category().name()
                << " message=" << e.code().message()
                << " what=" << e.what();

            EmitLogMasked(opt_, LogMask::Error, oss.str());

            if (e.code().category() == basio::error::get_ssl_category())
                DrainOpenSslErrors(opt_, "udp catch_system_error_ssl_queue");
        }
        catch (const std::exception& e)
        {
            EmitLogMasked(opt_, LogMask::Error,
                std::string("[wss-bridge] udp error tid=") + Tid() + " what=" + e.what());
        }

        impl_->activeSessions.fetch_sub(1);
        EmitLogMasked(opt_, LogMask::Info,
            std::string("[wss-bridge] udp session END tid=") + Tid() +
            " activeSessions=" + std::to_string(impl_->activeSessions.load()));
    }).detach();
}

// ------------------------------------------------------------
// TCP client session
// ------------------------------------------------------------

void WssTcpBridge::HandleClient(void* nativeSocket)
{
    std::unique_ptr<std::shared_ptr<btcp::socket>> holder(
        reinterpret_cast<std::shared_ptr<btcp::socket>*>(nativeSocket)
    );

    auto client = *holder;
    impl_->activeSessions.fetch_add(1);

    EmitLogMasked(opt_, LogMask::Info, std::string("[wss-bridge] session BEGIN tid=") + Tid());

    std::optional<Target> target;
    {
        std::lock_guard<std::mutex> lock(impl_->targetMtx);
        target = impl_->target;
    }

    if (!target.has_value())
    {
        EmitLogMasked(opt_, LogMask::Info, std::string("[wss-bridge] no target, closing client tid=") + Tid());
        boost::system::error_code sec;
        client->shutdown(btcp::socket::shutdown_both, sec);
        client->close(sec);

        impl_->activeSessions.fetch_sub(1);
        EmitLogMasked(opt_, LogMask::Info,
            std::string("[wss-bridge] session END tid=") + Tid() +
            " activeSessions=" + std::to_string(impl_->activeSessions.load()));
        return;
    }

    try
    {
        const auto& t = *target;

        {
            std::ostringstream oss;
            oss << "[wss-bridge] target"
                << " tid=" << Tid()
                << " host=" << t.host
                << " port=" << t.port
                << " path=" << t.path
                << " sni=" << EffectiveSni(t)
                << " verifyServerCert=" << (t.verifyServerCert ? "true" : "false");
            EmitLogMasked(opt_, LogMask::Info, oss.str());
        }

        auto conn = ConnectTlsWs(opt_, impl_->ioc, t, "after_tls_handshake");
        auto& ws = conn->ws;

        std::mutex wsMtx; // single lock for ANY ws operations (read/write/close)
        std::atomic<bool> done{false};

        // For TCP we prefer reliability -> block instead of drop
        const size_t qMax = (opt_.maxWsQueueBytes > 0) ? opt_.maxWsQueueBytes : (4 * 1024 * 1024);

        class WsWriteQueue
        {
        public:
            explicit WsWriteQueue(size_t maxBytes, bool dropOnOverflow)
                : maxBytes_(maxBytes), dropOnOverflow_(dropOnOverflow)
            {
            }

            bool Push(std::vector<uint8_t>&& msg)
            {
                std::unique_lock<std::mutex> lock(mtx_);
                if (stopped_) return false;

                const size_t sz = msg.size();

                if (bytes_ + sz > maxBytes_)
                {
                    if (dropOnOverflow_)
                        return false;

                    cv_.wait(lock, [&] { return stopped_ || (bytes_ + sz <= maxBytes_); });
                    if (stopped_) return false;
                }

                bytes_ += sz;
                q_.emplace_back(std::move(msg));
                cv_.notify_one();
                return true;
            }

            bool Pop(std::vector<uint8_t>& out)
            {
                std::unique_lock<std::mutex> lock(mtx_);
                cv_.wait(lock, [&] { return stopped_ || !q_.empty(); });

                if (q_.empty())
                    return false;

                out = std::move(q_.front());
                bytes_ -= out.size();
                q_.pop_front();

                cv_.notify_all();
                return true;
            }

            void Stop()
            {
                std::lock_guard<std::mutex> lock(mtx_);
                stopped_ = true;
                cv_.notify_all();
            }

        private:
            std::mutex mtx_;
            std::condition_variable cv_;
            std::deque<std::vector<uint8_t>> q_;

            size_t bytes_{0};
            size_t maxBytes_{4 * 1024 * 1024};
            bool dropOnOverflow_{true};
            bool stopped_{false};
        };

        WsWriteQueue out(qMax, false /*dropOnOverflow*/);

        // writer thread
        std::thread wsWriter([&]()
        {
            EmitLogMasked(opt_, LogMask::Info, std::string("[wss-bridge] tcp wsWriter BEGIN tid=") + Tid());
            std::vector<uint8_t> msg;

            while (!done.load() && !impl_->stopped.load())
            {
                msg.clear();
                if (!out.Pop(msg))
                {
                    if (done.load() || impl_->stopped.load())
                        break;
                    continue;
                }

                boost::system::error_code wec;
                {
                    std::lock_guard<std::mutex> lock(wsMtx);
                    ws.binary(true);
                    ws.write(basio::buffer(msg.data(), msg.size()), wec);
                }

                if (wec)
                {
                    LogEc(opt_, "tcp wsWriter ws.write", wec);
                    break;
                }
            }

            done.store(true);
            out.Stop();
            EmitLogMasked(opt_, LogMask::Info, std::string("[wss-bridge] tcp wsWriter END tid=") + Tid());
        });

        std::thread t1([&, client]()
        {
            std::array<uint8_t, 16 * 1024> buf{};
            uint64_t total = 0;

            EmitLogMasked(opt_, LogMask::Info, std::string("[wss-bridge] tcp->ws thread BEGIN tid=") + Tid());

            while (!done.load() && !impl_->stopped.load())
            {
                boost::system::error_code ec;
                size_t n = client->read_some(basio::buffer(buf), ec);

                if (ec)
                {
                    LogEc(opt_, "tcp->ws client read_some", ec);
                    break;
                }
                if (n == 0)
                    break;

                total += static_cast<uint64_t>(n);

                std::vector<uint8_t> msg(buf.data(), buf.data() + n);
                if (!out.Push(std::move(msg)))
                    break;
            }

            EmitLogMasked(opt_, LogMask::Info,
                std::string("[wss-bridge] tcp->ws loop exit tid=") + Tid() +
                " total_bytes=" + std::to_string(total));

            done.store(true);
            out.Stop();
        });

        std::thread t2([&, client]()
        {
            bbeast::flat_buffer buf;
            uint64_t total = 0;

            EmitLogMasked(opt_, LogMask::Info, std::string("[wss-bridge] ws->tcp thread BEGIN tid=") + Tid());

            while (!done.load() && !impl_->stopped.load())
            {
                buf.clear();

                boost::system::error_code ec;
                {
                    std::lock_guard<std::mutex> lock(wsMtx);
                    ws.read(buf, ec);
                }

                if (ec)
                {
                    LogEc(opt_, "ws->tcp ws.read", ec);
                    break;
                }

                total += static_cast<uint64_t>(buf.size());

                boost::system::error_code wtec;
                basio::write(*client, buf.data(), wtec);
                if (wtec)
                {
                    LogEc(opt_, "ws->tcp tcp write", wtec);
                    break;
                }
            }

            EmitLogMasked(opt_, LogMask::Info,
                std::string("[wss-bridge] ws->tcp loop exit tid=") + Tid() +
                " total_bytes=" + std::to_string(total));

            done.store(true);
            out.Stop();
        });

        t1.join();
        t2.join();

        done.store(true);
        out.Stop();

        if (wsWriter.joinable())
            wsWriter.join();

        boost::system::error_code cec;
        {
            std::lock_guard<std::mutex> lock(wsMtx);
            if (ws.is_open())
                ws.close(bws::close_code::normal, cec);
        }
        LogEc(opt_, "ws.close", cec);

        boost::system::error_code sec;
        client->shutdown(btcp::socket::shutdown_both, sec);
        client->close(sec);

        EmitLogMasked(opt_, LogMask::Info, std::string("[wss-bridge] session done tid=") + Tid());
    }
    catch (const boost::system::system_error& e)
    {
        std::ostringstream oss;
        oss << "[wss-bridge] error tid=" << Tid()
            << " code=" << e.code().value()
            << " category=" << e.code().category().name()
            << " message=" << e.code().message()
            << " what=" << e.what();

        EmitLogMasked(opt_, LogMask::Error, oss.str());

        if (e.code().category() == basio::error::get_ssl_category())
            DrainOpenSslErrors(opt_, "catch_system_error_ssl_queue");
    }
    catch (const std::exception& e)
    {
        EmitLogMasked(opt_, LogMask::Error, std::string("[wss-bridge] error tid=") + Tid() + " what=" + e.what());
    }

    impl_->activeSessions.fetch_sub(1);
    EmitLogMasked(opt_, LogMask::Info,
        std::string("[wss-bridge] session END tid=") + Tid() +
        " activeSessions=" + std::to_string(impl_->activeSessions.load()));
}