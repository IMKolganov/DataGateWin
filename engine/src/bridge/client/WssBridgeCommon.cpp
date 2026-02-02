#include "WssBridgeCommon.h"

#include <algorithm>
#include <array>
#include <chrono>
#include <iomanip>
#include <iostream>
#include <mutex>
#include <sstream>
#include <thread>

static std::mutex g_logMu;

uint32_t ToU32(LogMask m) { return static_cast<uint32_t>(m); }

std::string Tid()
{
    std::ostringstream oss;
    oss << std::this_thread::get_id();
    return oss.str();
}

void BridgeLogApi::EmitLog(const std::function<void(const std::string&)>& logFn, const std::string& s)
{
    if (logFn)
    {
        logFn(s);
        return;
    }

    std::lock_guard<std::mutex> lock(g_logMu);
    std::cerr << s << std::endl;
}

bool ShouldLog(uint32_t globalMask, uint32_t localMask, LogMask m)
{
    return ((globalMask & localMask) & ToU32(m)) != 0;
}

void EmitLogMasked(
    const std::function<void(const std::string&)>& logFn,
    uint32_t globalMask,
    uint32_t localMask,
    LogMask m,
    const std::string& s)
{
    if (!ShouldLog(globalMask, localMask, m))
        return;

    BridgeLogApi::EmitLog(logFn, s);
}

static std::string X509NameToString(X509_NAME* name)
{
    if (!name) return "<null>";

    char buf[1024]{};
    ::X509_NAME_oneline(name, buf, static_cast<int>(sizeof(buf)));
    return std::string(buf);
}

static void LogTlsInfo(
    const std::function<void(const std::string&)>& logFn,
    uint32_t globalMask,
    uint32_t localMask,
    SSL* ssl,
    const char* where)
{
    if (!ssl)
    {
        EmitLogMasked(logFn, globalMask, localMask, LogMask::Info,
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

        EmitLogMasked(logFn, globalMask, localMask, LogMask::Info, oss.str());
    }

    X509* cert = ::SSL_get_peer_certificate(ssl);
    if (!cert)
    {
        EmitLogMasked(logFn, globalMask, localMask, LogMask::Info,
            std::string("[wss-bridge] ") + where + " tid=" + Tid() + " peer_cert=<null>");
        return;
    }

    X509_NAME* subj = ::X509_get_subject_name(cert);
    X509_NAME* iss  = ::X509_get_issuer_name(cert);

    EmitLogMasked(logFn, globalMask, localMask, LogMask::Info,
        std::string("[wss-bridge] ") + where + " tid=" + Tid() + " peer_subject=" + X509NameToString(subj));
    EmitLogMasked(logFn, globalMask, localMask, LogMask::Info,
        std::string("[wss-bridge] ") + where + " tid=" + Tid() + " peer_issuer=" + X509NameToString(iss));

    ::X509_free(cert);
}

void DrainOpenSslErrors(
    const std::function<void(const std::string&)>& logFn,
    uint32_t globalMask,
    uint32_t localMask,
    const char* where)
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

        EmitLogMasked(logFn, globalMask, localMask, LogMask::Error, oss.str());
    }

    if (!any)
    {
        EmitLogMasked(logFn, globalMask, localMask, LogMask::Debug,
            std::string("[wss-bridge] ") + where + " tid=" + Tid() + " openssl_error_queue=<empty>");
    }
}

void LogEc(
    const std::function<void(const std::string&)>& logFn,
    uint32_t globalMask,
    uint32_t localMask,
    const char* where,
    const boost::system::error_code& ec)
{
    if (!ec) return;

    std::ostringstream oss;
    oss << "[wss-bridge] " << where
        << " tid=" << Tid()
        << " ec=" << ec.value()
        << " category=" << ec.category().name()
        << " message=" << ec.message();

    EmitLogMasked(logFn, globalMask, localMask, LogMask::Error, oss.str());

    if (ec.category() == basio::error::get_ssl_category())
        DrainOpenSslErrors(logFn, globalMask, localMask, where);
}

std::string EffectiveSni(const BridgeTargetView& t)
{
    return t.sni.empty() ? t.host : t.sni;
}

std::string JsonEscape(const std::string& s)
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

std::string EpToString(const budp::endpoint& ep)
{
    std::ostringstream oss;
    oss << ep.address().to_string() << ":" << ep.port();
    return oss.str();
}

std::string HexPrefix(const uint8_t* p, size_t n, size_t maxBytes)
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

void AppendU16Be(std::vector<uint8_t>& v, uint16_t x)
{
    v.push_back(static_cast<uint8_t>((x >> 8) & 0xFF));
    v.push_back(static_cast<uint8_t>(x & 0xFF));
}

bool TryReadU16Be(const uint8_t* p, size_t n, uint16_t& out)
{
    if (n < 2) return false;
    out = static_cast<uint16_t>((static_cast<uint16_t>(p[0]) << 8) | static_cast<uint16_t>(p[1]));
    return true;
}

uint64_t NowMs()
{
    return static_cast<uint64_t>(
        std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now().time_since_epoch()
        ).count()
    );
}

WsConnection::WsConnection(basio::io_context& ioc)
    : sslCtx(bssl::context::tls_client),
      tls(ioc, sslCtx),
      ws(std::move(tls))
{
}

std::shared_ptr<WsConnection> ConnectTlsWs(
    const std::function<void(const std::string&)>& logFn,
    uint32_t globalMask,
    uint32_t localMask,
    basio::io_context& ioc,
    const BridgeTargetView& t,
    const char* tlsLogWhere)
{
    auto c = std::make_shared<WsConnection>(ioc);

    boost::system::error_code ec;

    c->sslCtx.set_default_verify_paths(ec);
    LogEc(logFn, globalMask, localMask, "sslCtx.set_default_verify_paths", ec);
    if (ec) throw boost::system::system_error(ec);

    c->sslCtx.set_verify_mode(t.verifyServerCert ? bssl::verify_peer : bssl::verify_none);

    btcp::resolver resolver(ioc);
    auto results = resolver.resolve(t.host, t.port, ec);
    LogEc(logFn, globalMask, localMask, "resolver.resolve", ec);
    if (ec) throw boost::system::system_error(ec);

    const std::string sni = EffectiveSni(t);
    if (!::SSL_set_tlsext_host_name(c->ws.next_layer().native_handle(), sni.c_str()))
    {
        DrainOpenSslErrors(logFn, globalMask, localMask, "SSL_set_tlsext_host_name");
        EmitLogMasked(logFn, globalMask, localMask, LogMask::Error,
            std::string("[wss-bridge] SSL_set_tlsext_host_name failed tid=") + Tid() + " sni=" + sni);
    }

    bbeast::get_lowest_layer(c->ws).connect(results, ec);
    LogEc(logFn, globalMask, localMask, "tcp.connect", ec);
    if (ec) throw boost::system::system_error(ec);

    c->ws.next_layer().handshake(bssl::stream_base::client, ec);
    LogEc(logFn, globalMask, localMask, "tls.handshake", ec);
    if (ec) throw boost::system::system_error(ec);

    LogTlsInfo(logFn, globalMask, localMask, c->ws.next_layer().native_handle(), tlsLogWhere);
    DrainOpenSslErrors(logFn, globalMask, localMask, tlsLogWhere);

    c->ws.binary(true);

    c->ws.control_callback(
        [logFn, globalMask, localMask](bws::frame_type kind, bbeast::string_view payload)
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

            EmitLogMasked(logFn, globalMask, localMask, LogMask::Info, oss.str());
        });

    auto to = bws::stream_base::timeout::suggested(bbeast::role_type::client);
    c->ws.set_option(to);

    boost::system::error_code tec;
    auto& sock = bbeast::get_lowest_layer(c->ws).socket();

    sock.set_option(basio::socket_base::keep_alive(true), tec);
    LogEc(logFn, globalMask, localMask, "tcp.keep_alive", tec);

    sock.set_option(btcp::no_delay(true), tec);
    LogEc(logFn, globalMask, localMask, "tcp.no_delay", tec);

    c->ws.set_option(bws::stream_base::decorator(
        [t](bws::request_type& req)
        {
            if (!t.authorizationHeader.empty())
                req.set(bbeast::http::field::authorization, t.authorizationHeader);

            req.set(bbeast::http::field::user_agent, "datagate-wss-bridge");
        }));

    bbeast::http::response<bbeast::http::string_body> res;
    c->ws.handshake(res, t.host, t.path, ec);
    LogEc(logFn, globalMask, localMask, "ws.handshake", ec);
    if (ec) throw boost::system::system_error(ec);

    {
        std::ostringstream oss;
        oss << "[wss-bridge] ws_handshake_response tid=" << Tid()
            << " status=" << res.result_int()
            << " reason=" << res.reason();
        EmitLogMasked(logFn, globalMask, localMask, LogMask::Info, oss.str());
    }

    return c;
}