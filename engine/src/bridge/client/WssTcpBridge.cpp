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

#include <array>
#include <atomic>
#include <chrono>
#include <iomanip>
#include <iostream>
#include <memory>
#include <mutex>
#include <optional>
#include <sstream>
#include <thread>

#include <openssl/err.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

namespace basio  = boost::asio;
namespace bssl   = basio::ssl;
namespace bbeast = boost::beast;
namespace bws    = bbeast::websocket;

using btcp = basio::ip::tcp;

struct WssTcpBridge::Impl
{
    basio::io_context ioc{1};
    btcp::acceptor acceptor{ioc};
    std::thread worker;

    std::atomic<bool> started{false};
    std::atomic<bool> stopped{false};

    std::atomic<uint64_t> activeSessions{0};

    std::mutex targetMtx;
    std::optional<Target> target;
};

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

        EmitLog(opt, oss.str());
    }

    if (!any)
        EmitLog(opt, std::string("[wss-bridge] ") + where + " tid=" + Tid() + " openssl_error_queue=<empty>");
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

    EmitLog(opt, oss.str());

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
        EmitLog(opt, std::string("[wss-bridge] ") + where + " tid=" + Tid() + " tls ssl=<null>");
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

        EmitLog(opt, oss.str());
    }

    X509* cert = ::SSL_get_peer_certificate(ssl);
    if (!cert)
    {
        EmitLog(opt, std::string("[wss-bridge] ") + where + " tid=" + Tid() + " peer_cert=<null>");
        return;
    }

    X509_NAME* subj = ::X509_get_subject_name(cert);
    X509_NAME* iss  = ::X509_get_issuer_name(cert);

    EmitLog(opt, std::string("[wss-bridge] ") + where + " tid=" + Tid() + " peer_subject=" + X509NameToString(subj));
    EmitLog(opt, std::string("[wss-bridge] ") + where + " tid=" + Tid() + " peer_issuer=" + X509NameToString(iss));

    ::X509_free(cert);
}

static std::string EffectiveSni(const WssTcpBridge::Target& t)
{
    return t.sni.empty() ? t.host : t.sni;
}

WssTcpBridge::WssTcpBridge(Options opt)
    : opt_(std::move(opt)),
      impl_(new Impl())
{
    EmitLog(opt_, std::string("[wss-bridge] ctor tid=") + Tid());
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

    EmitLog(opt_, std::string("[wss-bridge] target updated tid=") + Tid());
}

void WssTcpBridge::ClearTarget()
{
    if (!impl_) return;

    {
        std::lock_guard<std::mutex> lock(impl_->targetMtx);
        impl_->target.reset();
    }

    EmitLog(opt_, std::string("[wss-bridge] target cleared tid=") + Tid());
}

void WssTcpBridge::Start()
{
    if (!impl_) return;

    bool expected = false;
    if (!impl_->started.compare_exchange_strong(expected, true))
    {
        EmitLog(opt_, std::string("[wss-bridge] Start skipped (already started) tid=") + Tid());
        return;
    }

    impl_->stopped.store(false);

    EmitLog(opt_, std::string("[wss-bridge] Start ENTER tid=") + Tid() +
                  " listen=" + opt_.listenIp + ":" + std::to_string(opt_.listenPort));

    btcp::endpoint ep(basio::ip::make_address(opt_.listenIp), opt_.listenPort);

    impl_->acceptor.open(ep.protocol());
    impl_->acceptor.set_option(basio::socket_base::reuse_address(true));
    impl_->acceptor.bind(ep);
    impl_->acceptor.listen();

    DoAccept();

    impl_->worker = std::thread([this]
    {
        EmitLog(opt_, std::string("[wss-bridge] io_context.run BEGIN tid=") + Tid());
        impl_->ioc.run();
        EmitLog(opt_, std::string("[wss-bridge] io_context.run END tid=") + Tid());
    });

    EmitLog(opt_, std::string("[wss-bridge] Start OK tid=") + Tid());
}

void WssTcpBridge::Stop()
{
    if (!impl_) return;

    const bool wasStopped = impl_->stopped.exchange(true);
    if (wasStopped)
        return;

    EmitLog(opt_, std::string("[wss-bridge] Stop ENTER tid=") + Tid() +
                  " activeSessions=" + std::to_string(impl_->activeSessions.load()));

    bbeast::error_code ec;
    impl_->acceptor.close(ec);
    LogEc(opt_, "acceptor.close", ec);

    impl_->ioc.stop();

    if (impl_->worker.joinable())
        impl_->worker.join();

    impl_->started.store(false);

    EmitLog(opt_, std::string("[wss-bridge] Stop OK tid=") + Tid() +
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

void WssTcpBridge::HandleClient(void* nativeSocket)
{
    std::unique_ptr<std::shared_ptr<btcp::socket>> holder(
        reinterpret_cast<std::shared_ptr<btcp::socket>*>(nativeSocket)
    );

    auto client = *holder;
    impl_->activeSessions.fetch_add(1);

    EmitLog(opt_, std::string("[wss-bridge] session BEGIN tid=") + Tid());

    std::optional<Target> target;
    {
        std::lock_guard<std::mutex> lock(impl_->targetMtx);
        target = impl_->target;
    }

    if (!target.has_value())
    {
        EmitLog(opt_, std::string("[wss-bridge] no target, closing client tid=") + Tid());
        boost::system::error_code sec;
        client->shutdown(btcp::socket::shutdown_both, sec);
        client->close(sec);

        impl_->activeSessions.fetch_sub(1);
        EmitLog(opt_, std::string("[wss-bridge] session END tid=") + Tid() +
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
            EmitLog(opt_, oss.str());
        }

        bssl::context sslCtx{bssl::context::tls_client};
        sslCtx.set_default_verify_paths();
        sslCtx.set_verify_mode(t.verifyServerCert ? bssl::verify_peer : bssl::verify_none);

        btcp::resolver resolver(impl_->ioc);

        auto results = resolver.resolve(t.host, t.port);

        bbeast::ssl_stream<bbeast::tcp_stream> tlsStream(impl_->ioc, sslCtx);

        const std::string sni = EffectiveSni(t);
        ::SSL_set_tlsext_host_name(tlsStream.native_handle(), sni.c_str());

        bbeast::get_lowest_layer(tlsStream).connect(results);

        tlsStream.handshake(bssl::stream_base::client);
        LogTlsInfo(opt_, tlsStream.native_handle(), "after_tls_handshake");
        DrainOpenSslErrors(opt_, "after_tls_handshake");

        bws::stream<bbeast::ssl_stream<bbeast::tcp_stream>> ws(std::move(tlsStream));
        ws.binary(true);

        ws.set_option(bws::stream_base::decorator(
            [&t](bws::request_type& req)
            {
                req.set(bbeast::http::field::user_agent, "DataGateWin/1.0");
                if (!t.authorizationHeader.empty())
                    req.set(bbeast::http::field::authorization, t.authorizationHeader);
            }
        ));

        bbeast::http::response<bbeast::http::string_body> res;
        ws.handshake(res, t.host, t.path);

        {
            std::ostringstream oss;
            oss << "[wss-bridge] ws_handshake_response tid=" << Tid()
                << " status=" << res.result_int()
                << " reason=" << res.reason();
            EmitLog(opt_, oss.str());
        }

        for (auto const& h : res)
        {
            std::ostringstream oss;
            oss << "[wss-bridge] ws_handshake_header tid=" << Tid()
                << " " << h.name_string() << ": " << h.value();
            EmitLog(opt_, oss.str());
        }

        LogTlsInfo(opt_, ws.next_layer().native_handle(), "after_ws_handshake");
        DrainOpenSslErrors(opt_, "after_ws_handshake");

        std::mutex wsMtx;
        std::atomic<bool> done{false};

        std::thread t1([&, client]()
        {
            std::array<uint8_t, 16 * 1024> buf{};
            uint64_t total = 0;

            EmitLog(opt_, std::string("[wss-bridge] tcp->ws thread BEGIN tid=") + Tid());

            while (!done.load())
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

                boost::system::error_code wec;
                {
                    std::lock_guard<std::mutex> lock(wsMtx);
                    ws.write(basio::buffer(buf.data(), n), wec);
                }

                if (wec)
                {
                    LogEc(opt_, "tcp->ws ws.write", wec);
                    break;
                }
            }

            EmitLog(opt_, std::string("[wss-bridge] tcp->ws loop exit tid=") + Tid() +
                          " total_bytes=" + std::to_string(total));

            done.store(true);
        });

        std::thread t2([&, client]()
        {
            bbeast::flat_buffer buf;
            uint64_t total = 0;

            EmitLog(opt_, std::string("[wss-bridge] ws->tcp thread BEGIN tid=") + Tid());

            while (!done.load())
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

            EmitLog(opt_, std::string("[wss-bridge] ws->tcp loop exit tid=") + Tid() +
                          " total_bytes=" + std::to_string(total));

            done.store(true);
        });

        t1.join();
        t2.join();

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

        EmitLog(opt_, std::string("[wss-bridge] session done tid=") + Tid());
    }
    catch (const boost::system::system_error& e)
    {
        std::ostringstream oss;
        oss << "[wss-bridge] error tid=" << Tid()
            << " code=" << e.code().value()
            << " category=" << e.code().category().name()
            << " message=" << e.code().message()
            << " what=" << e.what();

        EmitLog(opt_, oss.str());

        if (e.code().category() == basio::error::get_ssl_category())
            DrainOpenSslErrors(opt_, "catch_system_error_ssl_queue");
    }
    catch (const std::exception& e)
    {
        EmitLog(opt_, std::string("[wss-bridge] error tid=") + Tid() + " what=" + e.what());
    }

    impl_->activeSessions.fetch_sub(1);
    EmitLog(opt_, std::string("[wss-bridge] session END tid=") + Tid() +
                  " activeSessions=" + std::to_string(impl_->activeSessions.load()));
}
