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
#include <iostream>
#include <memory>
#include <mutex>
#include <thread>
#include <sstream>

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
    bssl::context sslCtx{bssl::context::tls_client};
    btcp::acceptor acceptor{ioc};
    std::thread worker;
    std::atomic<bool> stopped{false};
};

static std::mutex g_logMu;

static void LogLine(const std::string& s)
{
    std::lock_guard<std::mutex> lock(g_logMu);
    std::cerr << s << std::endl;
}

static std::string SniOf(const WssTcpBridge::Options& opt)
{
    return opt.sni.empty() ? opt.host : opt.sni;
}

static void LogStep(const char* step, const WssTcpBridge::Options& opt)
{
    LogLine(
        std::string("[wss-bridge] ") + step +
        " host=" + opt.host +
        " port=" + opt.port +
        " path=" + opt.path +
        " sni=" + SniOf(opt)
    );
}

static void DrainOpenSslErrors(const char* where)
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
            << " openssl_error=0x" << std::hex << std::uppercase << e
            << " text=" << buf;

        LogLine(oss.str());
    }

    if (!any)
        LogLine(std::string("[wss-bridge] ") + where + " openssl_error_queue=<empty>");
}

static void LogEc(const char* where, const boost::system::error_code& ec)
{
    if (!ec) return;

    std::ostringstream oss;
    oss << "[wss-bridge] " << where
        << " ec=" << ec.value()
        << " category=" << ec.category().name()
        << " message=" << ec.message();

    LogLine(oss.str());

    if (ec.category() == basio::error::get_ssl_category())
        DrainOpenSslErrors(where);
}

static std::string X509NameToString(X509_NAME* name)
{
    if (!name) return "<null>";

    char buf[1024]{};
    ::X509_NAME_oneline(name, buf, static_cast<int>(sizeof(buf)));
    return std::string(buf);
}

static void LogTlsInfo(SSL* ssl, const char* where)
{
    if (!ssl)
    {
        LogLine(std::string("[wss-bridge] ") + where + " tls ssl=<null>");
        return;
    }

    const char* ver = ::SSL_get_version(ssl);
    const char* cip = ::SSL_get_cipher_name(ssl);

    long vr = ::SSL_get_verify_result(ssl);

    std::ostringstream oss;
    oss << "[wss-bridge] " << where
        << " tls_version=" << (ver ? ver : "<null>")
        << " cipher=" << (cip ? cip : "<null>")
        << " verify_result=" << vr
        << " verify_text=" << ::X509_verify_cert_error_string(vr);

    LogLine(oss.str());

    X509* cert = ::SSL_get_peer_certificate(ssl);
    if (!cert)
    {
        LogLine(std::string("[wss-bridge] ") + where + " peer_cert=<null>");
        return;
    }

    X509_NAME* subj = ::X509_get_subject_name(cert);
    X509_NAME* iss  = ::X509_get_issuer_name(cert);

    LogLine(std::string("[wss-bridge] ") + where + " peer_subject=" + X509NameToString(subj));
    LogLine(std::string("[wss-bridge] ") + where + " peer_issuer=" + X509NameToString(iss));

    ::X509_free(cert);
}

WssTcpBridge::WssTcpBridge(Options opt)
    : opt_(std::move(opt)),
      impl_(new Impl())
{
    impl_->sslCtx.set_default_verify_paths();
    impl_->sslCtx.set_verify_mode(opt_.verifyServerCert ? bssl::verify_peer : bssl::verify_none);
}

WssTcpBridge::~WssTcpBridge()
{
    Stop();
    delete impl_;
}

void WssTcpBridge::Start()
{
    btcp::endpoint ep(basio::ip::make_address(opt_.listenIp), opt_.listenPort);

    impl_->acceptor.open(ep.protocol());
    impl_->acceptor.set_option(basio::socket_base::reuse_address(true));
    impl_->acceptor.bind(ep);
    impl_->acceptor.listen();

    DoAccept();
    impl_->worker = std::thread([this] { impl_->ioc.run(); });
}

void WssTcpBridge::Stop()
{
    impl_->stopped.store(true);

    bbeast::error_code ec;
    impl_->acceptor.close(ec);
    impl_->ioc.stop();

    if (impl_->worker.joinable())
        impl_->worker.join();
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
                {
                    LogLine(
                        std::string("[wss-bridge] accept error: ") +
                        ec.message() + " (" + std::to_string(ec.value()) + ")"
                    );
                }
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

    try
    {
        LogStep("client accepted", opt_);

        btcp::resolver resolver(impl_->ioc);

        LogStep("resolve", opt_);
        auto results = resolver.resolve(opt_.host, opt_.port);

        LogStep("create tls stream", opt_);
        bbeast::ssl_stream<bbeast::tcp_stream> tlsStream(impl_->ioc, impl_->sslCtx);

        const std::string sni = SniOf(opt_);
        ::SSL_set_tlsext_host_name(tlsStream.native_handle(), sni.c_str());

        LogStep("tcp connect", opt_);
        bbeast::get_lowest_layer(tlsStream).connect(results);

        LogStep("tls handshake", opt_);
        try
        {
            tlsStream.handshake(bssl::stream_base::client);
            LogTlsInfo(tlsStream.native_handle(), "after_tls_handshake");
            DrainOpenSslErrors("after_tls_handshake");
        }
        catch (const boost::system::system_error& e)
        {
            std::ostringstream oss;
            oss << "[wss-bridge] tls handshake threw"
                << " ec=" << e.code().value()
                << " category=" << e.code().category().name()
                << " message=" << e.code().message()
                << " what=" << e.what();

            LogLine(oss.str());

            LogTlsInfo(tlsStream.native_handle(), "tls_handshake_exception_tls_info");
            DrainOpenSslErrors("tls_handshake_exception");

            throw;
        }

        LogStep("create ws stream", opt_);
        bws::stream<bbeast::ssl_stream<bbeast::tcp_stream>> ws(std::move(tlsStream));
        ws.binary(true);

        ws.set_option(bws::stream_base::decorator(
            [this](bws::request_type& req)
            {
                req.set(bbeast::http::field::user_agent, "DataGateWin/1.0");
                if (!opt_.authorizationHeader.empty())
                    req.set(bbeast::http::field::authorization, opt_.authorizationHeader);
            }
        ));

        LogStep("ws handshake", opt_);
        try
        {
            bbeast::http::response<bbeast::http::string_body> res;
            ws.handshake(res, opt_.host, opt_.path);

            {
                std::ostringstream oss;
                oss << "[wss-bridge] ws_handshake_response status=" << res.result_int()
                    << " reason=" << res.reason();
                LogLine(oss.str());
            }

            for (auto const& h : res)
            {
                std::ostringstream oss;
                oss << "[wss-bridge] ws_handshake_header " << h.name_string() << ": " << h.value();
                LogLine(oss.str());
            }

            LogTlsInfo(ws.next_layer().native_handle(), "after_ws_handshake");
            DrainOpenSslErrors("after_ws_handshake");
        }
        catch (const boost::system::system_error& e)
        {
            std::ostringstream oss;
            oss << "[wss-bridge] ws handshake threw"
                << " ec=" << e.code().value()
                << " category=" << e.code().category().name()
                << " message=" << e.code().message()
                << " what=" << e.what();

            LogLine(oss.str());

            LogTlsInfo(ws.next_layer().native_handle(), "ws_handshake_exception_tls_info");
            DrainOpenSslErrors("ws_handshake_exception");

            throw;
        }

        std::atomic<bool> done{false};

        std::thread t1([&, client]()
        {
            std::array<uint8_t, 16 * 1024> buf{};
            uint64_t total = 0;

            while (!done.load())
            {
                boost::system::error_code ec;
                size_t n = client->read_some(basio::buffer(buf), ec);

                if (ec)
                {
                    LogEc("tcp->ws client read_some", ec);
                    break;
                }
                if (n == 0)
                {
                    LogLine("[wss-bridge] tcp->ws client read_some returned 0");
                    break;
                }

                total += static_cast<uint64_t>(n);

                boost::system::error_code wec;
                ws.write(basio::buffer(buf.data(), n), wec);
                if (wec)
                {
                    LogEc("tcp->ws ws.write", wec);

                    if (wec.category() == basio::error::get_ssl_category())
                    {
                        LogTlsInfo(ws.next_layer().native_handle(), "tcp_to_ws_write_tls_info");
                        DrainOpenSslErrors("tcp_to_ws_write_ssl_queue");
                    }

                    break;
                }
            }

            LogLine("[wss-bridge] tcp->ws loop exit total_bytes=" + std::to_string(total));
            done.store(true);
        });

        std::thread t2([&, client]()
        {
            bbeast::flat_buffer buf;
            uint64_t total = 0;

            while (!done.load())
            {
                buf.clear();

                boost::system::error_code ec;
                ws.read(buf, ec);

                if (ec)
                {
                    LogEc("ws->tcp ws.read", ec);

                    if (ec.category() == basio::error::get_ssl_category())
                    {
                        LogTlsInfo(ws.next_layer().native_handle(), "ws_to_tcp_read_tls_info");
                        DrainOpenSslErrors("ws_to_tcp_read_ssl_queue");
                    }

                    if (ec == bws::error::closed)
                    {
                        auto r = ws.reason();

                        std::ostringstream oss;
                        oss << "[wss-bridge] ws closed code=" << static_cast<unsigned>(r.code)
                            << " reason=" << r.reason;

                        LogLine(oss.str());
                    }

                    break;
                }

                total += static_cast<uint64_t>(buf.size());

                boost::system::error_code wtec;
                basio::write(*client, buf.data(), wtec);
                if (wtec)
                {
                    LogEc("ws->tcp tcp write", wtec);
                    break;
                }
            }

            LogLine("[wss-bridge] ws->tcp loop exit total_bytes=" + std::to_string(total));
            done.store(true);
        });

        t1.join();
        t2.join();

        boost::system::error_code cec;
        if (ws.is_open())
        {
            LogLine("[wss-bridge] ws closing...");
            ws.close(bws::close_code::normal, cec);
            LogEc("ws.close", cec);

            if (cec.category() == basio::error::get_ssl_category())
            {
                LogTlsInfo(ws.next_layer().native_handle(), "ws_close_tls_info");
                DrainOpenSslErrors("ws_close_ssl_queue");
            }
        }

        boost::system::error_code sec;
        client->shutdown(btcp::socket::shutdown_both, sec);
        client->close(sec);

        LogStep("session done", opt_);
    }
    catch (const boost::system::system_error& e)
    {
        std::ostringstream oss;
        oss << "[wss-bridge] error"
            << " code=" << e.code().value()
            << " category=" << e.code().category().name()
            << " message=" << e.code().message()
            << " what=" << e.what();

        LogLine(oss.str());

        if (e.code().category() == basio::error::get_ssl_category())
            DrainOpenSslErrors("catch_system_error_ssl_queue");
    }
    catch (const std::exception& e)
    {
        LogLine(std::string("[wss-bridge] error what=") + e.what());
    }
}
