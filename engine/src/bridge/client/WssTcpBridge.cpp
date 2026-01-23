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
#include <thread>

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

static void LogStep(const char* step, const WssTcpBridge::Options& opt)
{
    std::cerr << "[wss-bridge] " << step
              << " host=" << opt.host
              << " port=" << opt.port
              << " path=" << opt.path
              << " sni=" << (opt.sni.empty() ? opt.host : opt.sni)
              << std::endl;
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
                // Heap-own the socket (shared_ptr) and pass it as opaque pointer.
                auto* psock = new std::shared_ptr<btcp::socket>(std::make_shared<btcp::socket>(std::move(socket)));

                std::thread([this, psock]()
                {
                    HandleClient(reinterpret_cast<void*>(psock));
                }).detach();
            }
            else
            {
                if (ec && !impl_->stopped.load())
                {
                    std::cerr << "[wss-bridge] accept error: " << ec.message()
                              << " (" << ec.value() << ")" << std::endl;
                }
            }

            if (!impl_->stopped.load())
                DoAccept();
        }
    );
}

void WssTcpBridge::HandleClient(void* nativeSocket)
{
    // Take ownership of the heap pointer and guarantee delete.
    std::unique_ptr<std::shared_ptr<btcp::socket>> holder(
        reinterpret_cast<std::shared_ptr<btcp::socket>*>(nativeSocket)
    );

    auto client = *holder; // copy shared_ptr

    try
    {
        LogStep("client accepted", opt_);

        btcp::resolver resolver(impl_->ioc);

        LogStep("resolve", opt_);
        auto results = resolver.resolve(opt_.host, opt_.port);

        LogStep("create tls stream", opt_);
        bbeast::ssl_stream<bbeast::tcp_stream> tlsStream(impl_->ioc, impl_->sslCtx);

        const std::string sni = opt_.sni.empty() ? opt_.host : opt_.sni;
        SSL_set_tlsext_host_name(tlsStream.native_handle(), sni.c_str());

        LogStep("tcp connect", opt_);
        bbeast::get_lowest_layer(tlsStream).connect(results);

        LogStep("tls handshake", opt_);
        tlsStream.handshake(bssl::stream_base::client);

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
        ws.handshake(opt_.host, opt_.path);

        std::atomic<bool> done{false};

        std::thread t1([&, client]
        {
            std::array<uint8_t, 16 * 1024> buf{};
            while (!done.load())
            {
                bbeast::error_code ec;
                size_t n = client->read_some(basio::buffer(buf), ec);
                if (ec || n == 0)
                    break;

                bbeast::error_code wec;
                ws.write(basio::buffer(buf.data(), n), wec);
                if (wec)
                    break;
            }
            done.store(true);
        });

        std::thread t2([&, client]
        {
            bbeast::flat_buffer buf;
            while (!done.load())
            {
                buf.clear();

                bbeast::error_code ec;
                ws.read(buf, ec);
                if (ec)
                    break;

                bbeast::error_code wtec;
                basio::write(*client, buf.data(), wtec);
                if (wtec)
                    break;
            }
            done.store(true);
        });

        t1.join();
        t2.join();

        bbeast::error_code ec;
        if (ws.is_open())
            ws.close(bws::close_code::normal, ec);

        bbeast::error_code sec;
        client->shutdown(btcp::socket::shutdown_both, sec);
        client->close(sec);

        LogStep("session done", opt_);
    }
    catch (const boost::system::system_error& e)
    {
        std::cerr << "[wss-bridge] error code=" << e.code().value()
                  << " category=" << e.code().category().name()
                  << " message=" << e.code().message()
                  << " what=" << e.what()
                  << std::endl;
    }
    catch (const std::exception& e)
    {
        std::cerr << "[wss-bridge] error what=" << e.what() << std::endl;
    }
}
