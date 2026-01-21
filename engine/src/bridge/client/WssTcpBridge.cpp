#include "../client/WssTcpBridge.h"

#include <boost/asio.hpp>
#include <boost/asio/ssl.hpp>
#include <boost/beast.hpp>
#include <boost/beast/ssl.hpp>
#include <boost/beast/websocket.hpp>

#include <iostream>
#include <array>

#if defined(_WIN32)
#ifndef NOMINMAX
#define NOMINMAX
#endif
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#endif

namespace basio = boost::asio;
namespace bssl  = basio::ssl;
namespace bbeast = boost::beast;
namespace bws   = bbeast::websocket;

using btcp = basio::ip::tcp;

struct WssTcpBridge::Impl
{
    basio::io_context ioc{1};
    bssl::context sslCtx{bssl::context::tls_client};
    btcp::acceptor acceptor{ioc};
    std::thread worker;
    std::atomic<bool> stopped{false};
};

WssTcpBridge::WssTcpBridge(Options opt)
    : opt_(std::move(opt)),
      impl_(new Impl())
{
    impl_->sslCtx.set_default_verify_paths();
    impl_->sslCtx.set_verify_mode(
        opt_.verifyServerCert ? bssl::verify_peer : bssl::verify_none
    );
}

WssTcpBridge::~WssTcpBridge()
{
    Stop();
    delete impl_;
}

void WssTcpBridge::Start()
{
    btcp::endpoint ep(
        basio::ip::make_address(opt_.listenIp),
        opt_.listenPort
    );

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
                std::thread(
                    [this, s = std::move(socket)]() mutable
                    {
                        HandleClient(&s);
                    }
                ).detach();
            }

            if (!impl_->stopped.load())
                DoAccept();
        }
    );
}

void WssTcpBridge::HandleClient(void* nativeSocket)
{
    auto& clientSock = *reinterpret_cast<btcp::socket*>(nativeSocket);

    try
    {
        btcp::resolver resolver(impl_->ioc);
        auto results = resolver.resolve(opt_.host, opt_.port);

        bbeast::ssl_stream<bbeast::tcp_stream> tlsStream(
            impl_->ioc,
            impl_->sslCtx
        );

        const std::string sni = opt_.sni.empty() ? opt_.host : opt_.sni;
        SSL_set_tlsext_host_name(tlsStream.native_handle(), sni.c_str());

        bbeast::get_lowest_layer(tlsStream).connect(results);
        tlsStream.handshake(bssl::stream_base::client);

        bws::stream<
            bbeast::ssl_stream<bbeast::tcp_stream>
        > ws(std::move(tlsStream));

        ws.binary(true);

        ws.set_option(bws::stream_base::decorator(
            [this](bws::request_type& req)
            {
                req.set(bbeast::http::field::user_agent, "DataGateWin/1.0");
                if (!opt_.authorizationHeader.empty())
                    req.set(
                        bbeast::http::field::authorization,
                        opt_.authorizationHeader
                    );
            }
        ));

        ws.handshake(opt_.host, opt_.path);

        std::atomic<bool> done{false};

        std::thread t1([&]
        {
            std::array<uint8_t, 16 * 1024> buf{};
            while (!done.load())
            {
                bbeast::error_code ec;
                size_t n = clientSock.read_some(basio::buffer(buf), ec);
                if (ec || n == 0) break;
                ws.write(basio::buffer(buf.data(), n));
            }
            done.store(true);
        });

        std::thread t2([&]
        {
            bbeast::flat_buffer buf;
            while (!done.load())
            {
                buf.clear();
                ws.read(buf);
                basio::write(clientSock, buf.data());
            }
            done.store(true);
        });

        t1.join();
        t2.join();

        if (ws.is_open())
            ws.close(bws::close_code::normal);
    }
    catch (const std::exception& e)
    {
        std::cerr << "WSS bridge error: " << e.what() << std::endl;
    }
}
