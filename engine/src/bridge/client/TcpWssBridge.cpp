#include "TcpWssBridge.h"

#include <array>
#include <chrono>
#include <deque>
#include <memory>
#include <sstream>
#include <string>
#include <utility>
#include <vector>

struct TcpWsSession : public std::enable_shared_from_this<TcpWsSession>
{
    WssTcpBridgeOptionsView opt;
    uint32_t globalMask;
    BridgeTargetView target;

    basio::io_context& ioc;
    std::atomic<bool>& stopped;
    std::atomic<uint64_t>& activeSessions;

    btcp::socket client;
    std::shared_ptr<WsConnection> conn;
    bws::stream<bbeast::ssl_stream<bbeast::tcp_stream>>* ws{nullptr};

    basio::strand<basio::io_context::executor_type> strand;

    std::array<uint8_t, 16 * 1024> tcpInBuf{};
    bbeast::flat_buffer wsInBuf{};

    std::deque<std::vector<uint8_t>> wsOutQ;
    bool wsWriteInProgress{false};
    size_t wsOutBytes{0};
    size_t wsOutMax{4 * 1024 * 1024};
    bool dropOnOverflow{true};

    std::deque<std::vector<uint8_t>> tcpOutQ;
    bool tcpWriteInProgress{false};
    size_t tcpOutBytes{0};
    size_t tcpOutMax{4 * 1024 * 1024};
    bool dropTcpOnOverflow{true};

    std::atomic<bool> done{false};

    TcpWsSession(
        WssTcpBridgeOptionsView o,
        uint32_t gmask,
        BridgeTargetView t,
        basio::io_context& io,
        std::atomic<bool>& stoppedFlag,
        std::atomic<uint64_t>& activeSessionsRef,
        btcp::socket s)
        : opt(std::move(o)),
          globalMask(gmask),
          target(std::move(t)),
          ioc(io),
          stopped(stoppedFlag),
          activeSessions(activeSessionsRef),
          client(std::move(s)),
          strand(basio::make_strand(io))
    {
        wsOutMax = (opt.maxWsQueueBytes > 0) ? opt.maxWsQueueBytes : (4 * 1024 * 1024);
        dropOnOverflow = opt.dropWsOnOverflow;

        tcpOutMax = (opt.maxWsQueueBytes > 0) ? opt.maxWsQueueBytes : (4 * 1024 * 1024);
        dropTcpOnOverflow = true;
    }

    void Start()
    {
        activeSessions.fetch_add(1);

        EmitLogMasked(opt.log, globalMask, opt.logMask, LogMask::Info,
            std::string("[wss-bridge] session BEGIN tid=") + Tid());

        boost::system::error_code ec;
        client.set_option(basio::ip::tcp::no_delay(true), ec);
        LogEc(opt.log, globalMask, opt.logMask, "tcp.client.no_delay", ec);

        conn = ConnectTlsWs(opt.log, globalMask, opt.logMask, ioc, target, "after_tls_handshake");
        ws = &conn->ws;

        basio::dispatch(strand, [sp = shared_from_this()]()
        {
            sp->DoTcpRead();
            sp->DoWsRead();
        });
    }

    void Stop()
    {
        if (done.exchange(true))
            return;

        basio::dispatch(strand, [sp = shared_from_this()]()
        {
            boost::system::error_code ec;

            if (sp->ws && sp->ws->is_open())
            {
                sp->ws->close(bws::close_code::normal, ec);
                LogEc(sp->opt.log, sp->globalMask, sp->opt.logMask, "tcp ws.close", ec);
            }

            boost::system::error_code sec;
            sp->client.shutdown(btcp::socket::shutdown_both, sec);
            sp->client.close(sec);

            sp->wsOutQ.clear();
            sp->wsOutBytes = 0;
            sp->wsWriteInProgress = false;

            sp->tcpOutQ.clear();
            sp->tcpOutBytes = 0;
            sp->tcpWriteInProgress = false;

            sp->activeSessions.fetch_sub(1);

            EmitLogMasked(sp->opt.log, sp->globalMask, sp->opt.logMask, LogMask::Info,
                std::string("[wss-bridge] session END tid=") + Tid() +
                " activeSessions=" + std::to_string(sp->activeSessions.load()));
        });
    }

    void EnqueueWs(std::vector<uint8_t>&& msg)
    {
        const size_t sz = msg.size();
        if (wsOutBytes + sz > wsOutMax)
        {
            if (!dropOnOverflow)
                return;
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
                        LogEc(sp->opt.log, sp->globalMask, sp->opt.logMask, "tcp ws async_write", ec);
                        sp->Stop();
                        return;
                    }

                    (void)bytes;

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

    void EnqueueTcp(std::vector<uint8_t>&& msg)
    {
        const size_t sz = msg.size();
        if (tcpOutBytes + sz > tcpOutMax)
        {
            if (!dropTcpOnOverflow)
                return;
            return;
        }

        tcpOutBytes += sz;
        tcpOutQ.emplace_back(std::move(msg));

        if (!tcpWriteInProgress)
            DoTcpWrite();
    }

    void DoTcpWrite()
    {
        if (done.load() || stopped.load())
            return;

        if (tcpOutQ.empty())
        {
            tcpWriteInProgress = false;
            return;
        }

        tcpWriteInProgress = true;
        auto& front = tcpOutQ.front();

        basio::async_write(
            client,
            basio::buffer(front.data(), front.size()),
            basio::bind_executor(
                strand,
                [sp = shared_from_this()](boost::system::error_code ec, std::size_t bytes)
                {
                    if (ec)
                    {
                        LogEc(sp->opt.log, sp->globalMask, sp->opt.logMask, "tcp async_write", ec);
                        sp->Stop();
                        return;
                    }

                    (void)bytes;

                    if (!sp->tcpOutQ.empty())
                    {
                        sp->tcpOutBytes -= sp->tcpOutQ.front().size();
                        sp->tcpOutQ.pop_front();
                    }

                    sp->DoTcpWrite();
                }
            )
        );
    }

    void DoTcpRead()
    {
        if (done.load() || stopped.load())
            return;

        client.async_read_some(
            basio::buffer(tcpInBuf),
            basio::bind_executor(
                strand,
                [sp = shared_from_this()](boost::system::error_code ec, std::size_t n)
                {
                    if (ec)
                    {
                        LogEc(sp->opt.log, sp->globalMask, sp->opt.logMask, "tcp async_read_some", ec);
                        sp->Stop();
                        return;
                    }

                    if (n == 0)
                    {
                        sp->DoTcpRead();
                        return;
                    }

                    std::vector<uint8_t> msg(sp->tcpInBuf.data(), sp->tcpInBuf.data() + n);
                    sp->EnqueueWs(std::move(msg));
                    sp->DoTcpRead();
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
                        LogEc(sp->opt.log, sp->globalMask, sp->opt.logMask, "tcp ws async_read", ec);
                        sp->Stop();
                        return;
                    }

                    (void)bytes;

                    if (sp->ws->got_text())
                    {
                        sp->DoWsRead();
                        return;
                    }

                    const auto data = sp->wsInBuf.data();
                    const uint8_t* p = static_cast<const uint8_t*>(data.data());
                    const size_t n = data.size();

                    std::vector<uint8_t> out(p, p + n);
                    sp->EnqueueTcp(std::move(out));

                    sp->DoWsRead();
                }
            )
        );
    }
};

TcpWssBridge::TcpWssBridge(
    WssTcpBridgeOptionsView opt,
    uint32_t globalMask,
    basio::io_context& ioc,
    std::atomic<bool>& stopped,
    std::mutex& targetMtx,
    std::optional<BridgeTargetView>& target,
    std::atomic<uint64_t>& activeSessions)
    : opt_(std::move(opt)),
      globalMask_(globalMask),
      ioc_(ioc),
      stopped_(stopped),
      targetMtx_(targetMtx),
      target_(target),
      activeSessions_(activeSessions),
      acceptor_(ioc)
{
}

void TcpWssBridge::Start()
{
    boost::system::error_code ec;

    btcp::endpoint ep(basio::ip::make_address(opt_.listenIp, ec), opt_.listenPort);
    LogEc(opt_.log, globalMask_, opt_.logMask, "tcp.make_address", ec);
    if (ec) return;

    acceptor_.open(ep.protocol(), ec);
    LogEc(opt_.log, globalMask_, opt_.logMask, "acceptor.open", ec);
    if (ec) return;

    acceptor_.set_option(basio::socket_base::reuse_address(true), ec);
    LogEc(opt_.log, globalMask_, opt_.logMask, "acceptor.reuse_address", ec);

    acceptor_.bind(ep, ec);
    LogEc(opt_.log, globalMask_, opt_.logMask, "acceptor.bind", ec);
    if (ec) return;

    acceptor_.listen(basio::socket_base::max_listen_connections, ec);
    LogEc(opt_.log, globalMask_, opt_.logMask, "acceptor.listen", ec);
    if (ec) return;

    DoAccept();
}

void TcpWssBridge::Stop()
{
    boost::system::error_code ec;
    if (acceptor_.is_open())
    {
        acceptor_.cancel(ec);
        LogEc(opt_.log, globalMask_, opt_.logMask, "acceptor.cancel", ec);

        acceptor_.close(ec);
        LogEc(opt_.log, globalMask_, opt_.logMask, "acceptor.close", ec);
    }
}

void TcpWssBridge::DoAccept()
{
    acceptor_.async_accept(
        [this](bbeast::error_code ec, btcp::socket socket)
        {
            if (ec)
            {
                if (!stopped_.load())
                    LogEc(opt_.log, globalMask_, opt_.logMask, "accept", ec);

                if (!stopped_.load())
                    DoAccept();

                return;
            }

            std::optional<BridgeTargetView> target;
            {
                std::lock_guard<std::mutex> lock(targetMtx_);
                target = target_;
            }

            if (!target.has_value())
            {
                EmitLogMasked(opt_.log, globalMask_, opt_.logMask, LogMask::Info,
                    std::string("[wss-bridge] no target, closing client tid=") + Tid());

                boost::system::error_code sec;
                socket.shutdown(btcp::socket::shutdown_both, sec);
                socket.close(sec);

                if (!stopped_.load())
                    DoAccept();

                return;
            }

            auto session = std::make_shared<TcpWsSession>(
                opt_,
                globalMask_,
                *target,
                ioc_,
                stopped_,
                activeSessions_,
                std::move(socket));

            session->Start();

            if (!stopped_.load())
                DoAccept();
        }
    );
}