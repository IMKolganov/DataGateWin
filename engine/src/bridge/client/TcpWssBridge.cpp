#include "TcpWssBridge.h"

#include <array>
#include <chrono>
#include <condition_variable>
#include <deque>
#include <mutex>
#include <optional>
#include <sstream>
#include <string>
#include <thread>
#include <utility>
#include <vector>

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

TcpWssBridge::~TcpWssBridge()
{
    Stop();
}

void TcpWssBridge::Start()
{
    bool expected = false;
    if (!sessionThreadStarted_.compare_exchange_strong(expected, true))
        return;

    stopRequested_.store(false);

    sessionThread_ = std::thread([this]()
    {
        RunAcceptLoop();
    });
}

void TcpWssBridge::Stop()
{
    stopRequested_.store(true);

    boost::system::error_code ec;
    if (acceptor_.is_open())
    {
        acceptor_.cancel(ec);
        LogEc(opt_.log, globalMask_, opt_.logMask, "acceptor.cancel", ec);

        acceptor_.close(ec);
        LogEc(opt_.log, globalMask_, opt_.logMask, "acceptor.close", ec);
    }

    if (sessionThread_.joinable())
        sessionThread_.join();

    {
        std::lock_guard<std::mutex> lock(clientsMtx_);
        for (auto& t : clientThreads_)
        {
            if (t.joinable())
                t.join();
        }
        clientThreads_.clear();
    }
}

void TcpWssBridge::RunAcceptLoop()
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

    DoAcceptOnce();

    while (!stopRequested_.load() && !stopped_.load())
        std::this_thread::sleep_for(std::chrono::milliseconds(50));
}

void TcpWssBridge::DoAcceptOnce()
{
    acceptor_.async_accept(
        [this](bbeast::error_code ec, btcp::socket socket)
        {
            if (stopRequested_.load() || stopped_.load())
                return;

            if (!ec)
            {
                std::lock_guard<std::mutex> lock(clientsMtx_);
                clientThreads_.emplace_back([this, s = std::move(socket)]() mutable
                {
                    HandleClient(std::move(s));
                });
            }
            else
            {
                if (!stopRequested_.load() && !stopped_.load())
                    LogEc(opt_.log, globalMask_, opt_.logMask, "accept", ec);
            }

            if (!stopRequested_.load() && !stopped_.load())
                DoAcceptOnce();
        }
    );
}

void TcpWssBridge::HandleClient(btcp::socket socket)
{
    auto client = std::make_shared<btcp::socket>(std::move(socket));
    activeSessions_.fetch_add(1);

    EmitLogMasked(opt_.log, globalMask_, opt_.logMask, LogMask::Info,
        std::string("[wss-bridge] session BEGIN tid=") + Tid());

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
        client->shutdown(btcp::socket::shutdown_both, sec);
        client->close(sec);

        activeSessions_.fetch_sub(1);
        EmitLogMasked(opt_.log, globalMask_, opt_.logMask, LogMask::Info,
            std::string("[wss-bridge] session END tid=") + Tid() +
            " activeSessions=" + std::to_string(activeSessions_.load()));
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
            EmitLogMasked(opt_.log, globalMask_, opt_.logMask, LogMask::Info, oss.str());
        }

        auto conn = ConnectTlsWs(opt_.log, globalMask_, opt_.logMask, ioc_, t, "after_tls_handshake");
        auto& ws = conn->ws;

        std::mutex wsMtx;
        std::atomic<bool> done{false};

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

        WsWriteQueue out(qMax, false);

        std::thread wsWriter([&]()
        {
            EmitLogMasked(opt_.log, globalMask_, opt_.logMask, LogMask::Info,
                std::string("[wss-bridge] tcp wsWriter BEGIN tid=") + Tid());

            std::vector<uint8_t> msg;

            while (!done.load() && !stopped_.load() && !stopRequested_.load())
            {
                msg.clear();
                if (!out.Pop(msg))
                {
                    if (done.load() || stopped_.load() || stopRequested_.load())
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
                    LogEc(opt_.log, globalMask_, opt_.logMask, "tcp wsWriter ws.write", wec);
                    break;
                }
            }

            done.store(true);
            out.Stop();

            EmitLogMasked(opt_.log, globalMask_, opt_.logMask, LogMask::Info,
                std::string("[wss-bridge] tcp wsWriter END tid=") + Tid());
        });

        std::thread t1([&, client]()
        {
            std::array<uint8_t, 16 * 1024> buf{};
            uint64_t total = 0;

            EmitLogMasked(opt_.log, globalMask_, opt_.logMask, LogMask::Info,
                std::string("[wss-bridge] tcp->ws thread BEGIN tid=") + Tid());

            while (!done.load() && !stopped_.load() && !stopRequested_.load())
            {
                boost::system::error_code ec;
                size_t n = client->read_some(basio::buffer(buf), ec);

                if (ec)
                {
                    LogEc(opt_.log, globalMask_, opt_.logMask, "tcp->ws client read_some", ec);
                    break;
                }
                if (n == 0)
                    break;

                total += static_cast<uint64_t>(n);

                std::vector<uint8_t> msg(buf.data(), buf.data() + n);
                if (!out.Push(std::move(msg)))
                    break;
            }

            EmitLogMasked(opt_.log, globalMask_, opt_.logMask, LogMask::Info,
                std::string("[wss-bridge] tcp->ws loop exit tid=") + Tid() +
                " total_bytes=" + std::to_string(total));

            done.store(true);
            out.Stop();
        });

        std::thread t2([&, client]()
        {
            bbeast::flat_buffer buf;
            uint64_t total = 0;

            EmitLogMasked(opt_.log, globalMask_, opt_.logMask, LogMask::Info,
                std::string("[wss-bridge] ws->tcp thread BEGIN tid=") + Tid());

            while (!done.load() && !stopped_.load() && !stopRequested_.load())
            {
                buf.clear();

                boost::system::error_code ec;
                {
                    std::lock_guard<std::mutex> lock(wsMtx);
                    ws.read(buf, ec);
                }

                if (ec)
                {
                    LogEc(opt_.log, globalMask_, opt_.logMask, "ws->tcp ws.read", ec);
                    break;
                }

                total += static_cast<uint64_t>(buf.size());

                boost::system::error_code wtec;
                basio::write(*client, buf.data(), wtec);
                if (wtec)
                {
                    LogEc(opt_.log, globalMask_, opt_.logMask, "ws->tcp tcp write", wtec);
                    break;
                }
            }

            EmitLogMasked(opt_.log, globalMask_, opt_.logMask, LogMask::Info,
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
        LogEc(opt_.log, globalMask_, opt_.logMask, "ws.close", cec);

        boost::system::error_code sec;
        client->shutdown(btcp::socket::shutdown_both, sec);
        client->close(sec);

        EmitLogMasked(opt_.log, globalMask_, opt_.logMask, LogMask::Info,
            std::string("[wss-bridge] session done tid=") + Tid());
    }
    catch (const boost::system::system_error& e)
    {
        std::ostringstream oss;
        oss << "[wss-bridge] error tid=" << Tid()
            << " code=" << e.code().value()
            << " category=" << e.code().category().name()
            << " message=" << e.code().message()
            << " what=" << e.what();

        EmitLogMasked(opt_.log, globalMask_, opt_.logMask, LogMask::Error, oss.str());

        if (e.code().category() == basio::error::get_ssl_category())
            DrainOpenSslErrors(opt_.log, globalMask_, opt_.logMask, "catch_system_error_ssl_queue");
    }
    catch (const std::exception& e)
    {
        EmitLogMasked(opt_.log, globalMask_, opt_.logMask, LogMask::Error,
            std::string("[wss-bridge] error tid=") + Tid() + " what=" + e.what());
    }

    activeSessions_.fetch_sub(1);
    EmitLogMasked(opt_.log, globalMask_, opt_.logMask, LogMask::Info,
        std::string("[wss-bridge] session END tid=") + Tid() +
        " activeSessions=" + std::to_string(activeSessions_.load()));
}