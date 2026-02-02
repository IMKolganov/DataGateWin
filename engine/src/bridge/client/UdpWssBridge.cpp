#include "UdpWssBridge.h"
#include "TcpWssBridge.h"

#include <array>
#include <chrono>
#include <deque>
#include "WssBridgeOptionsView.h"

struct UdpWsSession : public std::enable_shared_from_this<UdpWsSession>
{
    WssTcpBridgeOptionsView opt;
    uint32_t globalMask;
    BridgeTargetView target;

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

    UdpWsSession(
        WssTcpBridgeOptionsView o,
        uint32_t gmask,
        BridgeTargetView t,
        basio::io_context& io,
        budp::socket& us,
        std::atomic<bool>& stoppedFlag,
        std::mutex& peerMtx,
        std::optional<budp::endpoint>& lastPeer)
        : opt(std::move(o)),
          globalMask(gmask),
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

        conn = ConnectTlsWs(opt.log, globalMask, opt.logMask, ioc, target, "udp_after_tls_handshake");
        ws = &conn->ws;

        {
            const std::string proto = target.remoteProto.empty() ? std::string("udp") : target.remoteProto;

            std::ostringstream j;
            j << "{"
              << "\"type\":\"connect\","
              << "\"proto\":\"" << JsonEscape(proto) << "\"";

            if (!target.remoteHost.empty())
                j << ",\"host\":\"" << JsonEscape(target.remoteHost) << "\"";

            if (target.remotePort != 0)
                j << ",\"port\":" << target.remotePort;

            j << "}";

            boost::system::error_code wec;
            ws->text(true);
            ws->write(basio::buffer(j.str()), wec);
            ws->text(false);

            if (wec)
            {
                LogEc(opt.log, globalMask, opt.logMask, "udp connect-handshake ws.write(text)", wec);
                throw boost::system::system_error(wec);
            }

            EmitLogMasked(opt.log, globalMask, opt.logMask, LogMask::Info,
                std::string("[wss-bridge] udp connect-handshake sent tid=") + Tid() + " json=" + j.str());
        }

        wsOutMax = (opt.maxWsQueueBytes > 0) ? opt.maxWsQueueBytes : (4 * 1024 * 1024);
        dropOnOverflow = opt.dropWsOnOverflow;

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
            sp->statsTimer.cancel();

            if (sp->ws && sp->ws->is_open())
                sp->ws->close(bws::close_code::normal, ec);

            LogEc(sp->opt.log, sp->globalMask, sp->opt.logMask, "udp session ws.close", ec);

            sp->wsOutQ.clear();
            sp->wsOutBytes = 0;
            sp->wsWriteInProgress = false;
        });
    }

    void EnqueueWsBinary(std::vector<uint8_t>&& msg)
    {
        const size_t sz = msg.size();

        if (wsOutBytes + sz > wsOutMax)
        {
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
                        LogEc(sp->opt.log, sp->globalMask, sp->opt.logMask, "udp ws async_write", ec);
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
                        LogEc(sp->opt.log, sp->globalMask, sp->opt.logMask, "udp ws async_read", ec);
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
                    if (ShouldLog(sp->globalMask, sp->opt.logMask, LogMask::Packet) && (msg <= 10 || (msg % 500 == 0)))
                    {
                        EmitLogMasked(sp->opt.log, sp->globalMask, sp->opt.logMask, LogMask::Packet,
                            std::string("[wss-bridge] ws->udp ws recv tid=") + Tid() +
                            " type=" + std::string(gotText ? "Text" : "Binary") +
                            " " + HexPrefix(p, n, 24));
                    }

                    if (gotText)
                    {
                        try
                        {
                            std::string s(static_cast<const char*>(data.data()), data.size());
                            EmitLogMasked(sp->opt.log, sp->globalMask, sp->opt.logMask, LogMask::Debug,
                                std::string("[wss-bridge] ws->udp text msg tid=") + Tid() + " text=" + s);
                        }
                        catch (...)
                        {
                            EmitLogMasked(sp->opt.log, sp->globalMask, sp->opt.logMask, LogMask::Debug,
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
                            LogEc(sp->opt.log, sp->globalMask, sp->opt.logMask, "udp ws->udp udp send_to", sec);
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

                        EmitLogMasked(sp->opt.log, sp->globalMask, sp->opt.logMask, LogMask::Error, oss.str());
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
                        LogEc(sp->opt.log, sp->globalMask, sp->opt.logMask, "udp async_receive_from", ec);
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

                    {
                        std::lock_guard<std::mutex> lock(sp->udpPeerMtx);
                        const bool changed = !sp->udpLastPeer.has_value() ||
                                             (sp->udpLastPeer.value() != sp->udpPeerTmp);

                        sp->udpLastPeer = sp->udpPeerTmp;

                        if (changed)
                        {
                            sp->udpPeerChanges.fetch_add(1);
                            EmitLogMasked(sp->opt.log, sp->globalMask, sp->opt.logMask, LogMask::Info,
                                std::string("[wss-bridge] udp peer updated tid=") + Tid() +
                                " peer=" + EpToString(sp->udpPeerTmp));
                        }
                    }

                    const uint64_t pkt = sp->udpRxPackets.load();
                    if (ShouldLog(sp->globalMask, sp->opt.logMask, LogMask::Packet) && (pkt <= 10 || (pkt % 500 == 0)))
                    {
                        EmitLogMasked(sp->opt.log, sp->globalMask, sp->opt.logMask, LogMask::Packet,
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

                    EmitLogMasked(sp->opt.log, sp->globalMask, sp->opt.logMask, LogMask::Stats, oss.str());
                    sp->ScheduleStats();
                }
            )
        );
    }
};

UdpWssBridge::UdpWssBridge(
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
      udpSock_(ioc)
{
}

void UdpWssBridge::Start()
{
    boost::system::error_code ec;

    budp::endpoint ep(basio::ip::make_address(opt_.listenIp, ec), opt_.listenPort);
    LogEc(opt_.log, globalMask_, opt_.logMask, "udp.make_address", ec);
    if (ec) return;

    udpSock_.open(ep.protocol(), ec);
    LogEc(opt_.log, globalMask_, opt_.logMask, "udp.open", ec);
    if (ec) return;

    udpSock_.set_option(basio::socket_base::reuse_address(true), ec);
    LogEc(opt_.log, globalMask_, opt_.logMask, "udp.reuse_address", ec);

    udpSock_.bind(ep, ec);
    LogEc(opt_.log, globalMask_, opt_.logMask, "udp.bind", ec);
    if (ec) return;

    udpBound_.store(true);
    StartUdpSessionDetached();
}

void UdpWssBridge::Stop()
{
    boost::system::error_code ec;
    if (udpSock_.is_open())
    {
        udpSock_.close(ec);
        LogEc(opt_.log, globalMask_, opt_.logMask, "udp.close", ec);
    }
}

void UdpWssBridge::StartUdpSessionDetached()
{
    std::thread([this]()
    {
        activeSessions_.fetch_add(1);
        EmitLogMasked(opt_.log, globalMask_, opt_.logMask, LogMask::Info,
            std::string("[wss-bridge] udp session BEGIN tid=") + Tid());

        BridgeTargetView fixed{};
        const uint64_t startMs = NowMs();
        const uint64_t timeoutMs = 5000;

        for (;;)
        {
            if (stopped_.load())
            {
                EmitLogMasked(opt_.log, globalMask_, opt_.logMask, LogMask::Info,
                    std::string("[wss-bridge] udp session stopped before target ready tid=") + Tid());
                activeSessions_.fetch_sub(1);
                return;
            }

            std::optional<BridgeTargetView> t;
            {
                std::lock_guard<std::mutex> lock(targetMtx_);
                t = target_;
            }

            if (t.has_value())
            {
                fixed = *t;

                // For UDP mode we only need WSS target (host/port/path) to connect.
                const bool hasWssTarget = !fixed.host.empty() && !fixed.port.empty();
                if (hasWssTarget)
                {
                    if (fixed.remoteProto.empty())
                        fixed.remoteProto = "udp";

                    break;
                }
            }

            if (NowMs() - startMs > timeoutMs)
            {
                EmitLogMasked(opt_.log, globalMask_, opt_.logMask, LogMask::Error,
                    std::string("[wss-bridge] udp target not ready (host/port missing) tid=") + Tid());

                activeSessions_.fetch_sub(1);
                return;
            }

            std::this_thread::sleep_for(std::chrono::milliseconds(50));
        }

        try
        {
            {
                std::ostringstream oss;
                oss << "[wss-bridge] udp target"
                    << " tid=" << Tid()
                    << " host=" << fixed.host
                    << " port=" << fixed.port
                    << " path=" << fixed.path
                    << " sni=" << EffectiveSni(fixed)
                    << " verifyServerCert=" << (fixed.verifyServerCert ? "true" : "false")
                    << " remoteHost=" << (fixed.remoteHost.empty() ? "<empty>" : fixed.remoteHost)
                    << " remotePort=" << fixed.remotePort
                    << " remoteProto=" << fixed.remoteProto;

                EmitLogMasked(opt_.log, globalMask_, opt_.logMask, LogMask::Info, oss.str());
            }

            auto session = std::make_shared<UdpWsSession>(
                opt_,
                globalMask_,
                fixed,
                ioc_,
                udpSock_,
                stopped_,
                udpPeerMtx_,
                udpLastPeer_);

            session->Start();

            while (!stopped_.load())
                std::this_thread::sleep_for(std::chrono::milliseconds(200));

            session->Stop();

            EmitLogMasked(opt_.log, globalMask_, opt_.logMask, LogMask::Info,
                std::string("[wss-bridge] udp session done tid=") + Tid());
        }
        catch (const boost::system::system_error& e)
        {
            std::ostringstream oss;
            oss << "[wss-bridge] udp error tid=" << Tid()
                << " code=" << e.code().value()
                << " category=" << e.code().category().name()
                << " message=" << e.code().message()
                << " what=" << e.what();

            EmitLogMasked(opt_.log, globalMask_, opt_.logMask, LogMask::Error, oss.str());

            if (e.code().category() == basio::error::get_ssl_category())
                DrainOpenSslErrors(opt_.log, globalMask_, opt_.logMask, "udp catch_system_error_ssl_queue");
        }
        catch (const std::exception& e)
        {
            EmitLogMasked(opt_.log, globalMask_, opt_.logMask, LogMask::Error,
                std::string("[wss-bridge] udp error tid=") + Tid() + " what=" + e.what());
        }

        activeSessions_.fetch_sub(1);
        EmitLogMasked(opt_.log, globalMask_, opt_.logMask, LogMask::Info,
            std::string("[wss-bridge] udp session END tid=") + Tid() +
            " activeSessions=" + std::to_string(activeSessions_.load()));
    }).detach();
}