#include "WssLocalBridge.h"

#include <memory>

static std::atomic<uint32_t> g_globalLogMask{ ToU32(LogMask::Default) };

struct WssLocalBridge::Impl
{
    basio::io_context ioc{1};
    using WorkGuard = basio::executor_work_guard<basio::io_context::executor_type>;
    std::optional<WorkGuard> work{ basio::make_work_guard(ioc) };

    std::thread worker;

    std::atomic<bool> started{false};
    std::atomic<bool> stopped{false};

    std::atomic<uint64_t> activeSessions{0};

    std::mutex targetMtx;
    std::optional<BridgeTargetView> target;

    std::unique_ptr<TcpWssBridge> tcp;
    std::unique_ptr<UdpWssBridge> udp;
};

void WssLocalBridge::SetGlobalLogMask(uint32_t mask)
{
    g_globalLogMask.store(mask, std::memory_order_relaxed);
}

uint32_t WssLocalBridge::GetGlobalLogMask()
{
    return g_globalLogMask.load(std::memory_order_relaxed);
}

static WssTcpBridgeOptionsView ToOptView(const WssLocalBridge::Options& o)
{
    WssTcpBridgeOptionsView v;
    v.listenIp = o.listenIp;
    v.listenPort = o.listenPort;
    v.logMask = o.logMask;
    v.log = o.log;
    v.maxWsQueueBytes = o.maxWsQueueBytes;
    v.dropWsOnOverflow = o.dropWsOnOverflow;
    return v;
}

static BridgeTargetView ToTargetView(const WssLocalBridge::Target& t)
{
    BridgeTargetView v;
    v.host = t.host;
    v.port = t.port;
    v.path = t.path;
    v.sni = t.sni;
    v.verifyServerCert = t.verifyServerCert;

    v.remoteHost = t.remoteHost;
    v.remotePort = t.remotePort;
    v.remoteProto = t.remoteProto;
    v.authorizationHeader = t.authorizationHeader;
    return v;
}

WssLocalBridge::WssLocalBridge(Options opt)
    : opt_(std::move(opt)),
      impl_(new Impl())
{
    EmitLogMasked(opt_.log, GetGlobalLogMask(), opt_.logMask, LogMask::Info,
        std::string("[wss-bridge] ctor tid=") + Tid());
}

WssLocalBridge::~WssLocalBridge()
{
    Stop();
    delete impl_;
    impl_ = nullptr;
}

bool WssLocalBridge::IsStarted() const
{
    return impl_ && impl_->started.load();
}

std::string WssLocalBridge::ListenIp() const
{
    return opt_.listenIp;
}

uint16_t WssLocalBridge::ListenPort() const
{
    return opt_.listenPort;
}

void WssLocalBridge::UpdateTarget(Target t)
{
    if (!impl_) return;

    {
        std::lock_guard<std::mutex> lock(impl_->targetMtx);
        impl_->target = ToTargetView(t);
    }

    EmitLogMasked(opt_.log, GetGlobalLogMask(), opt_.logMask, LogMask::Info,
        std::string("[wss-bridge] target updated tid=") + Tid());
}

void WssLocalBridge::ClearTarget()
{
    if (!impl_) return;

    {
        std::lock_guard<std::mutex> lock(impl_->targetMtx);
        impl_->target.reset();
    }

    EmitLogMasked(opt_.log, GetGlobalLogMask(), opt_.logMask, LogMask::Info,
        std::string("[wss-bridge] target cleared tid=") + Tid());
}

void WssLocalBridge::Start()
{
    if (!impl_) return;

    bool expected = false;
    if (!impl_->started.compare_exchange_strong(expected, true))
    {
        EmitLogMasked(opt_.log, GetGlobalLogMask(), opt_.logMask, LogMask::Info,
            std::string("[wss-bridge] Start skipped (already started) tid=") + Tid());
        return;
    }

    impl_->stopped.store(false);

    impl_->ioc.restart();

    EmitLogMasked(opt_.log, GetGlobalLogMask(), opt_.logMask, LogMask::Info,
        std::string("[wss-bridge] Start ENTER tid=") + Tid() +
        " listen=" + opt_.listenIp + ":" + std::to_string(opt_.listenPort) +
        " mode=" + std::string(opt_.mode == Mode::Udp ? "udp" : "tcp"));

    if (!impl_->work.has_value())
        impl_->work.emplace(basio::make_work_guard(impl_->ioc));

    impl_->worker = std::thread([this]
    {
        EmitLogMasked(opt_.log, GetGlobalLogMask(), opt_.logMask, LogMask::Info,
            std::string("[wss-bridge] io_context.run BEGIN tid=") + Tid());

        try
        {
            impl_->ioc.run();
        }
        catch (const std::exception& e)
        {
            EmitLogMasked(opt_.log, GetGlobalLogMask(), opt_.logMask, LogMask::Error,
                std::string("[wss-bridge] ioc.run exception tid=") + Tid() + " what=" + e.what());
            DrainOpenSslErrors(opt_.log, GetGlobalLogMask(), opt_.logMask, "ioc.run exception");
        }

        EmitLogMasked(opt_.log, GetGlobalLogMask(), opt_.logMask, LogMask::Info,
            std::string("[wss-bridge] io_context.run END tid=") + Tid());
    });

    auto ov = ToOptView(opt_);
    auto gm = GetGlobalLogMask();

    if (opt_.mode == Mode::Udp)
    {
        impl_->udp = std::make_unique<UdpWssBridge>(
            ov, gm, impl_->ioc, impl_->stopped, impl_->targetMtx, impl_->target, impl_->activeSessions);

        impl_->udp->Start();
    }
    else
    {
        impl_->tcp = std::make_unique<TcpWssBridge>(
            ov, gm, impl_->ioc, impl_->stopped, impl_->targetMtx, impl_->target, impl_->activeSessions);

        impl_->tcp->Start();
    }

    EmitLogMasked(opt_.log, gm, opt_.logMask, LogMask::Info,
        std::string("[wss-bridge] Start OK tid=") + Tid());
}

void WssLocalBridge::Stop()
{
    if (!impl_) return;

    const bool wasStopped = impl_->stopped.exchange(true);
    if (wasStopped)
        return;

    EmitLogMasked(opt_.log, GetGlobalLogMask(), opt_.logMask, LogMask::Info,
        std::string("[wss-bridge] Stop ENTER tid=") + Tid() +
        " activeSessions=" + std::to_string(impl_->activeSessions.load()));

    if (impl_->tcp)
        impl_->tcp->Stop();

    if (impl_->udp)
        impl_->udp->Stop();

    impl_->tcp.reset();
    impl_->udp.reset();

    if (impl_->work.has_value())
        impl_->work.reset();

    impl_->ioc.stop();

    if (impl_->worker.joinable())
        impl_->worker.join();

    impl_->started.store(false);

    EmitLogMasked(opt_.log, GetGlobalLogMask(), opt_.logMask, LogMask::Info,
        std::string("[wss-bridge] Stop OK tid=") + Tid() +
        " activeSessions=" + std::to_string(impl_->activeSessions.load()));
}