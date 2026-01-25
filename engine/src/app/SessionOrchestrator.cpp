#include "SessionOrchestrator.h"

#include "src/ipc/IpcProtocol.h"
#include "src/session/SessionState.h"

#include <windows.h>

#include <chrono>
#include <iostream>
#include <sstream>
#include <string>
#include <utility>

static std::string MakeStatePayload(const datagate::session::SessionState& st)
{
    std::ostringstream oss;
    oss << "{\"state\":\"" << datagate::session::ToString(st.phase) << "\"";
    if (!st.lastErrorCode.empty() || !st.lastErrorMessage.empty())
    {
        oss << ",\"error\":{\"code\":\"" << datagate::ipc::JsonEscape(st.lastErrorCode)
            << "\",\"message\":\"" << datagate::ipc::JsonEscape(st.lastErrorMessage) << "\"}";
    }
    oss << "}";
    return oss.str();
}

static std::string MakeLifecyclePayload(const char* phase, const char* reason, bool success)
{
    std::ostringstream oss;
    oss << "{"
        << "\"phase\":\"" << datagate::ipc::JsonEscape(phase) << "\","
        << "\"reason\":\"" << datagate::ipc::JsonEscape(reason) << "\","
        << "\"success\":" << (success ? "true" : "false")
        << "}";
    return oss.str();
}

static std::string MakeLifecyclePayloadWithDelayMs(const char* phase, const char* reason, bool success, int delayMs)
{
    std::ostringstream oss;
    oss << "{"
        << "\"phase\":\"" << datagate::ipc::JsonEscape(phase) << "\","
        << "\"reason\":\"" << datagate::ipc::JsonEscape(reason) << "\","
        << "\"success\":" << (success ? "true" : "false") << ","
        << "\"delayMs\":" << delayMs
        << "}";
    return oss.str();
}

static bool TryParseRestartDelayMs(const std::string& line, int& outDelayMs)
{
    // Example: "Client terminated, restarting in 5000 ms..."
    const std::string key = "Client terminated, restarting in ";
    auto p = line.find(key);
    if (p == std::string::npos)
        return false;

    p += key.size();
    auto e = line.find(" ms", p);
    if (e == std::string::npos || e <= p)
        return false;

    try
    {
        outDelayMs = std::stoi(line.substr(p, e - p));
        return outDelayMs >= 0;
    }
    catch (...)
    {
        return false;
    }
}

SessionOrchestrator::SessionOrchestrator(datagate::session::SessionController& session,
                                         datagate::ipc::IpcServer& ipc)
    : session_(session)
    , ipc_(ipc)
{
}

void SessionOrchestrator::WireCallbacks()
{
    session_.OnStateChanged = [&](const datagate::session::SessionState& st)
    {
        // Log transition with prev->new (best-effort)
        {
            std::lock_guard<std::mutex> lk(stateMx_);
            if (lastPhase_.has_value())
            {
                std::cerr << "[state] " << datagate::session::ToString(*lastPhase_)
                          << " -> " << datagate::session::ToString(st.phase)
                          << std::endl;
            }
            else
            {
                std::cerr << "[state] " << datagate::session::ToString(st.phase) << std::endl;
            }
            lastPhase_ = st.phase;
        }

        ipc_.SendEvent(datagate::ipc::EventType::StateChanged, MakeStatePayload(st));

        if (st.phase == datagate::session::SessionPhase::Connecting)
        {
            ipc_.SendEvent(
                datagate::ipc::EventType::SessionLifecycle,
                MakeLifecyclePayload("connecting", "engine", true)
            );
        }
        else if (st.phase == datagate::session::SessionPhase::Idle)
        {
            ipc_.SendEvent(
                datagate::ipc::EventType::SessionLifecycle,
                MakeLifecyclePayload("idle", "engine", true)
            );
        }
        else if (st.phase == datagate::session::SessionPhase::Stopping)
        {
            ipc_.SendEvent(
                datagate::ipc::EventType::SessionLifecycle,
                MakeLifecyclePayload("stopping", "engine", true)
            );
        }

        stateCv_.notify_all();
    };

    session_.OnLog = [&](const std::string& line)
    {
        std::cerr << line << std::endl;

        // Detect auto-restart delay from OpenVPN core log
        int delayMs = 0;
        if (TryParseRestartDelayMs(line, delayMs))
        {
            ipc_.SendEvent(
                datagate::ipc::EventType::SessionLifecycle,
                MakeLifecyclePayloadWithDelayMs("auto_restart_scheduled", "openvpn_core", true, delayMs)
            );
        }

        // Detect transport-related lines
        if (line.find("TCP recv error:") != std::string::npos ||
            line.find("Transport Error:") != std::string::npos ||
            line.find("NETWORK_RECV_ERROR") != std::string::npos)
        {
            ipc_.SendEvent(
                datagate::ipc::EventType::SessionLifecycle,
                MakeLifecyclePayload("transport_error", "network_recv_error", false)
            );
        }

        ipc_.SendEvent(
            datagate::ipc::EventType::Log,
            std::string("{\"line\":\"") + datagate::ipc::JsonEscape(line) + "\"}"
        );
    };

    session_.OnError = [&](const std::string& code, const std::string& message, bool fatal)
    {
        std::ostringstream oss;
        oss << "{\"code\":\"" << datagate::ipc::JsonEscape(code)
            << "\",\"message\":\"" << datagate::ipc::JsonEscape(message)
            << "\",\"fatal\":" << (fatal ? "true" : "false") << "}";
        ipc_.SendEvent(datagate::ipc::EventType::Error, oss.str());

        ipc_.SendEvent(
            datagate::ipc::EventType::SessionLifecycle,
            MakeLifecyclePayload("error", code.c_str(), !fatal)
        );

        stateCv_.notify_all();
    };

    session_.OnConnected = [&](const datagate::session::ConnectedInfo& ci)
    {
        std::ostringstream oss;
        oss << "{\"ifIndex\":" << ci.vpnIfIndex
            << ",\"vpnIpv4\":\"" << datagate::ipc::JsonEscape(ci.vpnIpv4) << "\"}";
        ipc_.SendEvent(datagate::ipc::EventType::Connected, oss.str());

        ipc_.SendEvent(
            datagate::ipc::EventType::SessionLifecycle,
            MakeLifecyclePayload("connected", "vpn", true)
        );
    };

    session_.OnDisconnected = [&](const std::string& reason)
    {
        // Extra context: current state
        const auto st = session_.GetState();
        std::cerr << "[orchestrator] OnDisconnected reason=" << reason
                  << " phase=" << datagate::session::ToString(st.phase)
                  << std::endl;

        ipc_.SendEvent(
            datagate::ipc::EventType::Disconnected,
            std::string("{\"reason\":\"") + datagate::ipc::JsonEscape(reason) + "\"}"
        );

        ipc_.SendEvent(
            datagate::ipc::EventType::SessionLifecycle,
            MakeLifecyclePayload("disconnected", reason.c_str(), true)
        );

        stateCv_.notify_all();
    };
}

bool SessionOrchestrator::StartAsync(datagate::session::StartOptions opt)
{
    bool expected = false;
    if (!startInProgress_.compare_exchange_strong(expected, true))
        return false;

    JoinStartThreadIfNeeded();

    std::cerr << "[orchestrator] StartAsync accepted" << std::endl;

    startThread_ = std::thread([this, opt = std::move(opt)]() mutable
    {
        std::cerr << "[orchestrator] StartAsync thread BEGIN" << std::endl;

        std::string err;
        bool ok = false;

        if (!shuttingDown_.load())
            ok = session_.Start(opt, err);

        std::cerr << "[orchestrator] StartAsync thread END ok=" << (ok ? "true" : "false")
                  << " err=" << err << std::endl;

        if (!ok && !err.empty())
        {
            ipc_.SendEvent(
                datagate::ipc::EventType::SessionLifecycle,
                MakeLifecyclePayload("start_failed", "start_error", false)
            );
        }

        startInProgress_.store(false);
        stateCv_.notify_all();
    });

    return true;
}

void SessionOrchestrator::StopAsync()
{
    std::thread([this]()
    {
        StopSync();
    }).detach();
}

void SessionOrchestrator::StopSync()
{
    std::cerr << "[orchestrator] StopSync ENTER" << std::endl;

    ipc_.SendEvent(
        datagate::ipc::EventType::SessionLifecycle,
        MakeLifecyclePayload("stopping", "user_request", true)
    );

    session_.Stop();
    JoinStartThreadIfNeeded();

    std::cerr << "[orchestrator] StopSync EXIT state=" << datagate::session::ToString(session_.GetState().phase) << std::endl;

    stateCv_.notify_all();
}

void SessionOrchestrator::ShutdownAsync(HANDLE stopEvent)
{
    shuttingDown_.store(true);

    std::thread([this, stopEvent]()
    {
        std::cerr << "[orchestrator] ShutdownAsync ENTER" << std::endl;

        ipc_.SendEvent(
            datagate::ipc::EventType::SessionLifecycle,
            MakeLifecyclePayload("stopping", "engine_shutdown", true)
        );

        StopSync();
        if (stopEvent)
            SetEvent(stopEvent);

        std::cerr << "[orchestrator] ShutdownAsync EXIT" << std::endl;
    }).detach();
}

bool SessionOrchestrator::IsRunning() const
{
    return session_.GetState().IsRunning();
}

bool SessionOrchestrator::WaitForIdle(uint32_t timeoutMs)
{
    {
        const auto st = session_.GetState();
        if (st.phase == datagate::session::SessionPhase::Idle)
            return true;
    }

    std::unique_lock<std::mutex> lk(stateMx_);
    return stateCv_.wait_for(lk, std::chrono::milliseconds(timeoutMs), [this]()
    {
        const auto st = session_.GetState();
        return st.phase == datagate::session::SessionPhase::Idle;
    });
}

void SessionOrchestrator::JoinStartThreadIfNeeded()
{
    if (startThread_.joinable())
        startThread_.join();
}
