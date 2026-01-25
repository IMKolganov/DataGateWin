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
        std::cerr << "[state] " << datagate::session::ToString(st.phase) << std::endl;

        ipc_.SendEvent(datagate::ipc::EventType::StateChanged, MakeStatePayload(st));

        // Optionally: signal lifecycle for "connecting/connected/idle"
        // Keep it conservative to avoid event spam.
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

        stateCv_.notify_all();
    };

    session_.OnLog = [&](const std::string& line)
    {
        std::cerr << line << std::endl;
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

    startThread_ = std::thread([this, opt = std::move(opt)]() mutable
    {
        std::string err;
        if (!shuttingDown_.load())
            session_.Start(opt, err);

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
    ipc_.SendEvent(
        datagate::ipc::EventType::SessionLifecycle,
        MakeLifecyclePayload("stopping", "user_request", true)
    );

    session_.Stop();
    JoinStartThreadIfNeeded();

    // If session_.Stop() doesn't emit Disconnected in some edge cases,
    // we still want waiters to re-check current state.
    stateCv_.notify_all();
}

void SessionOrchestrator::ShutdownAsync(HANDLE stopEvent)
{
    shuttingDown_.store(true);

    std::thread([this, stopEvent]()
    {
        ipc_.SendEvent(
            datagate::ipc::EventType::SessionLifecycle,
            MakeLifecyclePayload("stopping", "engine_shutdown", true)
        );

        StopSync();
        if (stopEvent)
            SetEvent(stopEvent);
    }).detach();
}

bool SessionOrchestrator::IsRunning() const
{
    return session_.GetState().IsRunning();
}

bool SessionOrchestrator::WaitForIdle(uint32_t timeoutMs)
{
    // Fast path
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
