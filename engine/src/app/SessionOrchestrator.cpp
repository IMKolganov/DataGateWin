#include "SessionOrchestrator.h"

#include "src/ipc/IpcProtocol.h"
#include "src/session/SessionState.h"

#include <windows.h>

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
    };

    session_.OnConnected = [&](const datagate::session::ConnectedInfo& ci)
    {
        std::ostringstream oss;
        oss << "{\"ifIndex\":" << ci.vpnIfIndex
            << ",\"vpnIpv4\":\"" << datagate::ipc::JsonEscape(ci.vpnIpv4) << "\"}";
        ipc_.SendEvent(datagate::ipc::EventType::Connected, oss.str());
    };

    session_.OnDisconnected = [&](const std::string& reason)
    {
        ipc_.SendEvent(
            datagate::ipc::EventType::Disconnected,
            std::string("{\"reason\":\"") + datagate::ipc::JsonEscape(reason) + "\"}"
        );
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
    session_.Stop();
    JoinStartThreadIfNeeded();
}

void SessionOrchestrator::ShutdownAsync(HANDLE stopEvent)
{
    shuttingDown_.store(true);

    std::thread([this, stopEvent]()
    {
        StopSync();
        if (stopEvent)
            SetEvent(stopEvent);
    }).detach();
}

bool SessionOrchestrator::IsRunning() const
{
    return session_.GetState().IsRunning();
}

void SessionOrchestrator::JoinStartThreadIfNeeded()
{
    if (startThread_.joinable())
        startThread_.join();
}
