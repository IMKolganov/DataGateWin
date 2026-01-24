#pragma once

#include "src/ipc/IpcServer.h"
#include "src/session/SessionController.h"

#include <atomic>
#include <thread>

class SessionOrchestrator
{
public:
    SessionOrchestrator(datagate::session::SessionController& session,
                        datagate::ipc::IpcServer& ipc);

    void WireCallbacks();

    bool StartAsync(datagate::session::StartOptions opt);

    void StopAsync();
    void StopSync();

    void ShutdownAsync(HANDLE stopEvent);

    bool IsRunning() const;

private:
    void JoinStartThreadIfNeeded();

private:
    datagate::session::SessionController& session_;
    datagate::ipc::IpcServer& ipc_;

    std::atomic_bool shuttingDown_{ false };
    std::atomic_bool startInProgress_{ false };
    std::thread startThread_;
};
