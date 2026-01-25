#pragma once

#include "src/ipc/IpcServer.h"
#include "src/session/SessionController.h"
#include "src/session/SessionState.h"

#include <atomic>
#include <condition_variable>
#include <mutex>
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

    // Wait until session becomes Idle (or until timeout). Used for "normal disconnect" ack.
    bool WaitForIdle(uint32_t timeoutMs);

private:
    void JoinStartThreadIfNeeded();

private:
    datagate::session::SessionController& session_;
    datagate::ipc::IpcServer& ipc_;

    std::atomic_bool shuttingDown_{ false };
    std::atomic_bool startInProgress_{ false };
    std::thread startThread_;

    std::mutex stateMx_;
    std::condition_variable stateCv_;
};