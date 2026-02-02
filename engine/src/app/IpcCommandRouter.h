#pragma once

#include "src/ipc/IpcServer.h"
#include "src/session/SessionController.h"
#include "src/app/SessionOrchestrator.h"

#include <windows.h>

class IpcCommandRouter
{
public:
    IpcCommandRouter(datagate::ipc::IpcServer& ipc,
                     datagate::session::SessionController& session,
                     SessionOrchestrator& orchestrator,
                     HANDLE stopEvent);

    void Install();

private:
    datagate::ipc::IpcServer& ipc_;
    datagate::session::SessionController& session_;
    SessionOrchestrator& orchestrator_;
    HANDLE stopEvent_;
};
