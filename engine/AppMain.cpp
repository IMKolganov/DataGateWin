// AppMain.cpp
#include "AppMain.h"

#include "src/app/ArgParser.h"
#include "src/app/CrashReporter.h"
#include "src/app/EngineLifetime.h"
#include "src/app/IpcCommandRouter.h"
#include "src/app/IdleShutdownPolicy.h"
#include "src/app/SessionOrchestrator.h"

#include "src/ipc/IpcServer.h"
#include "src/session/SessionController.h"

#include <windows.h>

#include <cstdint>
#include <iostream>
#include <string>

int AppMain::Run(int argc, char** argv)
{
    CrashReporter::Install();

    const std::string sessionId = ArgParser::GetValue(argc, argv, "--session-id");
    if (sessionId.empty())
        return 2;

    int lifetimeExitCode = 0;
    auto lifetime = EngineLifetime::CreateForSession(sessionId, lifetimeExitCode);
    if (lifetimeExitCode != 0)
        return lifetimeExitCode;

    if (lifetime.IsAlreadyRunning())
    {
        std::cerr << "[engine] already running for sessionId=" << sessionId << std::endl;
        return 0;
    }

    datagate::ipc::IpcServer ipc(sessionId);
    datagate::session::SessionController session;

    SessionOrchestrator orchestrator(session, ipc);
    orchestrator.WireCallbacks();

    IpcCommandRouter router(ipc, session, orchestrator, lifetime.StopEvent());
    router.Install();

    ipc.Start();
    ipc.SendEvent(datagate::ipc::EventType::EngineReady, "{}");

    IdleShutdownPolicy idle(5ull * 60ull * 1000ull);
    const uint64_t startMs = GetTickCount64();

    for (;;)
    {
        if (WaitForSingleObject(lifetime.StopEvent(), 500) == WAIT_OBJECT_0)
            break;

        if (orchestrator.IsRunning())
        {
            idle.ResetPrintTimer();
            continue;
        }

        if (ipc.HasAnyClient())
        {
            idle.ResetPrintTimer();
            continue;
        }

        const uint64_t nowMs = GetTickCount64();
        const uint64_t lastSeenMs = ipc.LastClientSeenTickMs();

        if (idle.ShouldExit(nowMs, lastSeenMs, startMs))
            break;

        idle.MaybePrintCountdown(std::cerr, nowMs, lastSeenMs, startMs);
    }

    orchestrator.StopSync();
    ipc.Stop();

    return 0;
}