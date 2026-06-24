#include "EngineShutdownHandler.h"

#include "EngineLifetime.h"
#include "SessionOrchestrator.h"

#include <iostream>

namespace
{
    SessionOrchestrator* g_orchestrator = nullptr;
    EngineLifetime* g_lifetime = nullptr;

    BOOL WINAPI ConsoleCtrlHandler(DWORD ctrlType)
    {
        switch (ctrlType)
        {
        case CTRL_CLOSE_EVENT:
        case CTRL_LOGOFF_EVENT:
        case CTRL_SHUTDOWN_EVENT:
            std::cerr << "[engine] console ctrl event=" << ctrlType << ", stopping VPN..." << std::endl;
            if (g_orchestrator)
                g_orchestrator->StopSync();
            if (g_lifetime)
                g_lifetime->SignalStop();
            return TRUE;
        default:
            return FALSE;
        }
    }
}

namespace datagate::app
{
    void InstallEngineShutdownHandler(SessionOrchestrator& orchestrator, EngineLifetime& lifetime)
    {
        g_orchestrator = &orchestrator;
        g_lifetime = &lifetime;

        if (!SetConsoleCtrlHandler(ConsoleCtrlHandler, TRUE))
        {
            std::cerr << "[engine] SetConsoleCtrlHandler failed: " << GetLastError() << std::endl;
        }
    }

    void UninstallEngineShutdownHandler()
    {
        SetConsoleCtrlHandler(ConsoleCtrlHandler, FALSE);
        g_orchestrator = nullptr;
        g_lifetime = nullptr;
    }
}
