#pragma once

#include <windows.h>

class EngineLifetime;
class SessionOrchestrator;

namespace datagate::app
{
    void InstallEngineShutdownHandler(SessionOrchestrator& orchestrator, EngineLifetime& lifetime);
    void UninstallEngineShutdownHandler();
}
