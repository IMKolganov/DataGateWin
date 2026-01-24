#pragma once

#include <windows.h>
#include <string>

class EngineLifetime
{
public:
    static EngineLifetime CreateForSession(const std::string& sessionId, int& exitCode);

    bool IsAlreadyRunning() const { return alreadyRunning_; }
    HANDLE StopEvent() const { return hStop_; }

    void SignalStop() const;

    EngineLifetime(const EngineLifetime&) = delete;
    EngineLifetime& operator=(const EngineLifetime&) = delete;

    EngineLifetime(EngineLifetime&& other) noexcept;
    EngineLifetime& operator=(EngineLifetime&& other) noexcept;

    ~EngineLifetime();

private:
    EngineLifetime() = default;

    void Reset();

    HANDLE hMutex_ = nullptr;
    HANDLE hStop_ = nullptr;
    bool alreadyRunning_ = false;
};
