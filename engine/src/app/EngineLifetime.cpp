#include "EngineLifetime.h"

EngineLifetime EngineLifetime::CreateForSession(const std::string& sessionId, int& exitCode)
{
    exitCode = 0;

    EngineLifetime lt;

    std::string mutexName = "Global\\datagate.engine." + sessionId + ".mutex";
    lt.hMutex_ = CreateMutexA(nullptr, TRUE, mutexName.c_str());
    if (!lt.hMutex_)
    {
        exitCode = 4;
        return lt;
    }

    if (GetLastError() == ERROR_ALREADY_EXISTS)
    {
        lt.alreadyRunning_ = true;
        exitCode = 0;
        return lt;
    }

    lt.hStop_ = CreateEventA(nullptr, TRUE, FALSE, nullptr);
    if (!lt.hStop_)
    {
        exitCode = 3;
        return lt;
    }

    return lt;
}

void EngineLifetime::SignalStop() const
{
    if (hStop_)
        SetEvent(hStop_);
}

EngineLifetime::EngineLifetime(EngineLifetime&& other) noexcept
{
    hMutex_ = other.hMutex_;
    hStop_ = other.hStop_;
    alreadyRunning_ = other.alreadyRunning_;

    other.hMutex_ = nullptr;
    other.hStop_ = nullptr;
    other.alreadyRunning_ = false;
}

EngineLifetime& EngineLifetime::operator=(EngineLifetime&& other) noexcept
{
    if (this == &other)
        return *this;

    Reset();

    hMutex_ = other.hMutex_;
    hStop_ = other.hStop_;
    alreadyRunning_ = other.alreadyRunning_;

    other.hMutex_ = nullptr;
    other.hStop_ = nullptr;
    other.alreadyRunning_ = false;

    return *this;
}

EngineLifetime::~EngineLifetime()
{
    Reset();
}

void EngineLifetime::Reset()
{
    if (hStop_)
    {
        CloseHandle(hStop_);
        hStop_ = nullptr;
    }

    if (hMutex_)
    {
        ReleaseMutex(hMutex_);
        CloseHandle(hMutex_);
        hMutex_ = nullptr;
    }

    alreadyRunning_ = false;
}
