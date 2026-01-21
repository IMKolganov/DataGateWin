#pragma once

#include <string>

namespace datagate::session
{
    enum class SessionPhase
    {
        Idle = 0,
        Starting,
        Connecting,
        Connected,
        Stopping,
        Stopped,
        Error
    };

    struct SessionState
    {
        SessionPhase phase = SessionPhase::Idle;

        // Optional: last error info for UI/logs
        std::string lastErrorCode;
        std::string lastErrorMessage;

        bool IsRunning() const
        {
            return phase == SessionPhase::Starting
                || phase == SessionPhase::Connecting
                || phase == SessionPhase::Connected
                || phase == SessionPhase::Stopping;
        }
    };

    inline const char* ToString(SessionPhase p)
    {
        switch (p)
        {
            case SessionPhase::Idle:       return "idle";
            case SessionPhase::Starting:   return "starting";
            case SessionPhase::Connecting: return "connecting";
            case SessionPhase::Connected:  return "connected";
            case SessionPhase::Stopping:   return "stopping";
            case SessionPhase::Stopped:    return "stopped";
            case SessionPhase::Error:      return "error";
            default:                       return "unknown";
        }
    }
}
