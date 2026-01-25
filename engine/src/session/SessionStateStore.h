#pragma once

#include "SessionState.h"
#include "SessionController.h"

#include <mutex>
#include <string>

namespace datagate::session
{
    class SessionStateStore
    {
    public:
        void SetCallbacks(
            StateChangedCallback onStateChanged,
            LogCallback onLog,
            ErrorCallback onError,
            ConnectedCallback onConnected,
            DisconnectedCallback onDisconnected);

        // Snapshot
        SessionState GetState() const;

        // State transitions / bookkeeping
        bool TryEnterStarting(std::string& outError);
        void SetPhase(SessionPhase phase);
        void SetError(const std::string& code, const std::string& message);
        void ClearError();
        void ResetDisconnectDedup();

        bool MarkDisconnectedOnce();
        bool IsRunning() const;

        // Callback publishing helpers (thread-safe)
        void PublishStateSnapshot();
        void PublishError(const std::string& code, const std::string& message, bool fatal);
        void PublishLogLine(const std::string& line);
        void PublishConnected(const ConnectedInfo& ci);
        void PublishDisconnected(const std::string& reason);

        // Used to allow Controller to cache last options if needed
        void SetLastStartOptions(const StartOptions& opt);
        StartOptions GetLastStartOptions() const;

    private:
        mutable std::mutex _mtx;

        SessionState _state{};
        StartOptions _lastStart{};

        bool _disconnectEmitted = false;

        StateChangedCallback _onStateChanged;
        LogCallback _onLog;
        ErrorCallback _onError;
        ConnectedCallback _onConnected;
        DisconnectedCallback _onDisconnected;
    };
}
