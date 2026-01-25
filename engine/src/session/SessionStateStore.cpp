#include "SessionStateStore.h"

namespace datagate::session
{
    void SessionStateStore::SetCallbacks(
        StateChangedCallback onStateChanged,
        LogCallback onLog,
        ErrorCallback onError,
        ConnectedCallback onConnected,
        DisconnectedCallback onDisconnected)
    {
        std::lock_guard<std::mutex> lock(_mtx);
        _onStateChanged = std::move(onStateChanged);
        _onLog = std::move(onLog);
        _onError = std::move(onError);
        _onConnected = std::move(onConnected);
        _onDisconnected = std::move(onDisconnected);
    }

    SessionState SessionStateStore::GetState() const
    {
        std::lock_guard<std::mutex> lock(_mtx);
        return _state;
    }

    bool SessionStateStore::TryEnterStarting(std::string& outError)
    {
        std::lock_guard<std::mutex> lock(_mtx);

        if (_state.IsRunning())
        {
            outError = "Session already running";
            return false;
        }

        _state.lastErrorCode.clear();
        _state.lastErrorMessage.clear();
        _state.phase = SessionPhase::Starting;
        _disconnectEmitted = false;

        return true;
    }

    void SessionStateStore::SetPhase(SessionPhase phase)
    {
        std::lock_guard<std::mutex> lock(_mtx);
        _state.phase = phase;
    }

    void SessionStateStore::SetError(const std::string& code, const std::string& message)
    {
        std::lock_guard<std::mutex> lock(_mtx);
        _state.lastErrorCode = code;
        _state.lastErrorMessage = message;
        _state.phase = SessionPhase::Error;
    }

    void SessionStateStore::ClearError()
    {
        std::lock_guard<std::mutex> lock(_mtx);
        _state.lastErrorCode.clear();
        _state.lastErrorMessage.clear();
    }

    void SessionStateStore::ResetDisconnectDedup()
    {
        std::lock_guard<std::mutex> lock(_mtx);
        _disconnectEmitted = false;
    }

    bool SessionStateStore::MarkDisconnectedOnce()
    {
        std::lock_guard<std::mutex> lock(_mtx);
        if (_disconnectEmitted)
            return false;

        _disconnectEmitted = true;
        return true;
    }

    bool SessionStateStore::IsRunning() const
    {
        std::lock_guard<std::mutex> lock(_mtx);
        return _state.IsRunning();
    }

    void SessionStateStore::PublishStateSnapshot()
    {
        StateChangedCallback cb;
        SessionState snapshot;

        {
            std::lock_guard<std::mutex> lock(_mtx);
            cb = _onStateChanged;
            snapshot = _state;
        }

        if (cb)
            cb(snapshot);
    }

    void SessionStateStore::PublishError(const std::string& code, const std::string& message, bool fatal)
    {
        ErrorCallback cb;
        {
            std::lock_guard<std::mutex> lock(_mtx);
            cb = _onError;
        }

        if (cb)
            cb(code, message, fatal);
    }

    void SessionStateStore::PublishLogLine(const std::string& line)
    {
        LogCallback cb;
        {
            std::lock_guard<std::mutex> lock(_mtx);
            cb = _onLog;
        }

        if (cb)
            cb(line);
    }

    void SessionStateStore::PublishConnected(const ConnectedInfo& ci)
    {
        ConnectedCallback cb;
        {
            std::lock_guard<std::mutex> lock(_mtx);
            cb = _onConnected;
        }

        if (cb)
            cb(ci);
    }

    void SessionStateStore::PublishDisconnected(const std::string& reason)
    {
        DisconnectedCallback cb;
        {
            std::lock_guard<std::mutex> lock(_mtx);
            cb = _onDisconnected;
        }

        if (cb)
            cb(reason);
    }

    void SessionStateStore::SetLastStartOptions(const StartOptions& opt)
    {
        std::lock_guard<std::mutex> lock(_mtx);
        _lastStart = opt;
    }

    StartOptions SessionStateStore::GetLastStartOptions() const
    {
        std::lock_guard<std::mutex> lock(_mtx);
        return _lastStart;
    }
}