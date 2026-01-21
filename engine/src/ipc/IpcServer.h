#pragma once

#include "IpcProtocol.h"

#include <windows.h>
#include <atomic>
#include <functional>
#include <string>
#include <thread>

namespace datagate::ipc
{
    class IpcServer
    {
    public:
        using CommandHandler = std::function<void(const Command&)>;

        explicit IpcServer(std::string sessionId);
        ~IpcServer();

        IpcServer(const IpcServer&) = delete;
        IpcServer& operator=(const IpcServer&) = delete;

        bool Start();
        void Stop();

        void SetCommandHandler(CommandHandler handler);

        void SendEvent(EventType type, const std::string& payloadJson = "{}");

        void ReplyOk(const std::string& id, const std::string& payloadJson = "{}");
        void ReplyError(const std::string& id, const std::string& code, const std::string& message);

        bool HasAnyClient() const;
        uint64_t LastClientSeenTickMs() const;

    private:
        void ControlAcceptLoop();
        void EventsAcceptLoop();

        void ReadControlLines(HANDLE hPipe);
        void WriteControlLine(const std::string& line);
        void WriteEventsLine(const std::string& line);

        static bool TryParseCommandLine(const std::string& line, Command& cmd);

        static HANDLE CreatePipeServer(const std::string& fullName, DWORD openMode, DWORD pipeMode);
        std::atomic<uint64_t> _lastClientSeenMs{0};

    private:
        std::string _sessionId;
        PipeNames _pipes;

        std::atomic<bool> _running{false};

        std::thread _controlThread;
        std::thread _eventsThread;

        std::atomic<HANDLE> _controlClient{INVALID_HANDLE_VALUE};
        std::atomic<HANDLE> _eventsClient{INVALID_HANDLE_VALUE};

        CommandHandler _handler;
    };
}
