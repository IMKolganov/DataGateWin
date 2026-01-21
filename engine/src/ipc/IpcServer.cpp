#include "IpcServer.h"

#include <chrono>
#include <iostream>

namespace datagate::ipc
{
    static uint64_t NowMs()
    {
        return GetTickCount64();
    }

    static void ClearHandle(std::atomic<HANDLE>& h)
    {
        h.store(INVALID_HANDLE_VALUE);
    }

    IpcServer::IpcServer(std::string sessionId)
        : _sessionId(std::move(sessionId)),
          _pipes(MakePipeNames(_sessionId))
    {
        _lastClientSeenMs.store(NowMs());
    }

    IpcServer::~IpcServer()
    {
        Stop();
    }

    void IpcServer::SetCommandHandler(CommandHandler handler)
    {
        _handler = std::move(handler);
    }

    bool IpcServer::HasAnyClient() const
    {
        return _controlClient.load() != INVALID_HANDLE_VALUE
            || _eventsClient.load()  != INVALID_HANDLE_VALUE;
    }

    uint64_t IpcServer::LastClientSeenTickMs() const
    {
        return _lastClientSeenMs.load();
    }

    bool IpcServer::Start()
    {
        if (_running.exchange(true))
            return true;

        _controlThread = std::thread([this] { ControlAcceptLoop(); });
        _eventsThread  = std::thread([this] { EventsAcceptLoop(); });

        return true;
    }

    void IpcServer::Stop()
    {
        if (!_running.exchange(false))
            return;

        ClearHandle(_controlClient);
        ClearHandle(_eventsClient);

        if (_controlThread.joinable()) _controlThread.join();
        if (_eventsThread.joinable())  _eventsThread.join();
    }

    void IpcServer::SendEvent(EventType type, const std::string& payloadJson)
    {
        WriteEventsLine(MakeEventLine(type, payloadJson));
    }

    void IpcServer::ReplyOk(const std::string& id, const std::string& payloadJson)
    {
        WriteControlLine(MakeOkResponseLine(id, payloadJson));
    }

    void IpcServer::ReplyError(const std::string& id, const std::string& code, const std::string& message)
    {
        WriteControlLine(MakeErrorResponseLine(id, code, message));
    }

    HANDLE IpcServer::CreatePipeServer(const std::string& fullName, DWORD openMode, DWORD pipeMode)
    {
        return CreateNamedPipeA(
            fullName.c_str(),
            openMode,
            pipeMode,
            1,
            64 * 1024,
            64 * 1024,
            0,
            nullptr
        );
    }

    void IpcServer::ControlAcceptLoop()
    {
        while (_running.load())
        {
            HANDLE hPipe = CreatePipeServer(
                _pipes.controlPipe,
                PIPE_ACCESS_DUPLEX,
                PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT
            );

            if (hPipe == INVALID_HANDLE_VALUE)
            {
                std::this_thread::sleep_for(std::chrono::milliseconds(200));
                continue;
            }

            BOOL ok = ConnectNamedPipe(hPipe, nullptr) ? TRUE : (GetLastError() == ERROR_PIPE_CONNECTED);
            if (!ok)
            {
                CloseHandle(hPipe);
                continue;
            }

            _controlClient.store(hPipe);
            _lastClientSeenMs.store(NowMs());

            ReadControlLines(hPipe);

            _lastClientSeenMs.store(NowMs());
            ClearHandle(_controlClient);

            DisconnectNamedPipe(hPipe);
            CloseHandle(hPipe);
        }
    }

    void IpcServer::EventsAcceptLoop()
    {
        while (_running.load())
        {
            HANDLE hPipe = CreatePipeServer(
                _pipes.eventsPipe,
                PIPE_ACCESS_OUTBOUND,
                PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT
            );

            if (hPipe == INVALID_HANDLE_VALUE)
            {
                std::this_thread::sleep_for(std::chrono::milliseconds(200));
                continue;
            }

            BOOL ok = ConnectNamedPipe(hPipe, nullptr) ? TRUE : (GetLastError() == ERROR_PIPE_CONNECTED);
            if (!ok)
            {
                CloseHandle(hPipe);
                continue;
            }

            _eventsClient.store(hPipe);
            _lastClientSeenMs.store(NowMs());

            WriteEventsLine(MakeEventLine(EventType::EngineReady, "{}"));

            while (_running.load())
            {
                std::this_thread::sleep_for(std::chrono::milliseconds(250));
                if (_eventsClient.load() == INVALID_HANDLE_VALUE)
                    break;
            }

            _lastClientSeenMs.store(NowMs());
            ClearHandle(_eventsClient);

            DisconnectNamedPipe(hPipe);
            CloseHandle(hPipe);
        }
    }

    void IpcServer::ReadControlLines(HANDLE hPipe)
    {
        std::string buffer;
        buffer.reserve(64 * 1024);

        char temp[4096];
        DWORD read = 0;

        while (_running.load())
        {
            BOOL ok = ReadFile(hPipe, temp, sizeof(temp), &read, nullptr);
            if (!ok || read == 0)
                break;

            _lastClientSeenMs.store(NowMs());

            buffer.append(temp, temp + read);

            for (;;)
            {
                const auto pos = buffer.find('\n');
                if (pos == std::string::npos)
                    break;

                std::string line = buffer.substr(0, pos);
                buffer.erase(0, pos + 1);

                Command cmd{};
                if (!TryParseCommandLine(line, cmd))
                {
                    ReplyError("?", "bad_request", "Invalid command line");
                    continue;
                }

                if (_handler)
                    _handler(cmd);
                else
                    ReplyError(cmd.id.empty() ? "?" : cmd.id, "no_handler", "No command handler set");
            }
        }
    }

    void IpcServer::WriteControlLine(const std::string& line)
    {
        HANDLE h = _controlClient.load();
        if (h == INVALID_HANDLE_VALUE)
            return;

        std::string msg = line;
        msg.push_back('\n');

        DWORD written = 0;
        WriteFile(h, msg.data(), (DWORD)msg.size(), &written, nullptr);

        _lastClientSeenMs.store(NowMs());
    }

    void IpcServer::WriteEventsLine(const std::string& line)
    {
        HANDLE h = _eventsClient.load();
        if (h == INVALID_HANDLE_VALUE)
            return;

        std::string msg = line;
        msg.push_back('\n');

        DWORD written = 0;
        WriteFile(h, msg.data(), (DWORD)msg.size(), &written, nullptr);

        _lastClientSeenMs.store(NowMs());
    }

    bool IpcServer::TryParseCommandLine(const std::string& line, Command& cmd)
    {
        auto extractString = [&](const char* field, std::string& value) -> bool
        {
            const std::string key = std::string("\"") + field + "\"";
            auto p = line.find(key);
            if (p == std::string::npos) return false;
            p = line.find(':', p);
            if (p == std::string::npos) return false;
            p = line.find('"', p);
            if (p == std::string::npos) return false;
            auto e = line.find('"', p + 1);
            if (e == std::string::npos) return false;
            value = line.substr(p + 1, e - (p + 1));
            return true;
        };

        std::string id, type;
        if (!extractString("id", id)) return false;
        if (!extractString("type", type)) return false;

        cmd.id = id;
        cmd.type = CommandTypeFromString(type);

        auto p = line.find("\"payload\"");
        if (p == std::string::npos) return false;
        p = line.find(':', p);
        if (p == std::string::npos) return false;

        std::string payload = line.substr(p + 1);
        while (!payload.empty() && payload.front() == ' ') payload.erase(payload.begin());

        cmd.payloadJson = payload;
        return true;
    }
}
