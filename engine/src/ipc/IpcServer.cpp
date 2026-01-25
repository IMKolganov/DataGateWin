// IpcServer.cpp
#include "IpcServer.h"

#include <chrono>
#include <cctype>
#include <iostream>

// Windows security for permissive Named Pipe ACL
#include <windows.h>
#include <Aclapi.h>

namespace datagate::ipc
{
    static uint64_t NowMs()
    {
        return GetTickCount64();
    }

    static void SafeClosePipe(HANDLE h)
    {
        if (h == INVALID_HANDLE_VALUE)
            return;

        CancelIoEx(h, nullptr);
        DisconnectNamedPipe(h);
        CloseHandle(h);
    }

    static SECURITY_ATTRIBUTES MakePipeSecurityAttributes()
    {
        SECURITY_ATTRIBUTES sa{};
        sa.nLength = sizeof(sa);
        sa.bInheritHandle = FALSE;

        auto* sd = (SECURITY_DESCRIPTOR*)LocalAlloc(LPTR, SECURITY_DESCRIPTOR_MIN_LENGTH);
        InitializeSecurityDescriptor(sd, SECURITY_DESCRIPTOR_REVISION);
        SetSecurityDescriptorDacl(sd, TRUE, nullptr, FALSE);

        sa.lpSecurityDescriptor = sd;
        return sa;
    }

    static void FreePipeSecurityAttributes(SECURITY_ATTRIBUTES& sa)
    {
        if (sa.lpSecurityDescriptor)
            LocalFree(sa.lpSecurityDescriptor);
        sa.lpSecurityDescriptor = nullptr;
    }

    static void TrimRightCr(std::string& s)
    {
        if (!s.empty() && s.back() == '\r')
            s.pop_back();
    }

    static size_t SkipWs(const std::string& s, size_t i)
    {
        while (i < s.size() && std::isspace((unsigned char)s[i]))
            i++;
        return i;
    }

    static bool TryExtractJsonValueRange(const std::string& s, size_t i, size_t& outStart, size_t& outEndExclusive)
    {
        i = SkipWs(s, i);
        if (i >= s.size())
            return false;

        outStart = i;

        const char c = s[i];

        if (c == '{' || c == '[')
        {
            const char open = c;
            const char close = (c == '{') ? '}' : ']';

            int depth = 0;
            bool inString = false;
            bool escaped = false;

            for (size_t p = i; p < s.size(); p++)
            {
                const char ch = s[p];

                if (inString)
                {
                    if (escaped) { escaped = false; continue; }
                    if (ch == '\\') { escaped = true; continue; }
                    if (ch == '"') { inString = false; continue; }
                    continue;
                }

                if (ch == '"') { inString = true; continue; }

                if (ch == open) { depth++; continue; }

                if (ch == close)
                {
                    depth--;
                    if (depth == 0)
                    {
                        outEndExclusive = p + 1;
                        return true;
                    }
                }
            }

            return false;
        }

        if (c == '"')
        {
            bool escaped = false;
            for (size_t p = i + 1; p < s.size(); p++)
            {
                const char ch = s[p];
                if (escaped) { escaped = false; continue; }
                if (ch == '\\') { escaped = true; continue; }
                if (ch == '"')
                {
                    outEndExclusive = p + 1;
                    return true;
                }
            }
            return false;
        }

        if (s.compare(i, 4, "true") == 0)  { outEndExclusive = i + 4; return true; }
        if (s.compare(i, 5, "false") == 0) { outEndExclusive = i + 5; return true; }
        if (s.compare(i, 4, "null") == 0)  { outEndExclusive = i + 4; return true; }

        size_t p = i;
        while (p < s.size())
        {
            const char ch = s[p];
            if (std::isspace((unsigned char)ch) || ch == ',' || ch == '}' || ch == ']')
                break;
            p++;
        }

        if (p == i)
            return false;

        outEndExclusive = p;
        return true;
    }

    IpcServer::IpcServer(std::string sessionId)
        : _sessionId(std::move(sessionId)),
          _pipes(MakePipeNames(_sessionId))
    {
        std::cerr << "[ipc] ctor sessionId=" << _sessionId << std::endl;
    }

    IpcServer::~IpcServer()
    {
        std::cerr << "[ipc] dtor sessionId=" << _sessionId << std::endl;
        Stop();
    }

    void IpcServer::SetCommandHandler(CommandHandler handler)
    {
        _handler = std::move(handler);
        std::cerr << "[ipc] command handler set" << std::endl;
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

        std::cerr << "[ipc] Start() sessionId=" << _sessionId << std::endl;

        _controlThread = std::thread([this] {
            std::cerr << "[ipc][control] accept thread started" << std::endl;
            ControlAcceptLoop();
            std::cerr << "[ipc][control] accept thread stopped" << std::endl;
        });

        _eventsThread = std::thread([this] {
            std::cerr << "[ipc][events] accept thread started" << std::endl;
            EventsAcceptLoop();
            std::cerr << "[ipc][events] accept thread stopped" << std::endl;
        });

        return true;
    }

    void IpcServer::Stop()
    {
        if (!_running.exchange(false))
            return;

        std::cerr << "[ipc] Stop()" << std::endl;

        StopControlWriter();

        HANDLE hc = _controlClient.exchange(INVALID_HANDLE_VALUE);
        HANDLE he = _eventsClient.exchange(INVALID_HANDLE_VALUE);

        SafeClosePipe(hc);
        SafeClosePipe(he);

        if (_controlThread.joinable()) _controlThread.join();
        if (_eventsThread.joinable())  _eventsThread.join();
    }

    void IpcServer::SendEvent(EventType type, const std::string& payloadJson)
    {
        WriteEventsLine(MakeEventLine(type, payloadJson));
    }

    void IpcServer::ReplyOk(const std::string& id, const std::string& payloadJson)
    {
        EnqueueControlLine(MakeOkResponseLine(id, payloadJson));
    }

    void IpcServer::ReplyError(const std::string& id, const std::string& code, const std::string& message)
    {
        EnqueueControlLine(MakeErrorResponseLine(id, code, message));
    }

    void IpcServer::StartControlWriter(HANDLE hPipe)
    {
        StopControlWriter();

        {
            std::lock_guard<std::mutex> lk(_controlOutMx);
            _controlOutQueue.clear();
        }

        _controlWriterRunning.store(true);

        _controlWriterThread = std::thread([this, hPipe]()
        {
            while (_running.load() && _controlWriterRunning.load())
            {
                std::string msg;

                {
                    std::unique_lock<std::mutex> lk(_controlOutMx);
                    _controlOutCv.wait(lk, [this]()
                    {
                        return !_running.load()
                            || !_controlWriterRunning.load()
                            || !_controlOutQueue.empty();
                    });

                    if (!_running.load() || !_controlWriterRunning.load())
                        break;

                    msg = std::move(_controlOutQueue.front());
                    _controlOutQueue.pop_front();
                }

                if (hPipe == INVALID_HANDLE_VALUE)
                    continue;

                DWORD written = 0;
                BOOL ok = WriteFile(hPipe, msg.data(), (DWORD)msg.size(), &written, nullptr);
                if (!ok)
                {
                    DWORD err = GetLastError();
                    if (err == ERROR_BROKEN_PIPE || err == ERROR_NO_DATA)
                    {
                        _controlClient.store(INVALID_HANDLE_VALUE);
                        break;
                    }
                }

                _lastClientSeenMs.store(NowMs());
            }
        });
    }

    void IpcServer::StopControlWriter()
    {
        if (!_controlWriterRunning.exchange(false))
            return;

        _controlOutCv.notify_all();

        if (_controlWriterThread.joinable())
            _controlWriterThread.join();

        {
            std::lock_guard<std::mutex> lk(_controlOutMx);
            _controlOutQueue.clear();
        }
    }

    void IpcServer::EnqueueControlLine(const std::string& line)
    {
        HANDLE h = _controlClient.load();
        if (h == INVALID_HANDLE_VALUE)
            return;

        if (!_controlWriterRunning.load())
            return;

        {
            std::lock_guard<std::mutex> lk(_controlOutMx);
            _controlOutQueue.push_back(line + "\n");
        }

        _controlOutCv.notify_one();
    }

    HANDLE IpcServer::CreatePipeServer(const std::string& fullName, DWORD openMode, DWORD pipeMode)
    {
        SECURITY_ATTRIBUTES sa = MakePipeSecurityAttributes();

        HANDLE h = CreateNamedPipeA(
            fullName.c_str(),
            openMode,
            pipeMode,
            1,
            64 * 1024,
            64 * 1024,
            0,
            &sa
        );

        FreePipeSecurityAttributes(sa);
        return h;
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
                Sleep(200);
                continue;
            }

            BOOL ok = ConnectNamedPipe(hPipe, nullptr)
                ? TRUE
                : (GetLastError() == ERROR_PIPE_CONNECTED);

            if (!ok)
            {
                CloseHandle(hPipe);
                continue;
            }

            std::cerr << "[ipc][control] client connected" << std::endl;
            _controlClient.store(hPipe);
            _lastClientSeenMs.store(NowMs());

            StartControlWriter(hPipe);

            ReadControlLines(hPipe);

            std::cerr << "[ipc][control] client disconnected" << std::endl;

            StopControlWriter();
            _controlClient.store(INVALID_HANDLE_VALUE);
            SafeClosePipe(hPipe);
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
                Sleep(200);
                continue;
            }

            BOOL ok = ConnectNamedPipe(hPipe, nullptr)
                ? TRUE
                : (GetLastError() == ERROR_PIPE_CONNECTED);

            if (!ok)
            {
                CloseHandle(hPipe);
                continue;
            }

            std::cerr << "[ipc][events] client connected" << std::endl;
            _eventsClient.store(hPipe);
            _lastClientSeenMs.store(NowMs());

            WriteEventsLine(MakeEventLine(EventType::EngineReady, "{}"));

            while (_running.load())
            {
                if (_eventsClient.load() == INVALID_HANDLE_VALUE)
                    break;

                Sleep(500);
            }

            std::cerr << "[ipc][events] client disconnected" << std::endl;

            _eventsClient.store(INVALID_HANDLE_VALUE);
            SafeClosePipe(hPipe);
        }
    }

    void IpcServer::ReadControlLines(HANDLE hPipe)
    {
        std::string buffer;
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
                auto pos = buffer.find('\n');
                if (pos == std::string::npos)
                    break;

                std::string line = buffer.substr(0, pos);
                std::cerr << "[ipc][control] recv: " << line << std::endl;
                buffer.erase(0, pos + 1);

                TrimRightCr(line);
                if (line.empty())
                    continue;

                Command cmd{};
                if (!TryParseCommandLine(line, cmd))
                {
                    std::cerr << "[ipc][control] parse failed" << std::endl;
                    ReplyError("?", "bad_request", "Invalid command");
                    continue;
                }

                if (_handler)
                    _handler(cmd);
                else
                    ReplyError(cmd.id, "no_handler", "No command handler");
            }
        }
    }

    void IpcServer::WriteEventsLine(const std::string& line)
    {
        HANDLE h = _eventsClient.load();
        if (h == INVALID_HANDLE_VALUE)
            return;

        std::string msg = line + "\n";
        DWORD written = 0;

        if (!WriteFile(h, msg.data(), (DWORD)msg.size(), &written, nullptr))
        {
            DWORD err = GetLastError();
            if (err == ERROR_BROKEN_PIPE || err == ERROR_NO_DATA)
                _eventsClient.store(INVALID_HANDLE_VALUE);
            return;
        }

        _lastClientSeenMs.store(NowMs());
    }

    bool IpcServer::TryParseCommandLine(const std::string& line, Command& cmd)
    {
        auto getStringField = [&](const char* key, std::string& out) -> bool
        {
            std::string k = "\"" + std::string(key) + "\"";
            auto p = line.find(k);
            if (p == std::string::npos) return false;

            p = line.find(':', p + k.size());
            if (p == std::string::npos) return false;

            p = line.find('"', p);
            if (p == std::string::npos) return false;

            auto e = p + 1;
            bool escaped = false;
            for (; e < line.size(); e++)
            {
                char c = line[e];
                if (escaped) { escaped = false; continue; }
                if (c == '\\') { escaped = true; continue; }
                if (c == '"') break;
            }
            if (e >= line.size()) return false;

            out = line.substr(p + 1, e - (p + 1));
            return true;
        };

        std::string type;
        if (!getStringField("id", cmd.id)) return false;
        if (!getStringField("type", type)) return false;

        cmd.type = CommandTypeFromString(type);

        auto p = line.find("\"payload\"");
        if (p == std::string::npos) return false;

        p = line.find(':', p);
        if (p == std::string::npos) return false;

        size_t vStart = 0;
        size_t vEnd = 0;
        if (!TryExtractJsonValueRange(line, p + 1, vStart, vEnd))
            return false;

        cmd.payloadJson = line.substr(vStart, vEnd - vStart);
        return true;
    }
}
