// AppMain.cpp
#include "AppMain.h"

#include "src/ipc/IpcServer.h"
#include "src/ipc/IpcProtocol.h"
#include "src/session/SessionController.h"
#include "src/session/SessionState.h"

#include <windows.h>
#include <dbghelp.h>
#include <eh.h>

#include <atomic>
#include <cctype>
#include <iomanip>
#include <iostream>
#include <sstream>
#include <stdexcept>
#include <string>
#include <thread>

#pragma comment(lib, "Dbghelp.lib")

// -------------------- Crash dump helpers --------------------

static std::string ToHex(unsigned int code)
{
    std::ostringstream oss;
    oss << "0x"
        << std::hex << std::uppercase << std::setw(8) << std::setfill('0')
        << code;
    return oss.str();
}

static const MINIDUMP_TYPE dumpType = static_cast<MINIDUMP_TYPE>(
    MiniDumpWithFullMemory
    | MiniDumpWithHandleData
    | MiniDumpWithThreadInfo
    | MiniDumpWithUnloadedModules
);

static void WriteMiniDump(EXCEPTION_POINTERS* ep)
{
    SYSTEMTIME st{};
    GetLocalTime(&st);

    char path[MAX_PATH]{};
    GetModuleFileNameA(nullptr, path, MAX_PATH);

    std::string dumpPath = std::string(path);
    auto dot = dumpPath.find_last_of('.');
    if (dot != std::string::npos) dumpPath.resize(dot);

    std::ostringstream name;
    name << dumpPath
         << "_crash_"
         << st.wYear
         << std::setw(2) << std::setfill('0') << st.wMonth
         << std::setw(2) << std::setfill('0') << st.wDay
         << "_"
         << std::setw(2) << std::setfill('0') << st.wHour
         << std::setw(2) << std::setfill('0') << st.wMinute
         << std::setw(2) << std::setfill('0') << st.wSecond
         << ".dmp";

    dumpPath = name.str();

    HANDLE hFile = CreateFileA(
        dumpPath.c_str(),
        GENERIC_WRITE,
        0,
        nullptr,
        CREATE_ALWAYS,
        FILE_ATTRIBUTE_NORMAL,
        nullptr);

    if (hFile == INVALID_HANDLE_VALUE)
        return;

    MINIDUMP_EXCEPTION_INFORMATION mei{};
    mei.ThreadId = GetCurrentThreadId();
    mei.ExceptionPointers = ep;
    mei.ClientPointers = FALSE;

    MiniDumpWriteDump(
        GetCurrentProcess(),
        GetCurrentProcessId(),
        hFile,
        dumpType,
        &mei,
        nullptr,
        nullptr
    );

    CloseHandle(hFile);
}

static LONG WINAPI UnhandledExceptionFilterFn(EXCEPTION_POINTERS* ep)
{
    WriteMiniDump(ep);
    return EXCEPTION_EXECUTE_HANDLER;
}

static void SehTranslator(unsigned int code, _EXCEPTION_POINTERS*)
{
    throw std::runtime_error(std::string("SEH exception ") + ToHex(code));
}

// -------------------- Small helpers --------------------

static std::string GetArgValue(int argc, char** argv, const char* key)
{
    for (int i = 1; i < argc; i++)
    {
        if (std::string(argv[i]) == key && i + 1 < argc)
            return argv[i + 1];
    }
    return {};
}

static std::string MakeStatePayload(const datagate::session::SessionState& st)
{
    std::ostringstream oss;
    oss << "{\"state\":\"" << datagate::session::ToString(st.phase) << "\"";
    if (!st.lastErrorCode.empty() || !st.lastErrorMessage.empty())
    {
        oss << ",\"error\":{\"code\":\"" << datagate::ipc::JsonEscape(st.lastErrorCode)
            << "\",\"message\":\"" << datagate::ipc::JsonEscape(st.lastErrorMessage) << "\"}";
    }
    oss << "}";
    return oss.str();
}

// -------------------- JSON helpers --------------------

static std::string JsonUnescape(const std::string& s)
{
    std::string out;
    out.reserve(s.size());

    for (size_t i = 0; i < s.size(); i++)
    {
        char c = s[i];
        if (c != '\\')
        {
            out.push_back(c);
            continue;
        }

        if (i + 1 >= s.size())
            break;

        char n = s[++i];
        switch (n)
        {
        case '\\': out.push_back('\\'); break;
        case '"':  out.push_back('"');  break;
        case 'n':  out.push_back('\n'); break;
        case 'r':  out.push_back('\r'); break;
        case 't':  out.push_back('\t'); break;
        default:   out.push_back(n);    break;
        }
    }

    return out;
}

static bool TryExtractJsonStringField(
    const std::string& json,
    const char* field,
    std::string& outValue)
{
    std::string key = std::string("\"") + field + "\"";
    auto p = json.find(key);
    if (p == std::string::npos) return false;

    p = json.find(':', p);
    if (p == std::string::npos) return false;

    p = json.find('"', p);
    if (p == std::string::npos) return false;

    auto e = p + 1;
    bool escaped = false;
    for (; e < json.size(); e++)
    {
        char c = json[e];
        if (escaped) { escaped = false; continue; }
        if (c == '\\') { escaped = true; continue; }
        if (c == '"') break;
    }
    if (e >= json.size()) return false;

    outValue = json.substr(p + 1, e - (p + 1));
    outValue = JsonUnescape(outValue);
    return true;
}

static bool TryExtractJsonBoolField(
    const std::string& json,
    const char* field,
    bool& outValue)
{
    std::string key = std::string("\"") + field + "\"";
    auto p = json.find(key);
    if (p == std::string::npos) return false;

    p = json.find(':', p);
    if (p == std::string::npos) return false;

    auto v = json.substr(p + 1);
    while (!v.empty() && std::isspace((unsigned char)v.front()))
        v.erase(v.begin());

    if (v.rfind("true", 0) == 0)  { outValue = true;  return true; }
    if (v.rfind("false", 0) == 0) { outValue = false; return true; }

    return false;
}

static bool TryExtractJsonUInt16Field(
    const std::string& json,
    const char* field,
    uint16_t& outValue)
{
    std::string key = std::string("\"") + field + "\"";
    auto p = json.find(key);
    if (p == std::string::npos) return false;

    p = json.find(':', p);
    if (p == std::string::npos) return false;

    p++;
    while (p < json.size() && std::isspace((unsigned char)json[p]))
        p++;

    size_t e = p;
    while (e < json.size() && std::isdigit((unsigned char)json[e]))
        e++;

    if (e == p) return false;

    unsigned long v = std::stoul(json.substr(p, e - p));
    if (v > 65535) return false;

    outValue = static_cast<uint16_t>(v);
    return true;
}

// -------------------- AppMain --------------------

int AppMain::Run(int argc, char** argv)
{
    SetUnhandledExceptionFilter(UnhandledExceptionFilterFn);
    _set_se_translator(SehTranslator);

    const std::string sessionId = GetArgValue(argc, argv, "--session-id");
    if (sessionId.empty())
        return 2;

    // Single instance per session-id
    std::string mutexName = "Global\\datagate.engine." + sessionId + ".mutex";
    HANDLE hMutex = CreateMutexA(nullptr, TRUE, mutexName.c_str());
    if (!hMutex)
        return 4;

    if (GetLastError() == ERROR_ALREADY_EXISTS)
    {
        std::cerr << "[engine] already running for sessionId=" << sessionId << std::endl;
        CloseHandle(hMutex);
        return 0;
    }

    HANDLE hStop = CreateEventA(nullptr, TRUE, FALSE, nullptr);
    if (!hStop)
    {
        ReleaseMutex(hMutex);
        CloseHandle(hMutex);
        return 3;
    }

    datagate::ipc::IpcServer ipc(sessionId);
    datagate::session::SessionController session;

    std::atomic_bool shuttingDown{ false };
    std::atomic_bool startInProgress{ false };
    std::thread startThread;

    auto JoinStartThreadIfNeeded = [&]()
    {
        if (startThread.joinable())
            startThread.join();
    };

    auto StopSessionSafe = [&]()
    {
        JoinStartThreadIfNeeded();
        session.Stop();
    };

    // ---- Session callbacks ----

    session.OnStateChanged = [&](const datagate::session::SessionState& st)
    {
        std::cerr << "[state] " << datagate::session::ToString(st.phase) << std::endl;
        ipc.SendEvent(datagate::ipc::EventType::StateChanged, MakeStatePayload(st));
    };

    session.OnLog = [&](const std::string& line)
    {
        std::cerr << line << std::endl;
        ipc.SendEvent(
            datagate::ipc::EventType::Log,
            std::string("{\"line\":\"") + datagate::ipc::JsonEscape(line) + "\"}"
        );
    };

    session.OnError = [&](const std::string& code, const std::string& message, bool fatal)
    {
        std::ostringstream oss;
        oss << "{\"code\":\"" << datagate::ipc::JsonEscape(code)
            << "\",\"message\":\"" << datagate::ipc::JsonEscape(message)
            << "\",\"fatal\":" << (fatal ? "true" : "false") << "}";
        ipc.SendEvent(datagate::ipc::EventType::Error, oss.str());
    };

    session.OnConnected = [&](const datagate::session::ConnectedInfo& ci)
    {
        std::ostringstream oss;
        oss << "{\"ifIndex\":" << ci.vpnIfIndex
            << ",\"vpnIpv4\":\"" << datagate::ipc::JsonEscape(ci.vpnIpv4) << "\"}";
        ipc.SendEvent(datagate::ipc::EventType::Connected, oss.str());
    };

    session.OnDisconnected = [&](const std::string& reason)
    {
        ipc.SendEvent(
            datagate::ipc::EventType::Disconnected,
            std::string("{\"reason\":\"") + datagate::ipc::JsonEscape(reason) + "\"}"
        );
    };

    // ---- IPC commands ----

    ipc.SetCommandHandler([&](const datagate::ipc::Command& cmd)
    {

        // std::cerr << "[ipc][control] cmd type=" << datagate::ipc::ToString(cmd.type)
        //   << " id=" << cmd.id
        //   << " payload=" << cmd.payloadJson << std::endl;

        switch (cmd.type)
        {
        case datagate::ipc::CommandType::StartSession:
        {
            datagate::session::StartOptions opt;
            if (!TryExtractJsonStringField(cmd.payloadJson, "ovpnContent", opt.ovpnContentUtf8))
            {
                ipc.ReplyError(cmd.id, "bad_payload", "Missing ovpnContent");
                return;
            }

            // TODO: parse your bridge fields here too if needed

            ipc.ReplyOk(cmd.id, "{}");

            bool expected = false;
            if (!startInProgress.compare_exchange_strong(expected, true))
                return;

            JoinStartThreadIfNeeded();

            startThread = std::thread([&, opt = std::move(opt)]() mutable
            {
                std::string err;
                if (!shuttingDown.load())
                    session.Start(opt, err);

                startInProgress.store(false);
            });

            return;
        }

        case datagate::ipc::CommandType::StopSession:
            StopSessionSafe();
            ipc.ReplyOk(cmd.id, "{}");
            return;

        case datagate::ipc::CommandType::GetStatus:
            ipc.ReplyOk(cmd.id, MakeStatePayload(session.GetState()));
            return;

        case datagate::ipc::CommandType::StopEngine:
            shuttingDown.store(true);
            StopSessionSafe();
            ipc.ReplyOk(cmd.id, "{}");
            SetEvent(hStop);
            return;

        default:
            ipc.ReplyError(cmd.id, "unknown_command", "Unknown command");
            return;
        }
    });

    ipc.Start();
    ipc.SendEvent(datagate::ipc::EventType::EngineReady, "{}");

    // ---- Main loop ----

    const uint64_t idleExitAfterMs = 5ull * 60ull * 1000ull;
    const uint64_t startMs = GetTickCount64();
    uint64_t lastPrintedSec = 0;

    for (;;)
    {
        if (WaitForSingleObject(hStop, 500) == WAIT_OBJECT_0)
            break;

        if (session.GetState().IsRunning())
        {
            lastPrintedSec = 0;
            continue;
        }

        if (ipc.HasAnyClient())
        {
            lastPrintedSec = 0;
            continue;
        }

        uint64_t lastSeen = ipc.LastClientSeenTickMs();
        if (!lastSeen) lastSeen = startMs;

        uint64_t idleForMs = GetTickCount64() - lastSeen;
        if (idleForMs >= idleExitAfterMs)
            break;

        uint64_t sec = (idleExitAfterMs - idleForMs + 999) / 1000;
        if (sec != lastPrintedSec)
        {
            lastPrintedSec = sec;
            std::cerr << "[engine] idle shutdown in " << sec << "s" << std::endl;
        }
    }

    shuttingDown.store(true);
    StopSessionSafe();
    ipc.Stop();

    CloseHandle(hStop);

    ReleaseMutex(hMutex);
    CloseHandle(hMutex);

    return 0;
}
