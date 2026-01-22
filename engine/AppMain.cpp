#include "AppMain.h"

#include "src/ipc/IpcServer.h"
#include "src/ipc/IpcProtocol.h"
#include "src/session/SessionController.h"
#include "src/session/SessionState.h"

#include <windows.h>
#include <dbghelp.h>
#include <eh.h>

#include <atomic>
#include <iomanip>
#include <iostream>
#include <sstream>
#include <stdexcept>
#include <string>

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
    {
        std::cerr << "CreateFile failed for dump: " << dumpPath
                  << " lastError=" << GetLastError() << std::endl;
        return;
    }

    MINIDUMP_EXCEPTION_INFORMATION mei{};
    mei.ThreadId = GetCurrentThreadId();
    mei.ExceptionPointers = ep;
    mei.ClientPointers = FALSE;

    BOOL ok = MiniDumpWriteDump(
        GetCurrentProcess(),
        GetCurrentProcessId(),
        hFile,
        dumpType,
        &mei,
        nullptr,
        nullptr
    );

    CloseHandle(hFile);

    std::cerr << "MiniDumpWriteDump: " << (ok ? "OK" : "FAILED")
              << " path=" << dumpPath
              << " lastError=" << GetLastError()
              << std::endl;
}

static LONG WINAPI UnhandledExceptionFilterFn(EXCEPTION_POINTERS* ep)
{
    auto code = ep && ep->ExceptionRecord ? ep->ExceptionRecord->ExceptionCode : 0;
    std::cerr << "Unhandled SEH: " << ToHex(code) << std::endl;
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
        default:
            out.push_back(n);
            break;
        }
    }

    return out;
}

static bool TryExtractJsonStringField(const std::string& json, const char* field, std::string& outValue)
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

static bool TryExtractJsonBoolField(const std::string& json, const char* field, bool& outValue)
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

static bool TryExtractJsonUInt16Field(const std::string& json, const char* field, uint16_t& outValue)
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

    outValue = (uint16_t)v;
    return true;
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

// -------------------- AppMain --------------------

int AppMain::Run(int argc, char** argv)
{
    SetUnhandledExceptionFilter(UnhandledExceptionFilterFn);
    _set_se_translator(SehTranslator);

    const std::string sessionId = GetArgValue(argc, argv, "--session-id");
    if (sessionId.empty())
    {
        std::cerr << "Missing required arg: --session-id <value>" << std::endl;
        return 2;
    }

    HANDLE hStop = CreateEventA(nullptr, TRUE, FALSE, nullptr);
    if (!hStop)
    {
        std::cerr << "CreateEvent failed lastError=" << GetLastError() << std::endl;
        return 3;
    }

    datagate::ipc::IpcServer ipc(sessionId);
    datagate::session::SessionController session;

    // Session -> IPC events
    session.OnStateChanged = [&](const datagate::session::SessionState& st)
    {
        ipc.SendEvent(datagate::ipc::EventType::StateChanged, MakeStatePayload(st));
    };

    session.OnLog = [&](const std::string& line)
    {
        std::string payload = std::string("{\"line\":\"") + datagate::ipc::JsonEscape(line) + "\"}";
        ipc.SendEvent(datagate::ipc::EventType::Log, payload);
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
        std::string payload = std::string("{\"reason\":\"") + datagate::ipc::JsonEscape(reason) + "\"}";
        ipc.SendEvent(datagate::ipc::EventType::Disconnected, payload);
    };

    // IPC -> Session commands
    ipc.SetCommandHandler([&](const datagate::ipc::Command& cmd)
    {
        switch (cmd.type)
        {
        case datagate::ipc::CommandType::StartSession:
        {
            datagate::session::StartOptions opt;

            if (!TryExtractJsonStringField(cmd.payloadJson, "ovpnContent", opt.ovpnContentUtf8))
            {
                ipc.ReplyError(cmd.id, "bad_payload", "Missing field: ovpnContent");
                return;
            }

            TryExtractJsonStringField(cmd.payloadJson, "host", opt.bridge.host);
            TryExtractJsonStringField(cmd.payloadJson, "port", opt.bridge.port);
            TryExtractJsonStringField(cmd.payloadJson, "path", opt.bridge.path);
            TryExtractJsonStringField(cmd.payloadJson, "sni", opt.bridge.sni);
            TryExtractJsonStringField(cmd.payloadJson, "listenIp", opt.bridge.listenIp);
            TryExtractJsonUInt16Field(cmd.payloadJson, "listenPort", opt.bridge.listenPort);
            TryExtractJsonBoolField(cmd.payloadJson, "verifyServerCert", opt.bridge.verifyServerCert);
            TryExtractJsonStringField(cmd.payloadJson, "authorizationHeader", opt.bridge.authorizationHeader);

            if (opt.bridge.host.empty() || opt.bridge.port.empty() || opt.bridge.path.empty()
                || opt.bridge.listenIp.empty() || opt.bridge.listenPort == 0)
            {
                ipc.ReplyError(cmd.id, "bad_payload", "Missing bridge fields: host/port/path/listenIp/listenPort");
                return;
            }

            std::string err;
            if (!session.Start(opt, err))
            {
                ipc.ReplyError(cmd.id, "start_failed", err);
                return;
            }

            ipc.ReplyOk(cmd.id, "{}");
            return;
        }

        case datagate::ipc::CommandType::StopSession:
        {
            session.Stop();
            ipc.ReplyOk(cmd.id, "{}");
            return;
        }

        case datagate::ipc::CommandType::GetStatus:
        {
            auto st = session.GetState();
            ipc.ReplyOk(cmd.id, MakeStatePayload(st));
            return;
        }

        case datagate::ipc::CommandType::StopEngine:
        {
            session.Stop();
            ipc.ReplyOk(cmd.id, "{}");
            SetEvent(hStop);
            return;
        }

        default:
            ipc.ReplyError(cmd.id.empty() ? "?" : cmd.id, "unknown_command", "Unknown command type");
            return;
        }
    });

    ipc.Start();
    std::cerr << "[engine] ipc started, sending EngineReady" << std::endl;
    ipc.SendEvent(datagate::ipc::EventType::EngineReady, "{}");

    const uint64_t idleExitAfterMs = 10 * 1000;
    const uint64_t startMs = GetTickCount64();

    for (;;)
    {
        DWORD w = WaitForSingleObject(hStop, 500);
        if (w == WAIT_OBJECT_0)
            break;

        auto st = session.GetState();
        if (st.IsRunning())
            continue;

        const bool hasClients = ipc.HasAnyClient();
        if (hasClients)
            continue;

        uint64_t lastSeen = ipc.LastClientSeenTickMs();
        if (lastSeen == 0)
            lastSeen = startMs;

        const uint64_t now = GetTickCount64();
        if ((now - lastSeen) >= idleExitAfterMs)
            break;
    }

    session.Stop();
    ipc.Stop();
    CloseHandle(hStop);
    return 0;
}
