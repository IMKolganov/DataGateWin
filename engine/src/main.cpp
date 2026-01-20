#include <iostream>
#include <string>
#include <sstream>
#include <iomanip>
#include <stdexcept>

#include <eh.h>

#include <openvpn/common/file.hpp>
#include <openvpn/common/exception.hpp>

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#include <dbghelp.h>

#pragma comment(lib, "Dbghelp.lib")

#include "VpnClient.h"
#include "WssTcpBridge.h"

// -------------------- Crash dump helpers --------------------

static std::string ToHex(unsigned int code)
{
    std::ostringstream oss;
    oss << "0x"
        << std::hex << std::uppercase << std::setw(8) << std::setfill('0')
        << code;
    return oss.str();
}

const MINIDUMP_TYPE dumpType = static_cast<MINIDUMP_TYPE>(
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

static std::string ForceTcpToLocalBridge(const std::string& originalOvpn, const std::string& localHost, uint16_t localPort)
{
    std::istringstream in(originalOvpn);
    std::ostringstream out;

    std::string line;
    bool replacedRemote = false;
    bool hasProto = false;

    while (std::getline(in, line))
    {
        std::string trimmed = line;
        while (!trimmed.empty() && (trimmed.back() == '\r' || trimmed.back() == '\n'))
            trimmed.pop_back();

        if (trimmed.rfind("remote ", 0) == 0)
        {
            if (!replacedRemote)
            {
                out << "remote " << localHost << " " << localPort << "\n";
                replacedRemote = true;
            }
            else
            {
                out << "; " << trimmed << "\n";
            }
            continue;
        }

        if (trimmed.rfind("proto ", 0) == 0)
        {
            hasProto = true;
            out << "proto tcp-client\n";
            continue;
        }

        out << trimmed << "\n";
    }

    if (!replacedRemote)
    {
        out << "remote " << localHost << " " << localPort << "\n";
    }

    if (!hasProto)
    {
        out << "proto tcp-client\n";
    }

    return out.str();
}

// -------------------- AppMain --------------------

class AppMain
{
public:
    int Run()
    {
        SetUnhandledExceptionFilter(UnhandledExceptionFilterFn);
        _set_se_translator(SehTranslator);

        const char* ovpnPath = "F:\\C++\\DataGateWin\\ovpnfiles\\test-win-wss.ovpn";
        std::cout << "ovpnPath: " << ovpnPath << std::endl;

        openvpn::ClientAPI::Config cfg;
        cfg.content = openvpn::read_text_utf8(ovpnPath);

        // 1) Start local TCP -> WSS bridge
        WssTcpBridge::Options bridgeOpt;
        bridgeOpt.host = "dev-s1.datagateapp.com";
        bridgeOpt.port = "443";
        bridgeOpt.path = "/api/proxy";
        bridgeOpt.sni = "dev-s1.datagateapp.com";
        bridgeOpt.listenIp = "127.0.0.1";
        bridgeOpt.listenPort = 18080;
        bridgeOpt.verifyServerCert = false;

        // If your backend requires auth, set it here:
        // bridgeOpt.authorizationHeader = "Bearer <token>";

        WssTcpBridge bridge(bridgeOpt);
        bridge.Start();

        std::cout << "[bridge] listening on " << bridgeOpt.listenIp << ":" << bridgeOpt.listenPort
                  << " -> wss://" << bridgeOpt.host << bridgeOpt.path << std::endl;

        // 2) Force OpenVPN profile to connect to local bridge via TCP
        cfg.content = ForceTcpToLocalBridge(cfg.content, bridgeOpt.listenIp, bridgeOpt.listenPort);

        VpnClient vpn;

        vpn.OnConnected = [&](const VpnClient::ConnectedInfo& ci)
        {
            std::cout << "[app] connected: ifIndex=" << ci.vpnIfIndex
                      << " vpnIpv4=" << ci.vpnIpv4
                      << std::endl;
        };

        vpn.OnDisconnected = [&](const std::string& reason)
        {
            std::cout << "[app] disconnected reason=" << reason << std::endl;
        };

        auto eval = vpn.Eval(cfg);
        std::cout << "eval.error: " << eval.error << std::endl;
        std::cout << "eval.message: " << eval.message << std::endl;
        std::cout << "eval.windowsDriver: " << eval.windowsDriver << std::endl;

        if (eval.error)
        {
            std::cerr << "Config evaluation failed" << std::endl;
            bridge.Stop();
            return 2;
        }

        std::cout << "Connecting..." << std::endl;

        auto status = vpn.Connect();
        std::cout << "connect() error: " << status.error
                  << " status: " << status.status
                  << " message: " << status.message << std::endl;

        vpn.WaitDone();

        if (!vpn.IsConnected())
        {
            std::cout << "Not connected. Last event: " << vpn.LastEventName()
                      << " info: " << vpn.LastEventInfo() << std::endl;
            bridge.Stop();
            return 3;
        }

        std::cout << "Connected successfully." << std::endl;
        std::cout << "Press Enter to disconnect..." << std::endl;

        std::string line;
        std::getline(std::cin, line);

        vpn.stop();
        std::cout << "stop() called" << std::endl;

        bridge.Stop();
        std::cout << "[bridge] stopped" << std::endl;

        return 0;
    }
};

int main()
{
    try
    {
        AppMain app;
        return app.Run();
    }
    catch (const openvpn::Exception& e)
    {
        std::cerr << "openvpn::Exception: " << e.what() << std::endl;
        return 10;
    }
    catch (const std::exception& e)
    {
        std::cerr << "std::exception: " << e.what() << std::endl;
        return 11;
    }
}