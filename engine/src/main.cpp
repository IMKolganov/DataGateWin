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

#include "DnsProxy.h"
#include "VpnClient.h"

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

// -------------------- Small helpers --------------------

static int RunCommand(const std::string& cmd)
{
    std::cout << "[cmd] " << cmd << std::endl;
    return system(cmd.c_str());
}

// -------------------- AppMain --------------------

class AppMain
{
public:
    int Run()
    {
        SetUnhandledExceptionFilter(UnhandledExceptionFilterFn);
        _set_se_translator(SehTranslator);

        const char* ovpnPath = "F:\\C++\\DataGateWin\\ovpnfiles\\win-test-udp-0.ovpn";
        std::cout << "ovpnPath: " << ovpnPath << std::endl;

        openvpn::ClientAPI::Config cfg;
        cfg.content = openvpn::read_text_utf8(ovpnPath);

        VpnClient vpn;

        vpn.OnConnected = [&](const VpnClient::ConnectedInfo& ci)
        {
            std::cout << "[app] connected: ifIndex=" << ci.vpnIfIndex
                      << " vpnIpv4=" << ci.vpnIpv4
                      << std::endl;

            if (ci.vpnIfIndex <= 0 || ci.vpnIpv4.empty())
            {
                std::cerr << "[app] missing ifIndex or vpnIpv4, dns proxy will not start" << std::endl;
                return;
            }

            vpnIfIndex_ = ci.vpnIfIndex;
            vpnIp_ = ci.vpnIpv4;

            // IMPORTANT: listen on VPN interface IP, not 127.0.0.1.
            // This is much more compatible with block-outside-dns behavior.
            DnsProxy::Config dcfg;
            dcfg.listenIp = ci.vpnIpv4;
            dcfg.listenPort = 53;
            dcfg.upstreamIp = "8.8.8.8:53";
            dcfg.upstreamPort = 53;
            dcfg.vpnBindIp = ci.vpnIpv4;

            if (!dns_.Start(dcfg))
            {
                std::cerr << "[app] dns proxy failed to start" << std::endl;
                return;
            }

            // Set DNS server for the VPN interface to our local DNS proxy (on VPN IP).
            std::ostringstream cmd;
            cmd << "netsh interface ip set dnsservers " << ci.vpnIfIndex
                << " static " << ci.vpnIpv4 << " register=primary validate=no";
            RunCommand(cmd.str());
        };

        vpn.OnDisconnected = [&](const std::string& reason)
        {
            std::cout << "[app] disconnected reason=" << reason << std::endl;

            dns_.Stop();
            RestoreDnsIfNeeded();
        };

        auto eval = vpn.Eval(cfg);
        std::cout << "eval.error: " << eval.error << std::endl;
        std::cout << "eval.message: " << eval.message << std::endl;
        std::cout << "eval.windowsDriver: " << eval.windowsDriver << std::endl;

        if (eval.error)
        {
            std::cerr << "Config evaluation failed" << std::endl;
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
            RestoreDnsIfNeeded();
            return 3;
        }

        std::cout << "Connected successfully." << std::endl;
        std::cout << "Press Enter to disconnect..." << std::endl;

        std::string line;
        std::getline(std::cin, line);

        vpn.stop();
        std::cout << "stop() called" << std::endl;

        dns_.Stop();
        RestoreDnsIfNeeded();

        return 0;
    }

private:
    void RestoreDnsIfNeeded()
    {
        if (vpnIfIndex_ <= 0)
            return;

        std::ostringstream restore;
        restore << "netsh interface ip set dnsservers " << vpnIfIndex_ << " dhcp";
        RunCommand(restore.str());

        vpnIfIndex_ = -1;
        vpnIp_.clear();
    }

private:
    DnsProxy dns_{};
    int vpnIfIndex_ = -1;
    std::string vpnIp_{};
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
