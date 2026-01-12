#include <iostream>
#include <string>
#include <mutex>
#include <condition_variable>
#include <atomic>
#include <sstream>
#include <iomanip>
#include <stdexcept>

#include <eh.h>

#include <client/ovpncli.hpp>
#include <openvpn/common/file.hpp>
#include <openvpn/common/exception.hpp>

// Windows headers: include late to avoid winsock header conflicts
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <dbghelp.h>


#pragma comment(lib, "Dbghelp.lib")

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

class MyClient : public openvpn::ClientAPI::OpenVPNClient
{
public:
    std::mutex mtx;
    std::condition_variable cv;
    std::atomic<bool> done{false};
    bool connected = false;
    std::string last_event_name;
    std::string last_event_info;

    bool pause_on_connection_timeout() override { return false; }

    void event(const openvpn::ClientAPI::Event& ev) override
    {
        {
            std::lock_guard<std::mutex> lock(mtx);
            last_event_name = ev.name;
            last_event_info = ev.info;

            std::cout << "[event] name=" << ev.name << " info=" << ev.info << std::endl;

            if (ev.name == "CONNECTED")
            {
                connected = true;
                done = true;
            }
            if (ev.name == "DISCONNECTED" || ev.name == "AUTH_FAILED")
            {
                connected = false;
                done = true;
            }
        }
        cv.notify_all();
    }

    void acc_event(const openvpn::ClientAPI::AppCustomControlMessageEvent&) override
    {
        std::cout << "[acc_event]" << std::endl;
    }

    void log(const openvpn::ClientAPI::LogInfo& log) override
    {
        std::cout << "[log] " << log.text << std::endl;
    }

    void external_pki_cert_request(openvpn::ClientAPI::ExternalPKICertRequest&) override {}
    void external_pki_sign_request(openvpn::ClientAPI::ExternalPKISignRequest&) override {}
};

int main()
{
    SetUnhandledExceptionFilter(UnhandledExceptionFilterFn);
    _set_se_translator(SehTranslator);

    try
    {
        const char* ovpnPath = "F:\\C++\\DataGateWin\\ovpnfiles\\win-test-udp-0.ovpn";
        std::cout << "ovpnPath: " << ovpnPath << std::endl;

        MyClient client;


        openvpn::ClientAPI::Config cfg;
        cfg.content = openvpn::read_text_utf8(ovpnPath);

        // Optional: force TAP instead of Wintun
        cfg.wintun = false;

        // Optional: if you want to avoid DCO during experiments
        // cfg.dco = false;

        auto eval = client.eval_config(cfg);
        if (eval.error) return 2;

        std::cout << "eval.error: " << eval.error << std::endl;
        std::cout << "eval.message: " << eval.message << std::endl;
        std::cout << "eval.windowsDriver: " << eval.windowsDriver << std::endl;

        if (eval.error)
        {
            std::cerr << "Config evaluation failed" << std::endl;
            return 2;
        }

        std::cout << "Connecting..." << std::endl;

        auto status = client.connect();
        std::cout << "connect() error: " << status.error
                  << " status: " << status.status
                  << " message: " << status.message << std::endl;

        {
            std::unique_lock<std::mutex> lock(client.mtx);
            client.cv.wait(lock, [&] { return client.done.load(); });
        }

        if (client.connected)
        {
            std::cout << "Connected successfully." << std::endl;
            std::cout << "Press Enter to disconnect..." << std::endl;
            std::string line;
            std::getline(std::cin, line);

            client.stop();
            std::cout << "stop() called" << std::endl;
        }
        else
        {
            std::cout << "Not connected. Last event: " << client.last_event_name
                      << " info: " << client.last_event_info << std::endl;
            return 3;
        }

        return 0;
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
