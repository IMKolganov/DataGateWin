#include "CrashReporter.h"

#include <windows.h>
#include <dbghelp.h>
#include <eh.h>

#include <iomanip>
#include <sstream>
#include <stdexcept>
#include <string>

#pragma comment(lib, "Dbghelp.lib")

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

void CrashReporter::Install()
{
    SetUnhandledExceptionFilter(UnhandledExceptionFilterFn);
    _set_se_translator(SehTranslator);
}
