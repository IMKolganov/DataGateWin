#include "CrashReporter.h"
#include "../util/InMemoryLogBudget.h"

#include <windows.h>
#include <dbghelp.h>
#include <eh.h>

#include <algorithm>
#include <cstdlib>
#include <exception>
#include <fstream>
#include <iomanip>
#include <mutex>
#include <sstream>
#include <stdexcept>
#include <string>
#include <vector>

#pragma comment(lib, "Dbghelp.lib")

namespace
{
static constexpr const char* EngineProcessName = "com.imkolganov.datagate.win.engine";

static std::terminate_handler PreviousTerminateHandler = nullptr;

static std::string ToHex(unsigned int code)
{
    std::ostringstream oss;
    oss << "0x"
        << std::hex << std::uppercase << std::setw(8) << std::setfill('0')
        << code;
    return oss.str();
}

static std::string FormatTimestampUtcIso(const SYSTEMTIME& st)
{
    std::ostringstream oss;
    oss << st.wYear
        << "-" << std::setw(2) << std::setfill('0') << st.wMonth
        << "-" << std::setw(2) << std::setfill('0') << st.wDay
        << "T" << std::setw(2) << std::setfill('0') << st.wHour
        << ":" << std::setw(2) << std::setfill('0') << st.wMinute
        << ":" << std::setw(2) << std::setfill('0') << st.wSecond
        << "." << std::setw(3) << std::setfill('0') << st.wMilliseconds
        << "Z";
    return oss.str();
}

static std::string FormatFilenameTimestampUtc(const SYSTEMTIME& st)
{
    std::ostringstream oss;
    oss << st.wYear
        << "-" << std::setw(2) << std::setfill('0') << st.wMonth
        << "-" << std::setw(2) << std::setfill('0') << st.wDay
        << "T" << std::setw(2) << std::setfill('0') << st.wHour
        << "-" << std::setw(2) << std::setfill('0') << st.wMinute
        << "-" << std::setw(2) << std::setfill('0') << st.wSecond
        << "." << std::setw(3) << std::setfill('0') << st.wMilliseconds
        << "Z";
    return oss.str();
}

static std::string BuildCrashFilenameUtc()
{
    SYSTEMTIME st{};
    GetSystemTime(&st);
    return std::string("win_engine_crash_") + FormatFilenameTimestampUtc(st) + ".txt";
}

static const MINIDUMP_TYPE dumpType = static_cast<MINIDUMP_TYPE>(
    MiniDumpWithFullMemory
    | MiniDumpWithHandleData
    | MiniDumpWithThreadInfo
    | MiniDumpWithUnloadedModules
);

static std::string WriteMiniDump(EXCEPTION_POINTERS* ep)
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
        return {};

    MINIDUMP_EXCEPTION_INFORMATION mei{};
    mei.ThreadId = GetCurrentThreadId();
    mei.ExceptionPointers = ep;
    mei.ClientPointers = FALSE;

    MINIDUMP_EXCEPTION_INFORMATION* meiPtr = ep == nullptr ? nullptr : &mei;

    MiniDumpWriteDump(
        GetCurrentProcess(),
        GetCurrentProcessId(),
        hFile,
        dumpType,
        meiPtr,
        nullptr,
        nullptr
    );

    CloseHandle(hFile);
    return dumpPath;
}

static std::string JsonEscape(const std::string& value)
{
    std::ostringstream oss;
    for (unsigned char ch : value)
    {
        switch (ch)
        {
        case '\\':
            oss << "\\\\";
            break;
        case '"':
            oss << "\\\"";
            break;
        case '\b':
            oss << "\\b";
            break;
        case '\f':
            oss << "\\f";
            break;
        case '\n':
            oss << "\\n";
            break;
        case '\r':
            oss << "\\r";
            break;
        case '\t':
            oss << "\\t";
            break;
        default:
            if (ch < 0x20)
            {
                oss << "\\u"
                    << std::hex << std::uppercase << std::setw(4) << std::setfill('0')
                    << static_cast<int>(ch)
                    << std::dec << std::nouppercase;
            }
            else
            {
                oss << static_cast<char>(ch);
            }
            break;
        }
    }

    return oss.str();
}

static std::string GetQueueDirectory()
{
    char localAppData[MAX_PATH]{};
    const DWORD len = GetEnvironmentVariableA("LOCALAPPDATA", localAppData, MAX_PATH);
    if (len == 0 || len >= MAX_PATH)
        return {};

    std::string base(localAppData);
    const std::string appDir = base + "\\DataGateWin";
    CreateDirectoryA(appDir.c_str(), nullptr);

    const std::string queueDir = appDir + "\\crash-queue";
    CreateDirectoryA(queueDir.c_str(), nullptr);
    return queueDir;
}

static std::string BuildPayload(
    const std::string& exceptionName,
    const std::string& message,
    const std::string& kind,
    DWORD threadId,
    const std::string& dumpPath)
{
    SYSTEMTIME st{};
    GetSystemTime(&st);

    std::ostringstream body;
    body << "timestamp_utc=" << FormatTimestampUtcIso(st) << "\n";
    body << "process=" << EngineProcessName << "\n";
    body << "thread=NativeThread-" << threadId << "\n";
    body << "sdk=native C++ engine\n";
    body << "device=Windows\n";
    body << "kind=" << kind << "\n";
    body << "exception=" << exceptionName << "\n";
    body << "message=" << message << "\n";
    if (!dumpPath.empty())
        body << "dump_path=" << dumpPath << "\n";

    body << "\n";
    body << message << "\n";
    if (!dumpPath.empty())
        body << "Minidump: " << dumpPath << "\n";

    return body.str();
}

static void TrimQueueDirectory(const std::string& queueDir)
{
    const std::string pattern = queueDir + "\\*.queued.json";
    WIN32_FIND_DATAA fd{};
    HANDLE h = FindFirstFileA(pattern.c_str(), &fd);
    if (h == INVALID_HANDLE_VALUE)
        return;

    struct Entry
    {
        std::string path;
        FILETIME created{};
        ULONGLONG size{ 0 };
    };

    std::vector<Entry> entries;
    ULONGLONG total = 0;
    do
    {
        if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)
            continue;

        Entry e;
        e.path = queueDir + "\\" + fd.cFileName;
        e.created = fd.ftCreationTime;
        e.size = (static_cast<ULONGLONG>(fd.nFileSizeHigh) << 32) | fd.nFileSizeLow;
        total += e.size;
        entries.push_back(std::move(e));
    } while (FindNextFileA(h, &fd));
    FindClose(h);

    if (total <= datagate::kInMemoryLogBudgetBytes)
        return;

    std::sort(entries.begin(), entries.end(), [](const Entry& a, const Entry& b)
    {
        return CompareFileTime(&a.created, &b.created) < 0;
    });

    for (const auto& e : entries)
    {
        if (total <= datagate::kInMemoryLogBudgetBytes)
            break;
        if (DeleteFileA(e.path.c_str()))
        {
            if (total >= e.size)
                total -= e.size;
            else
                total = 0;
        }
    }
}

static bool ShouldDropDuplicateNonFatal(const std::string& exceptionName, const std::string& message)
{
    static std::mutex mx;
    static std::string lastKey;
    static ULONGLONG lastTickMs = 0;
    constexpr ULONGLONG kMinIntervalMs = 30'000;

    const std::string key = exceptionName + "\n" + message;
    const ULONGLONG now = GetTickCount64();

    std::lock_guard<std::mutex> lock(mx);
    if (key == lastKey && (now - lastTickMs) < kMinIntervalMs)
        return true;

    lastKey = key;
    lastTickMs = now;
    return false;
}

static void QueueCrashReport(const std::string& filename, const std::string& payload)
{
    const std::string queueDir = GetQueueDirectory();
    if (queueDir.empty())
        return;

    SYSTEMTIME st{};
    GetSystemTime(&st);

    std::ostringstream queueName;
    queueName << st.wYear
              << std::setw(2) << std::setfill('0') << st.wMonth
              << std::setw(2) << std::setfill('0') << st.wDay
              << std::setw(2) << std::setfill('0') << st.wHour
              << std::setw(2) << std::setfill('0') << st.wMinute
              << std::setw(2) << std::setfill('0') << st.wSecond
              << std::setw(3) << std::setfill('0') << st.wMilliseconds
              << "_" << GetCurrentProcessId()
              << "_" << GetCurrentThreadId()
              << ".queued.json";

    const std::string path = queueDir + "\\" + queueName.str();
    std::ofstream file(path, std::ios::binary | std::ios::trunc);
    if (!file)
        return;

    file << "{\"Filename\":\"" << JsonEscape(filename)
         << "\",\"Payload\":\"" << JsonEscape(payload)
         << "\",\"ProcessName\":\"" << EngineProcessName
         << "\"}";
    file.close();

    TrimQueueDirectory(queueDir);
}

static LONG WINAPI UnhandledExceptionFilterFn(EXCEPTION_POINTERS* ep)
{
    const DWORD code = ep != nullptr && ep->ExceptionRecord != nullptr
        ? ep->ExceptionRecord->ExceptionCode
        : 0;
    const std::string message = std::string("Unhandled SEH exception ") + ToHex(code);
    const std::string dumpPath = WriteMiniDump(ep);

    QueueCrashReport(
        BuildCrashFilenameUtc(),
        BuildPayload("SEHException", message, "fatal", GetCurrentThreadId(), dumpPath));

    return EXCEPTION_EXECUTE_HANDLER;
}

static void SehTranslator(unsigned int code, _EXCEPTION_POINTERS*)
{
    throw std::runtime_error(std::string("SEH exception ") + ToHex(code));
}

static void TerminateHandler()
{
    std::string message = "std::terminate";

    try
    {
        auto current = std::current_exception();
        if (current)
            std::rethrow_exception(current);
    }
    catch (const std::exception& ex)
    {
        message = std::string("Unhandled C++ exception: ") + ex.what();
    }
    catch (...)
    {
        message = "Unhandled non-standard C++ exception";
    }

    const std::string dumpPath = WriteMiniDump(nullptr);
    QueueCrashReport(
        BuildCrashFilenameUtc(),
        BuildPayload("Terminate", message, "fatal", GetCurrentThreadId(), dumpPath));

    if (PreviousTerminateHandler != nullptr)
        PreviousTerminateHandler();

    std::abort();
}
}

void CrashReporter::Install()
{
    SetUnhandledExceptionFilter(UnhandledExceptionFilterFn);
    _set_se_translator(SehTranslator);
    PreviousTerminateHandler = std::set_terminate(TerminateHandler);
}

void CrashReporter::ReportFatal(const std::string& exceptionName, const std::string& message)
{
    const std::string dumpPath = WriteMiniDump(nullptr);
    QueueCrashReport(
        BuildCrashFilenameUtc(),
        BuildPayload(exceptionName, message, "fatal", GetCurrentThreadId(), dumpPath));
}

void CrashReporter::ReportNonFatal(const std::string& exceptionName, const std::string& message)
{
    if (ShouldDropDuplicateNonFatal(exceptionName, message))
        return;

    QueueCrashReport(
        BuildCrashFilenameUtc(),
        BuildPayload(exceptionName, message, "nonfatal", GetCurrentThreadId(), std::string()));
}
