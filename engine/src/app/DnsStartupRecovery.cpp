#include "DnsStartupRecovery.h"

#include <windows.h>

#include <iostream>
#include <stdexcept>
#include <string>
#include <vector>

namespace datagate::dns
{
    namespace
    {
        constexpr const wchar_t* kNrptRulePrefix = L"OpenVPNDNSRouting";

        const wchar_t* const kNrptSubkeys[] = {
            L"SOFTWARE\\Policies\\Microsoft\\Windows NT\\DNSClient\\DnsPolicyConfig",
            L"SYSTEM\\CurrentControlSet\\Services\\Dnscache\\Parameters\\DnsPolicyConfig",
        };

        const wchar_t* const kSearchListSubkeys[] = {
            L"SOFTWARE\\Policies\\Microsoft\\Windows NT\\DNSClient",
            L"SOFTWARE\\Policies\\Microsoft\\WindowsNT\\DNSClient",
            L"SYSTEM\\CurrentControlSet\\Services\\TCPIP\\Parameters",
        };

        const REGSAM kRegistryViews[] = {
            KEY_WOW64_64KEY,
            KEY_WOW64_32KEY,
        };

        bool StartsWithPrefix(const std::wstring& name)
        {
            return name.rfind(kNrptRulePrefix, 0) == 0;
        }

        bool IsProcessAlive(DWORD pid)
        {
            if (pid == 0)
                return false;

            HANDLE proc = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
            if (!proc)
                return false;

            DWORD exitCode = 0;
            const bool alive = GetExitCodeProcess(proc, &exitCode) && exitCode == STILL_ACTIVE;
            CloseHandle(proc);
            return alive;
        }

        bool TryParseNrptOwnerPid(const std::wstring& ruleName, DWORD& outPid)
        {
            // OpenVPNDNSRouting-{pid}
            const auto dash = ruleName.find_last_of(L'-');
            if (dash == std::wstring::npos || dash + 1 >= ruleName.size())
                return false;

            try
            {
                outPid = static_cast<DWORD>(std::stoul(ruleName.substr(dash + 1)));
                return outPid != 0;
            }
            catch (...)
            {
                return false;
            }
        }

        bool EngineSessionMutexHeld()
        {
            // Prefer exact mutex for the UI default session-id, then any
            // Global\datagate.engine.<id>.mutex via known control-pipe presence.
            HANDLE h = OpenMutexA(SYNCHRONIZE, FALSE, "Global\\datagate.engine.dev.mutex");
            if (h)
            {
                CloseHandle(h);
                return true;
            }

            // Enumerate named pipes: datagate.engine.<sessionId>.control means an engine is up.
            WIN32_FIND_DATAW fd{};
            HANDLE find = FindFirstFileW(L"\\\\.\\pipe\\*", &fd);
            if (find == INVALID_HANDLE_VALUE)
                return false;

            bool held = false;
            do
            {
                const std::wstring name = fd.cFileName;
                constexpr wchar_t kPrefix[] = L"datagate.engine.";
                constexpr wchar_t kSuffix[] = L".control";
                if (name.size() > (std::size(kPrefix) - 1) + (std::size(kSuffix) - 1)
                    && name.compare(0, std::size(kPrefix) - 1, kPrefix) == 0
                    && name.compare(name.size() - (std::size(kSuffix) - 1), std::size(kSuffix) - 1, kSuffix) == 0)
                {
                    // Confirm matching session mutex when possible.
                    const auto mid = name.substr(
                        std::size(kPrefix) - 1,
                        name.size() - (std::size(kPrefix) - 1) - (std::size(kSuffix) - 1));
                    std::string mutexName = "Global\\datagate.engine.";
                    for (wchar_t ch : mid)
                        mutexName.push_back(static_cast<char>(ch <= 0x7f ? ch : '?'));
                    mutexName += ".mutex";

                    HANDLE mh = OpenMutexA(SYNCHRONIZE, FALSE, mutexName.c_str());
                    if (mh)
                    {
                        CloseHandle(mh);
                        held = true;
                        break;
                    }

                    // Pipe without mutex is still a strong signal the engine process is alive.
                    held = true;
                    break;
                }
            } while (FindNextFileW(find, &fd));

            FindClose(find);
            return held;
        }

        bool HasLiveOpenVpnNrptOwner(bool& accessDenied)
        {
            accessDenied = false;

            for (const REGSAM view : kRegistryViews)
            {
                for (const auto* subkey : kNrptSubkeys)
                {
                    HKEY nrptKey = nullptr;
                    const LONG rc = RegOpenKeyExW(
                        HKEY_LOCAL_MACHINE, subkey, 0, KEY_READ | view, &nrptKey);
                    if (rc == ERROR_ACCESS_DENIED)
                    {
                        accessDenied = true;
                        continue;
                    }
                    if (rc != ERROR_SUCCESS || !nrptKey)
                        continue;

                    for (DWORD index = 0;; ++index)
                    {
                        wchar_t name[256]{};
                        DWORD nameLen = static_cast<DWORD>(std::size(name));
                        const LONG enumRc = RegEnumKeyExW(
                            nrptKey, index, name, &nameLen, nullptr, nullptr, nullptr, nullptr);
                        if (enumRc == ERROR_NO_MORE_ITEMS)
                            break;
                        if (enumRc != ERROR_SUCCESS)
                            continue;

                        if (!StartsWithPrefix(name))
                            continue;

                        DWORD pid = 0;
                        if (TryParseNrptOwnerPid(name, pid) && IsProcessAlive(pid))
                        {
                            RegCloseKey(nrptKey);
                            return true;
                        }
                    }

                    RegCloseKey(nrptKey);
                }
            }

            return false;
        }

        int DeleteMatchingSubkeys(HKEY root, REGSAM view, const wchar_t* subkeyPath, bool& accessDenied)
        {
            int removed = 0;

            HKEY nrptKey = nullptr;
            const LONG openRc = RegOpenKeyExW(
                root, subkeyPath, 0, KEY_READ | KEY_WRITE | view, &nrptKey);
            if (openRc == ERROR_ACCESS_DENIED)
            {
                accessDenied = true;
                return 0;
            }
            if (openRc != ERROR_SUCCESS)
                return 0;

            std::vector<std::wstring> toDelete;
            for (DWORD index = 0;; ++index)
            {
                wchar_t name[256]{};
                DWORD nameLen = static_cast<DWORD>(std::size(name));
                const LONG rc = RegEnumKeyExW(
                    nrptKey, index, name, &nameLen, nullptr, nullptr, nullptr, nullptr);
                if (rc == ERROR_NO_MORE_ITEMS)
                    break;
                if (rc != ERROR_SUCCESS)
                    continue;

                if (StartsWithPrefix(name))
                    toDelete.emplace_back(name);
            }

            for (const auto& ruleName : toDelete)
            {
                const LONG delRc = RegDeleteTreeW(nrptKey, ruleName.c_str());
                if (delRc == ERROR_SUCCESS)
                    ++removed;
                else if (delRc == ERROR_ACCESS_DENIED)
                    accessDenied = true;
            }

            RegCloseKey(nrptKey);
            return removed;
        }

        int RemoveStaleNrptRules(bool& accessDenied)
        {
            int removed = 0;
            for (const REGSAM view : kRegistryViews)
            {
                for (const auto* subkey : kNrptSubkeys)
                    removed += DeleteMatchingSubkeys(HKEY_LOCAL_MACHINE, view, subkey, accessDenied);
            }

            std::cerr << "[engine][dns] startup: removed " << removed << " stale NRPT rule(s)" << std::endl;
            return removed;
        }

        bool ReadRegString(HKEY key, const wchar_t* valueName, std::wstring& out)
        {
            out.clear();
            DWORD type = 0;
            DWORD cb = 0;
            LONG rc = RegQueryValueExW(key, valueName, nullptr, &type, nullptr, &cb);
            if (rc == ERROR_FILE_NOT_FOUND)
                return false;
            if (rc != ERROR_SUCCESS || (type != REG_SZ && type != REG_EXPAND_SZ) || cb < sizeof(wchar_t))
                return false;

            std::vector<wchar_t> buf(cb / sizeof(wchar_t) + 1, L'\0');
            rc = RegQueryValueExW(
                key,
                valueName,
                nullptr,
                &type,
                reinterpret_cast<LPBYTE>(buf.data()),
                &cb);
            if (rc != ERROR_SUCCESS)
                return false;

            out.assign(buf.data());
            return true;
        }

        bool RestoreSearchListUnderKey(HKEY root, REGSAM view, const wchar_t* subkeyPath, bool& accessDenied)
        {
            HKEY key = nullptr;
            const LONG openRc = RegOpenKeyExW(root, subkeyPath, 0, KEY_READ | KEY_WRITE | view, &key);
            if (openRc == ERROR_ACCESS_DENIED)
            {
                accessDenied = true;
                return false;
            }
            if (openRc != ERROR_SUCCESS)
                return false;

            std::wstring original;
            std::wstring initial;
            const bool hasOriginal = ReadRegString(key, L"OriginalSearchList", original);
            const bool hasInitial = ReadRegString(key, L"InitialSearchList", initial);

            if (!hasOriginal && !hasInitial)
            {
                RegCloseKey(key);
                return false;
            }

            const std::wstring restore = hasOriginal ? original : std::wstring{};
            const LONG setRc = RegSetValueExW(
                key,
                L"SearchList",
                0,
                REG_SZ,
                reinterpret_cast<const BYTE*>(restore.c_str()),
                static_cast<DWORD>((restore.size() + 1) * sizeof(wchar_t)));

            if (setRc == ERROR_ACCESS_DENIED)
            {
                accessDenied = true;
                RegCloseKey(key);
                return false;
            }

            if (setRc != ERROR_SUCCESS)
            {
                // Do not delete Original/Initial backups when SearchList write failed —
                // otherwise openvpn3 cannot restore on a later successful run.
                std::cerr << "[engine][dns] startup: RegSetValueExW(SearchList) failed err="
                          << setRc << std::endl;
                RegCloseKey(key);
                return false;
            }

            RegDeleteValueW(key, L"InitialSearchList");
            RegDeleteValueW(key, L"OriginalSearchList");

            RegCloseKey(key);
            return true;
        }

        int RestoreSearchList(bool& accessDenied)
        {
            int restored = 0;
            for (const REGSAM view : kRegistryViews)
            {
                for (const auto* subkey : kSearchListSubkeys)
                {
                    if (RestoreSearchListUnderKey(HKEY_LOCAL_MACHINE, view, subkey, accessDenied))
                        ++restored;
                }
            }

            std::cerr << "[engine][dns] startup: restored SearchList under " << restored
                      << " key(s)" << std::endl;
            return restored;
        }

        void SignalDnsCacheReload()
        {
            SC_HANDLE scm = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT);
            if (!scm)
            {
                std::cerr << "[engine][dns] startup: OpenSCManager failed err=" << GetLastError() << std::endl;
                return;
            }

            SC_HANDLE svc = OpenServiceW(scm, L"Dnscache", SERVICE_PAUSE_CONTINUE);
            if (!svc)
            {
                const DWORD err = GetLastError();
                std::cerr << "[engine][dns] startup: OpenService(Dnscache) failed err=" << err << std::endl;
                if (err == ERROR_ACCESS_DENIED)
                    std::cerr << "[engine][dns] startup: ACCESS_DENIED — run elevated (Administrator)" << std::endl;
                CloseServiceHandle(scm);
                return;
            }

            SERVICE_STATUS status{};
            if (ControlService(svc, SERVICE_CONTROL_PARAMCHANGE, &status))
                std::cerr << "[engine][dns] startup: signaled Dnscache PARAMCHANGE" << std::endl;
            else
                std::cerr << "[engine][dns] startup: Dnscache PARAMCHANGE failed err="
                          << GetLastError() << std::endl;

            CloseServiceHandle(svc);
            CloseServiceHandle(scm);
        }

        void FlushDnsCache()
        {
            wchar_t systemDir[MAX_PATH]{};
            if (!GetSystemDirectoryW(systemDir, MAX_PATH))
                throw std::runtime_error("GetSystemDirectoryW failed");

            std::wstring cmd = std::wstring(systemDir) + L"\\ipconfig.exe /flushdns";

            STARTUPINFOW si{};
            si.cb = sizeof(si);
            PROCESS_INFORMATION pi{};

            std::vector<wchar_t> cmdLine(cmd.begin(), cmd.end());
            cmdLine.push_back(L'\0');

            if (!CreateProcessW(
                    nullptr,
                    cmdLine.data(),
                    nullptr,
                    nullptr,
                    FALSE,
                    CREATE_NO_WINDOW,
                    nullptr,
                    nullptr,
                    &si,
                    &pi))
            {
                throw std::runtime_error("CreateProcessW(ipconfig /flushdns) failed");
            }

            WaitForSingleObject(pi.hProcess, 15000);
            CloseHandle(pi.hThread);
            CloseHandle(pi.hProcess);

            std::cerr << "[engine][dns] startup: flushed DNS cache" << std::endl;
        }
    }

    DnsRecoveryResult RecoverStaleWindowsDnsState(bool refuseIfVpnLikelyActive)
    {
        DnsRecoveryResult result{};

        if (refuseIfVpnLikelyActive)
        {
            bool probeAccessDenied = false;
            if (EngineSessionMutexHeld() || HasLiveOpenVpnNrptOwner(probeAccessDenied))
            {
                result.ok = false;
                result.skippedBecauseSessionActive = true;
                std::cerr << "[engine][dns] SKIPPED: VPN/engine session appears active — "
                             "do not run --recover-dns while connected (would wipe live NRPT/SearchList)"
                          << std::endl;
                return result;
            }
            if (probeAccessDenied)
                result.accessDenied = true;
        }

        try
        {
            result.nrptRemoved = RemoveStaleNrptRules(result.accessDenied);
        }
        catch (const std::exception& ex)
        {
            result.ok = false;
            std::cerr << "[engine][dns] startup: NRPT cleanup failed: " << ex.what() << std::endl;
        }
        catch (...)
        {
            result.ok = false;
            std::cerr << "[engine][dns] startup: NRPT cleanup failed: unknown error" << std::endl;
        }

        try
        {
            result.searchListKeysRestored = RestoreSearchList(result.accessDenied);
        }
        catch (const std::exception& ex)
        {
            result.ok = false;
            std::cerr << "[engine][dns] startup: SearchList restore failed: " << ex.what() << std::endl;
        }
        catch (...)
        {
            result.ok = false;
            std::cerr << "[engine][dns] startup: SearchList restore failed: unknown error" << std::endl;
        }

        try
        {
            SignalDnsCacheReload();
        }
        catch (const std::exception& ex)
        {
            result.ok = false;
            std::cerr << "[engine][dns] startup: Dnscache signal failed: " << ex.what() << std::endl;
        }
        catch (...)
        {
            result.ok = false;
            std::cerr << "[engine][dns] startup: Dnscache signal failed: unknown error" << std::endl;
        }

        try
        {
            FlushDnsCache();
        }
        catch (const std::exception& ex)
        {
            result.ok = false;
            std::cerr << "[engine][dns] startup: DNS cache flush failed: " << ex.what() << std::endl;
        }
        catch (...)
        {
            result.ok = false;
            std::cerr << "[engine][dns] startup: DNS cache flush failed: unknown error" << std::endl;
        }

        if (result.accessDenied)
        {
            result.ok = false;
            std::cerr << "[engine][dns] ACCESS_DENIED writing HKLM — run as Administrator "
                         "(Release UI elevates; Debug asInvoker may not)"
                      << std::endl;
        }

        return result;
    }
}
