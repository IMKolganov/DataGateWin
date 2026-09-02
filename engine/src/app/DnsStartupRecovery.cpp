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

        // OpenVPN3 uses "WindowsNT" (no space) for the GPO search-list key; also cover the
        // documented "Windows NT" spelling and TCPIP Parameters (see openvpn/tun/win/dns.hpp).
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

        int DeleteMatchingSubkeys(HKEY root, REGSAM view, const wchar_t* subkeyPath)
        {
            int removed = 0;

            HKEY nrptKey = nullptr;
            if (RegOpenKeyExW(
                    root,
                    subkeyPath,
                    0,
                    KEY_READ | KEY_WRITE | view,
                    &nrptKey) != ERROR_SUCCESS)
            {
                return 0;
            }

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
                if (RegDeleteTreeW(nrptKey, ruleName.c_str()) == ERROR_SUCCESS)
                    ++removed;
            }

            RegCloseKey(nrptKey);
            return removed;
        }

        void RemoveStaleNrptRules()
        {
            int removed = 0;
            for (const REGSAM view : kRegistryViews)
            {
                for (const auto* subkey : kNrptSubkeys)
                    removed += DeleteMatchingSubkeys(HKEY_LOCAL_MACHINE, view, subkey);
            }

            std::cerr << "[engine][dns] startup: removed " << removed << " stale NRPT rule(s)" << std::endl;
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

        bool RestoreSearchListUnderKey(HKEY root, REGSAM view, const wchar_t* subkeyPath)
        {
            HKEY key = nullptr;
            if (RegOpenKeyExW(root, subkeyPath, 0, KEY_READ | KEY_WRITE | view, &key) != ERROR_SUCCESS)
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

            // Mirror openvpn3 Dns::reset_search_domains: restore OriginalSearchList, or empty if absent.
            const std::wstring restore = hasOriginal ? original : std::wstring{};
            RegSetValueExW(
                key,
                L"SearchList",
                0,
                REG_SZ,
                reinterpret_cast<const BYTE*>(restore.c_str()),
                static_cast<DWORD>((restore.size() + 1) * sizeof(wchar_t)));

            RegDeleteValueW(key, L"InitialSearchList");
            RegDeleteValueW(key, L"OriginalSearchList");

            RegCloseKey(key);
            return true;
        }

        void RestoreSearchList()
        {
            int restored = 0;
            for (const REGSAM view : kRegistryViews)
            {
                for (const auto* subkey : kSearchListSubkeys)
                {
                    if (RestoreSearchListUnderKey(HKEY_LOCAL_MACHINE, view, subkey))
                        ++restored;
                }
            }

            std::cerr << "[engine][dns] startup: restored SearchList under " << restored
                      << " key(s)" << std::endl;
        }

        void SignalDnsCacheReload()
        {
            SC_HANDLE scm = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT);
            if (!scm)
            {
                std::cerr << "[engine][dns] startup: OpenSCManager failed" << std::endl;
                return;
            }

            SC_HANDLE svc = OpenServiceW(scm, L"Dnscache", SERVICE_PAUSE_CONTINUE);
            if (!svc)
            {
                std::cerr << "[engine][dns] startup: OpenService(Dnscache) failed" << std::endl;
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

    void RecoverStaleWindowsDnsState()
    {
        // Order: NRPT → SearchList → Dnscache reload → flushdns
        try
        {
            RemoveStaleNrptRules();
        }
        catch (const std::exception& ex)
        {
            std::cerr << "[engine][dns] startup: NRPT cleanup failed: " << ex.what() << std::endl;
        }
        catch (...)
        {
            std::cerr << "[engine][dns] startup: NRPT cleanup failed: unknown error" << std::endl;
        }

        try
        {
            RestoreSearchList();
        }
        catch (const std::exception& ex)
        {
            std::cerr << "[engine][dns] startup: SearchList restore failed: " << ex.what() << std::endl;
        }
        catch (...)
        {
            std::cerr << "[engine][dns] startup: SearchList restore failed: unknown error" << std::endl;
        }

        try
        {
            SignalDnsCacheReload();
        }
        catch (const std::exception& ex)
        {
            std::cerr << "[engine][dns] startup: Dnscache signal failed: " << ex.what() << std::endl;
        }
        catch (...)
        {
            std::cerr << "[engine][dns] startup: Dnscache signal failed: unknown error" << std::endl;
        }

        try
        {
            FlushDnsCache();
        }
        catch (const std::exception& ex)
        {
            std::cerr << "[engine][dns] startup: DNS cache flush failed: " << ex.what() << std::endl;
        }
        catch (...)
        {
            std::cerr << "[engine][dns] startup: DNS cache flush failed: unknown error" << std::endl;
        }
    }
}
