#include "DnsStartupRecovery.h"

#include <windows.h>

#include <iostream>
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

        bool StartsWithPrefix(const std::wstring& name)
        {
            return name.rfind(kNrptRulePrefix, 0) == 0;
        }

        int DeleteMatchingSubkeys(HKEY root, const wchar_t* subkeyPath)
        {
            int removed = 0;

            HKEY nrptKey = nullptr;
            if (RegOpenKeyExW(root, subkeyPath, 0, KEY_READ | KEY_WRITE, &nrptKey) != ERROR_SUCCESS)
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
                if (RegDeleteTreeW(nrptKey, ruleName.c_str()) == ERROR_SUCCESS)
                    ++removed;
            }

            RegCloseKey(nrptKey);
            return removed;
        }

        void RemoveStaleNrptRules()
        {
            int removed = 0;
            for (const auto* subkey : kNrptSubkeys)
                removed += DeleteMatchingSubkeys(HKEY_LOCAL_MACHINE, subkey);

            std::cerr << "[engine][dns] startup: removed " << removed << " stale NRPT rule(s)" << std::endl;
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

            // CreateProcess needs mutable buffer.
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
