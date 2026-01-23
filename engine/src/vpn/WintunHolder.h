#pragma once

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif

#include <windows.h>
#include <string>
#include <optional>
#include <cstdint>

namespace datagate::wintun
{
    class WintunHolder
    {
    public:
        WintunHolder();
        ~WintunHolder();

        WintunHolder(const WintunHolder&) = delete;
        WintunHolder& operator=(const WintunHolder&) = delete;

        bool EnsureAdapter(const std::wstring& adapterName, const std::wstring& tunnelType, std::string& outError);

        std::optional<uint32_t> GetIfIndex() const;

    private:
        using WINTUN_ADAPTER_HANDLE = void*;

        using WintunCreateAdapterFn = WINTUN_ADAPTER_HANDLE(__stdcall*)(const wchar_t* Name, const wchar_t* TunnelType, const GUID* RequestedGUID);
        using WintunOpenAdapterFn   = WINTUN_ADAPTER_HANDLE(__stdcall*)(const wchar_t* Name);
        using WintunCloseAdapterFn  = void(__stdcall*)(WINTUN_ADAPTER_HANDLE Adapter);
        using WintunDeleteAdapterFn = BOOL(__stdcall*)(WINTUN_ADAPTER_HANDLE Adapter, BOOL ForceCloseSessions);

        using WintunGetAdapterLuidFn = uint64_t(__stdcall*)(WINTUN_ADAPTER_HANDLE Adapter);

        bool Load(std::string& outError);
        void Unload();

        HMODULE _dll = nullptr;

        WintunCreateAdapterFn _create = nullptr;
        WintunOpenAdapterFn _open = nullptr;
        WintunCloseAdapterFn _close = nullptr;
        WintunDeleteAdapterFn _delete = nullptr;
        WintunGetAdapterLuidFn _getLuid = nullptr;

        WINTUN_ADAPTER_HANDLE _adapter = nullptr;
        std::wstring _adapterName;
        std::wstring _tunnelType;
    };
}
