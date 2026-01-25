#include "WintunHolder.h"

#include <iphlpapi.h>

#include <ifdef.h>
#include <netioapi.h>

#pragma comment(lib, "Iphlpapi.lib")

namespace datagate::wintun
{
    static std::string GetLastErrorText(DWORD code)
    {
        char buf[512]{};
        FormatMessageA(
            FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
            nullptr,
            code,
            0,
            buf,
            (DWORD)sizeof(buf),
            nullptr
        );
        return std::string(buf);
    }

    WintunHolder::WintunHolder() = default;

    WintunHolder::~WintunHolder()
    {
        if (_adapter && _close)
        {
            _close(_adapter);
            _adapter = nullptr;
        }

        Unload();
    }

    bool WintunHolder::Load(std::string& outError)
    {
        if (_dll)
            return true;

        SetDefaultDllDirectories(LOAD_LIBRARY_SEARCH_DEFAULT_DIRS | LOAD_LIBRARY_SEARCH_APPLICATION_DIR);

        _dll = LoadLibraryExW(L"wintun.dll", nullptr, LOAD_LIBRARY_SEARCH_APPLICATION_DIR);
        if (!_dll)
        {
            const auto e = GetLastError();
            outError = "LoadLibraryExW(wintun.dll) failed: " + std::to_string(e) + " " + GetLastErrorText(e);
            return false;
        }

        _create = (WintunCreateAdapterFn)GetProcAddress(_dll, "WintunCreateAdapter");
        _open   = (WintunOpenAdapterFn)GetProcAddress(_dll, "WintunOpenAdapter");
        _close  = (WintunCloseAdapterFn)GetProcAddress(_dll, "WintunCloseAdapter");
        _delete = (WintunDeleteAdapterFn)GetProcAddress(_dll, "WintunDeleteAdapter");

        // WintunGetAdapterLUID returns NET_LUID by value. We treat it as 64-bit raw.
        _getLuid = (WintunGetAdapterLuidFn)GetProcAddress(_dll, "WintunGetAdapterLUID");

        if (!_create || !_open || !_close || !_getLuid)
        {
            outError = "wintun.dll missing required exports (Create/Open/Close/GetAdapterLUID)";
            return false;
        }

        return true;
    }

    void WintunHolder::Unload()
    {
        if (_dll)
        {
            FreeLibrary(_dll);
            _dll = nullptr;
        }

        _create = nullptr;
        _open = nullptr;
        _close = nullptr;
        _delete = nullptr;
        _getLuid = nullptr;
    }

    bool WintunHolder::EnsureAdapter(const std::wstring& adapterName, const std::wstring& tunnelType, std::string& outError)
    {
        if (!Load(outError))
            return false;

        if (_adapter)
            return true;

        _adapterName = adapterName;
        _tunnelType = tunnelType;

        _adapter = _open(_adapterName.c_str());
        if (_adapter)
            return true;

        _adapter = _create(_adapterName.c_str(), _tunnelType.c_str(), nullptr);
        if (!_adapter)
        {
            const auto e = GetLastError();
            outError = "WintunCreateAdapter failed: " + std::to_string(e) + " " + GetLastErrorText(e);
            return false;
        }

        return true;
    }

    std::optional<uint32_t> WintunHolder::GetIfIndex() const
    {
        if (!_adapter || !_getLuid)
            return std::nullopt;

        const uint64_t raw = _getLuid(_adapter);

        NET_LUID luid{};
        static_assert(sizeof(NET_LUID) == sizeof(uint64_t), "NET_LUID size mismatch");
        std::memcpy(&luid, &raw, sizeof(uint64_t));

        NET_IFINDEX ifIndex = 0;
        const auto st = ConvertInterfaceLuidToIndex(&luid, &ifIndex);
        if (st != NO_ERROR)
            return std::nullopt;

        return (uint32_t)ifIndex;
    }
}
