#include "WintunAdapterManager.h"

namespace datagate::session
{
    bool WintunAdapterManager::EnsureReady(std::string& outError)
    {
        const std::wstring adapterName = L"DataGate";
        const std::wstring tunnelType = L"DataGate";

        if (_ready)
            return true;

        if (!_tun.EnsureAdapter(adapterName, tunnelType, outError))
            return false;

        _ready = true;
        return true;
    }

    std::optional<int> WintunAdapterManager::GetIfIndex() const
    {
        if (auto idx = _tun.GetIfIndex())
            return static_cast<int>(*idx);

        return std::nullopt;
    }
}
