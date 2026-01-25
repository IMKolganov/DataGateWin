#pragma once

#include "vpn/WintunHolder.h"

#include <optional>
#include <string>

namespace datagate::session
{
    class WintunAdapterManager
    {
    public:
        bool EnsureReady(std::string& outError);
        std::optional<int> GetIfIndex() const;

    private:
        datagate::wintun::WintunHolder _tun;
        bool _ready = false;
    };
}
