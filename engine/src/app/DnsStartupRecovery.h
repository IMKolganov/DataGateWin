#pragma once

namespace datagate::dns
{
    // Order: NRPT wipe → SearchList restore → Dnscache PARAMCHANGE → ipconfig /flushdns.
    // Same safety net as ovpnagent / TunWin::Setup::destroy DNS teardown.
    void RecoverStaleWindowsDnsState();
}