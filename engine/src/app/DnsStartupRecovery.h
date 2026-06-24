#pragma once

namespace datagate::dns
{
    // Remove stale OpenVPN NRPT rules, then flush the DNS cache (same safety net as ovpnagent/tunsetup).
    void RecoverStaleWindowsDnsState();
}