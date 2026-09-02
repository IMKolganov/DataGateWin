#pragma once

namespace datagate::dns
{
    struct DnsRecoveryResult
    {
        bool ok = true;
        bool skippedBecauseSessionActive = false;
        bool accessDenied = false;
        int nrptRemoved = 0;
        int searchListKeysRestored = 0;
    };

    // Order: NRPT wipe → SearchList restore → Dnscache PARAMCHANGE → ipconfig /flushdns.
    // Same safety net as ovpnagent / TunWin::Setup::destroy DNS teardown.
    //
    // If refuseIfVpnLikelyActive is true (used by --recover-dns), skips mutation when a
    // DataGate engine mutex is held or a live OpenVPNDNSRouting-{pid} owner process exists.
    DnsRecoveryResult RecoverStaleWindowsDnsState(bool refuseIfVpnLikelyActive = false);
}
