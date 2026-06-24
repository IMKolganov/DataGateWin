#include "DnsStartupRecovery.h"

#include <openvpn/tun/win/nrpt.hpp>
#include <openvpn/win/cmd.hpp>

#include <exception>
#include <iostream>
#include <sstream>

namespace datagate::dns
{
    namespace
    {
        void RemoveStaleNrptRules()
        {
            openvpn::TunWin::NRPT::delete_rules(0);
            std::cerr << "[engine][dns] startup: removed stale NRPT rules" << std::endl;
        }

        void FlushDnsCache()
        {
            openvpn::WinCmd flush("ipconfig /flushdns");
            std::ostringstream os;
            flush.execute(os);
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
