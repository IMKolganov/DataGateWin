#pragma once

#include <string>
#include <vector>

namespace datagate::xray
{
    /// Builds a Windows Xray client JSON (TUN inbound + outbounds + private→direct routing).
    /// No geoip.dat; no Android tun fd (Xray creates the adapter).
    class XrayConfigBuilder
    {
    public:
        /// First vless/vmess/… line, or JSON field "vless".
        static std::string ExtractShareLinkOrEmpty(const std::string& text);

        /// @param outboundsOrConfigJson share-convert result, `{outbounds:[...]}`, or raw outbounds array.
        /// @param directBypassCidrs extra CIDRs → direct (proxy endpoint /32, API hosts).
        /// @param tunnelDnsServers DNS IPs forced through proxy before private→direct.
        /// @param fullConfigJson out — ready for runXrayFromJson
        static bool BuildWindowsTunClientConfig(
            const std::string& outboundsOrConfigJson,
            std::string& fullConfigJson,
            std::string& outError,
            const std::vector<std::string>& directBypassCidrs = {},
            const std::vector<std::string>& tunnelDnsServers = {},
            int mtu = 1500);

        /// Collect IPv4/IPv6 literal endpoints from proxy outbounds as /32 or /128.
        static std::vector<std::string> CollectProxyEndpointCidrs(const std::string& outboundsOrConfigJson);
    };
}
