#pragma once

#include <cstdint>
#include <string>
#include <vector>

#include "EnginePortDefaults.h"

namespace datagate::session::ovpn
{
    struct OvpnRemote
    {
        std::string host;
        uint16_t port = kOpenVpnDefaultRemotePort;
        std::string proto; // may be empty; e.g. "udp", "udp4", "tcp"
    };

    // Parses a decimal port in 1..65535. Rejects 0, empty, non-digits, overflow.
    bool TryParsePort(const std::string& text, uint16_t& outPort);

    // Returns the value of the first "proto" directive, or "" if missing.
    std::string TryGetProtoFromOvpn(const std::string& ovpnContentUtf8);

    // Parses the first "remote host [port] [proto]" line.
    bool TryGetFirstRemoteFromOvpn(const std::string& ovpnContentUtf8, OvpnRemote& out);

    // Collects "dhcp-option DNS <addr>" values (diagnostics / UI; OpenVPN3 still applies push).
    std::vector<std::string> TryGetDnsServersFromOvpn(const std::string& ovpnContentUtf8);

    // OpenVPN default is UDP when proto is omitted.
    bool IsUdpProto(const std::string& proto);

    // Prefer per-remote proto, then global proto, then OpenVPN default (udp).
    std::string ResolveTransportProto(const std::string& ovpnContentUtf8);

    std::string AppendQueryParam(std::string path, const char* key, const char* value);
}
