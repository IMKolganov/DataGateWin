#include "OvpnTextUtils.h"

#include <algorithm>
#include <cctype>
#include <sstream>

namespace datagate::session::ovpn
{
    static std::string Trim(const std::string& s)
    {
        size_t b = 0;
        while (b < s.size() && std::isspace(static_cast<unsigned char>(s[b])))
            ++b;

        size_t e = s.size();
        while (e > b && std::isspace(static_cast<unsigned char>(s[e - 1])))
            --e;

        return s.substr(b, e - b);
    }

    static std::string ToLower(std::string s)
    {
        std::transform(
            s.begin(),
            s.end(),
            s.begin(),
            [](unsigned char c) { return static_cast<char>(std::tolower(c)); }
        );
        return s;
    }

    static bool IsAllDigits(const std::string& s)
    {
        if (s.empty())
            return false;

        for (unsigned char c : s)
        {
            if (!std::isdigit(c))
                return false;
        }
        return true;
    }

    bool TryParsePort(const std::string& text, uint16_t& outPort)
    {
        if (!IsAllDigits(text))
            return false;

        try
        {
            const unsigned long p = std::stoul(text);
            if (p < 1 || p > 65535)
                return false;

            outPort = static_cast<uint16_t>(p);
            return true;
        }
        catch (...)
        {
            return false;
        }
    }

    std::string TryGetProtoFromOvpn(const std::string& ovpnContentUtf8)
    {
        std::istringstream iss(ovpnContentUtf8);
        std::string line;

        while (std::getline(iss, line))
        {
            line = Trim(line);
            if (line.empty())
                continue;

            if (line[0] == '#' || line[0] == ';')
                continue;

            auto lower = ToLower(line);

            if (lower.rfind("proto", 0) == 0)
            {
                std::istringstream ls(lower);
                std::string k, v;
                ls >> k >> v;
                if (k == "proto")
                    return v;
            }
        }

        return "";
    }

    bool TryGetFirstRemoteFromOvpn(const std::string& ovpnContentUtf8, OvpnRemote& out)
    {
        std::istringstream iss(ovpnContentUtf8);
        std::string line;

        while (std::getline(iss, line))
        {
            line = Trim(line);
            if (line.empty())
                continue;

            if (line[0] == '#' || line[0] == ';')
                continue;

            std::istringstream ls(line);
            std::string key;
            ls >> key;
            if (ToLower(key) != "remote")
                continue;

            std::string host;
            ls >> host;
            if (host.empty())
                continue;

            OvpnRemote remote;
            remote.host = std::move(host);
            remote.port = kOpenVpnDefaultRemotePort;

            std::string t2;
            std::string t3;
            ls >> t2 >> t3;

            if (!t2.empty())
            {
                if (IsAllDigits(t2))
                {
                    uint16_t parsed = 0;
                    if (TryParsePort(t2, parsed))
                        remote.port = parsed;
                    // else keep OpenVPN default (invalid / 0 / overflow)

                    if (!t3.empty() && !IsAllDigits(t3))
                        remote.proto = ToLower(t3);
                }
                else
                {
                    remote.proto = ToLower(t2);
                }
            }

            out = std::move(remote);
            return true;
        }

        return false;
    }

    std::vector<std::string> TryGetDnsServersFromOvpn(const std::string& ovpnContentUtf8)
    {
        std::vector<std::string> servers;
        std::istringstream iss(ovpnContentUtf8);
        std::string line;

        while (std::getline(iss, line))
        {
            line = Trim(line);
            if (line.empty() || line[0] == '#' || line[0] == ';')
                continue;

            auto lower = ToLower(line);
            std::istringstream ls(lower);
            std::string a, b, c;
            ls >> a >> b >> c;
            if (a == "dhcp-option" && b == "dns" && !c.empty())
                servers.push_back(c);
        }

        return servers;
    }

    bool IsUdpProto(const std::string& proto)
    {
        const auto p = ToLower(proto);
        if (p.empty())
            return true; // OpenVPN default transport is UDP

        return p == "udp" || p == "udp4" || p == "udp6";
    }

    std::string ResolveTransportProto(const std::string& ovpnContentUtf8)
    {
        OvpnRemote remote;
        if (TryGetFirstRemoteFromOvpn(ovpnContentUtf8, remote) && !remote.proto.empty())
            return remote.proto;

        const auto globalProto = TryGetProtoFromOvpn(ovpnContentUtf8);
        if (!globalProto.empty())
            return globalProto;

        return "udp";
    }

    std::string AppendQueryParam(std::string path, const char* key, const char* value)
    {
        if (path.empty())
            path = "/";

        const std::string needle = std::string(key) + "=";
        if (path.find(needle) != std::string::npos)
            return path;

        if (path.find('?') == std::string::npos)
            path += "?";
        else if (path.back() != '?' && path.back() != '&')
            path += "&";

        path += key;
        path += "=";
        path += value;
        return path;
    }
}
