#include "XrayConfigBuilder.h"

#include <json/json.h>

#include <algorithm>
#include <cctype>
#include <memory>
#include <sstream>

namespace datagate::xray
{
    namespace
    {
        constexpr int kDirectBypassCidrsPerRule = 250;
        constexpr int kDefaultMuxConcurrency = 8;
        constexpr int kDefaultMuxXudpConcurrency = 16;

        Json::Value PrivateDirectIps()
        {
            static const char* kCidrs[] = {
                "0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16",
                "172.16.0.0/12", "192.0.0.0/24", "192.0.2.0/24", "192.168.0.0/16", "198.18.0.0/15",
                "198.51.100.0/24", "203.0.113.0/24", "224.0.0.0/4", "240.0.0.0/4", "255.255.255.255/32",
                "::/128", "::1/128", "fc00::/7", "fe80::/10", "ff00::/8",
            };
            Json::Value arr(Json::arrayValue);
            for (const char* c : kCidrs)
                arr.append(c);
            return arr;
        }

        bool ParseJson(const std::string& s, Json::Value& out, std::string& err)
        {
            Json::CharReaderBuilder b;
            std::unique_ptr<Json::CharReader> reader(b.newCharReader());
            return reader->parse(s.data(), s.data() + s.size(), &out, &err);
        }

        std::string Trim(std::string s)
        {
            while (!s.empty() && std::isspace(static_cast<unsigned char>(s.front())))
                s.erase(s.begin());
            while (!s.empty() && std::isspace(static_cast<unsigned char>(s.back())))
                s.pop_back();
            return s;
        }

        std::string ToLower(std::string s)
        {
            std::transform(s.begin(), s.end(), s.begin(),
                           [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
            return s;
        }

        bool LooksLikeIpLiteral(const std::string& host)
        {
            if (host.empty())
                return false;
            // IPv4
            int dots = 0;
            bool allDigitsDots = true;
            for (char c : host)
            {
                if (c == '.')
                    ++dots;
                else if (!std::isdigit(static_cast<unsigned char>(c)))
                {
                    allDigitsDots = false;
                    break;
                }
            }
            if (allDigitsDots && dots == 3)
                return true;
            // crude IPv6
            return host.find(':') != std::string::npos;
        }

        void SanitizeOutbounds(Json::Value& outbounds)
        {
            if (!outbounds.isArray())
                return;
            for (auto& ob : outbounds)
            {
                if (ob.isObject() && ob.isMember("sendThrough"))
                    ob.removeMember("sendThrough");
            }
        }

        bool ExtractOutbounds(const std::string& raw, Json::Value& outbounds, std::string& err)
        {
            Json::Value root;
            if (!ParseJson(raw, root, err))
                return false;

            if (root.isArray())
            {
                outbounds = root;
                return true;
            }
            if (root.isObject())
            {
                if (root.isMember("outbounds") && root["outbounds"].isArray())
                {
                    outbounds = root["outbounds"];
                    return true;
                }
                if (root.isMember("OutboundConfigs") && root["OutboundConfigs"].isArray())
                {
                    outbounds = root["OutboundConfigs"];
                    return true;
                }
            }
            err = "Config has no outbounds";
            return false;
        }

        bool TryReadInt(const Json::Value& v, int& out)
        {
            if (v.isInt())
            {
                out = v.asInt();
                return true;
            }
            if (v.isUInt())
            {
                out = static_cast<int>(v.asUInt());
                return true;
            }
            if (v.isString())
            {
                try
                {
                    out = std::stoi(v.asString());
                    return true;
                }
                catch (...)
                {
                    return false;
                }
            }
            return false;
        }

        bool NormalizeMux(const std::string& raw, Json::Value& outMux)
        {
            const auto trimmed = Trim(raw);
            if (trimmed.empty() || trimmed.front() != '{')
                return false;
            Json::Value root;
            std::string err;
            if (!ParseJson(trimmed, root, err) || !root.isObject() || !root.isMember("mux"))
                return false;
            const auto& mux = root["mux"];
            if (!mux.isObject())
                return false;
            if (mux.isMember("enabled") && mux["enabled"].isBool() && !mux["enabled"].asBool())
                return false;

            int concurrency = kDefaultMuxConcurrency;
            if (mux.isMember("concurrency"))
            {
                int n = 0;
                if (TryReadInt(mux["concurrency"], n) && n >= 1 && n <= 128)
                    concurrency = n;
            }
            int xudp = kDefaultMuxXudpConcurrency;
            if (mux.isMember("xudpConcurrency"))
            {
                int n = 0;
                if (TryReadInt(mux["xudpConcurrency"], n) && n >= 1 && n <= 1024)
                    xudp = n;
            }
            std::string xudp443 = "reject";
            if (mux.isMember("xudpProxyUDP443") && mux["xudpProxyUDP443"].isString())
            {
                const auto s = ToLower(mux["xudpProxyUDP443"].asString());
                if (s == "reject" || s == "allow" || s == "skip")
                    xudp443 = s;
            }

            outMux = Json::Value(Json::objectValue);
            outMux["enabled"] = true;
            outMux["concurrency"] = concurrency;
            outMux["xudpConcurrency"] = xudp;
            outMux["xudpProxyUDP443"] = xudp443;
            return true;
        }

        void AppendDirectBypassRules(Json::Value& rules, const std::vector<std::string>& cidrs)
        {
            std::vector<std::string> cleaned;
            for (const auto& c : cidrs)
            {
                auto t = Trim(c);
                if (t.empty())
                    continue;
                if (std::find(cleaned.begin(), cleaned.end(), t) == cleaned.end())
                    cleaned.push_back(t);
            }
            for (size_t i = 0; i < cleaned.size(); i += kDirectBypassCidrsPerRule)
            {
                Json::Value ips(Json::arrayValue);
                const size_t end = std::min(cleaned.size(), i + static_cast<size_t>(kDirectBypassCidrsPerRule));
                for (size_t j = i; j < end; ++j)
                    ips.append(cleaned[j]);
                Json::Value rule(Json::objectValue);
                rule["type"] = "field";
                rule["outboundTag"] = "direct";
                rule["ip"] = ips;
                rules.append(rule);
            }
        }

        void AppendProxyDnsRules(Json::Value& rules, const std::string& proxyTag,
                                 const std::vector<std::string>& dnsServers)
        {
            Json::Value ips(Json::arrayValue);
            for (const auto& s : dnsServers)
            {
                auto t = Trim(s);
                if (t.empty())
                    continue;
                if (t.find('/') == std::string::npos)
                    t += "/32";
                ips.append(t);
            }
            if (ips.empty())
                return;
            Json::Value rule(Json::objectValue);
            rule["type"] = "field";
            rule["outboundTag"] = proxyTag;
            rule["ip"] = ips;
            rules.append(rule);
        }

        void CollectHostsFromOutbounds(const Json::Value& outbounds, std::vector<std::string>& outCidrs)
        {
            if (!outbounds.isArray())
                return;
            auto addHost = [&](const std::string& hostRaw)
            {
                auto host = Trim(hostRaw);
                if (!host.empty() && host.front() == '[')
                    host.erase(host.begin());
                if (!host.empty() && host.back() == ']')
                    host.pop_back();
                if (!LooksLikeIpLiteral(host))
                    return;
                const std::string cidr = host.find(':') != std::string::npos ? host + "/128" : host + "/32";
                if (std::find(outCidrs.begin(), outCidrs.end(), cidr) == outCidrs.end())
                    outCidrs.push_back(cidr);
            };

            for (const auto& ob : outbounds)
            {
                if (!ob.isObject())
                    continue;
                const auto protocol = ToLower(ob.get("protocol", "").asString());
                if (protocol == "freedom" || protocol == "blackhole" || protocol == "dns" || protocol == "loopback")
                    continue;
                const auto& settings = ob["settings"];
                if (!settings.isObject())
                    continue;
                if (settings.isMember("vnext") && settings["vnext"].isArray())
                {
                    for (const auto& n : settings["vnext"])
                        if (n.isObject())
                            addHost(n.get("address", "").asString());
                }
                if (settings.isMember("servers") && settings["servers"].isArray())
                {
                    for (const auto& s : settings["servers"])
                        if (s.isObject())
                            addHost(s.get("address", "").asString());
                }
            }
        }
    }

    std::string XrayConfigBuilder::ExtractShareLinkOrEmpty(const std::string& text)
    {
        const auto trimmed = Trim(text);
        if (trimmed.empty())
            return {};

        if (trimmed.front() == '{')
        {
            Json::Value root;
            std::string err;
            if (ParseJson(trimmed, root, err) && root.isObject())
            {
                const auto vless = Trim(root.get("vless", "").asString());
                if (vless.size() >= 8 && ToLower(vless.substr(0, 8)) == "vless://")
                    return vless;
            }
        }

        std::string normalized = trimmed;
        for (char& c : normalized)
            if (c == '\r')
                c = '\n';

        std::istringstream iss(normalized);
        std::string line;
        while (std::getline(iss, line))
        {
            line = Trim(line);
            if (line.empty() || line.front() == '#')
                continue;
            const auto lower = ToLower(line);
            if (lower.rfind("vless://", 0) == 0
                || lower.rfind("vmess://", 0) == 0
                || lower.rfind("trojan://", 0) == 0
                || lower.rfind("ss://", 0) == 0
                || lower.rfind("hy2://", 0) == 0
                || lower.rfind("hysteria2://", 0) == 0)
                return line;
        }
        return {};
    }

    std::vector<std::string> XrayConfigBuilder::CollectProxyEndpointCidrs(const std::string& outboundsOrConfigJson)
    {
        Json::Value outbounds;
        std::string err;
        if (!ExtractOutbounds(outboundsOrConfigJson, outbounds, err))
            return {};
        std::vector<std::string> cidrs;
        CollectHostsFromOutbounds(outbounds, cidrs);
        return cidrs;
    }

    bool XrayConfigBuilder::BuildWindowsTunClientConfig(
        const std::string& outboundsOrConfigJson,
        std::string& fullConfigJson,
        std::string& outError,
        const std::vector<std::string>& directBypassCidrs,
        const std::vector<std::string>& tunnelDnsServers,
        int mtu)
    {
        Json::Value outbounds;
        if (!ExtractOutbounds(outboundsOrConfigJson, outbounds, outError))
            return false;
        if (!outbounds.isArray() || outbounds.empty())
        {
            outError = "No Xray outbounds in config";
            return false;
        }

        SanitizeOutbounds(outbounds);

        auto& first = outbounds[0];
        if (!first.isMember("tag") || first["tag"].asString().empty())
            first["tag"] = "proxy";
        const std::string proxyTag = first["tag"].asString();

        Json::Value mux;
        if (NormalizeMux(outboundsOrConfigJson, mux))
            first["mux"] = mux;

        bool hasDirect = false;
        bool hasBlock = false;
        for (const auto& ob : outbounds)
        {
            const auto tag = ob.get("tag", "").asString();
            if (tag == "direct") hasDirect = true;
            if (tag == "block") hasBlock = true;
        }
        if (!hasDirect)
        {
            Json::Value direct(Json::objectValue);
            direct["tag"] = "direct";
            direct["protocol"] = "freedom";
            direct["settings"] = Json::Value(Json::objectValue);
            outbounds.append(direct);
        }
        if (!hasBlock)
        {
            Json::Value block(Json::objectValue);
            block["tag"] = "block";
            block["protocol"] = "blackhole";
            block["settings"] = Json::Value(Json::objectValue);
            outbounds.append(block);
        }

        Json::Value tunSettings(Json::objectValue);
        tunSettings["mtu"] = mtu;
        tunSettings["name"] = "xray0";
        tunSettings["stack"] = "system";
        // Windows: without these, TUN comes up but default route stays on Ethernet —
        // browser traffic never enters Xray (Android VpnService sets routes itself).
        {
            Json::Value gateway(Json::arrayValue);
            gateway.append("172.19.0.1/30");
            tunSettings["gateway"] = gateway;
            Json::Value dns(Json::arrayValue);
            std::vector<std::string> dnsForTun = tunnelDnsServers;
            if (dnsForTun.empty())
            {
                dnsForTun.push_back("1.1.1.1");
                dnsForTun.push_back("8.8.8.8");
            }
            for (const auto& d : dnsForTun)
                if (!Trim(d).empty())
                    dns.append(Trim(d));
            tunSettings["dns"] = dns;
            Json::Value routes(Json::arrayValue);
            routes.append("0.0.0.0/0");
            tunSettings["autoSystemRoutingTable"] = routes;
            tunSettings["autoOutboundsInterface"] = "auto";
        }

        Json::Value sniffing(Json::objectValue);
        sniffing["enabled"] = true;
        sniffing["destOverride"] = Json::Value(Json::arrayValue);
        sniffing["destOverride"].append("http");
        sniffing["destOverride"].append("tls");
        sniffing["destOverride"].append("quic");

        Json::Value tunInbound(Json::objectValue);
        tunInbound["tag"] = "tun-in";
        tunInbound["protocol"] = "tun";
        tunInbound["settings"] = tunSettings;
        tunInbound["sniffing"] = sniffing;

        Json::Value rules(Json::arrayValue);
        {
            // Windows APIPA NetBIOS floods TUN; drop before private-direct / catch-all.
            Json::Value netbios(Json::objectValue);
            netbios["type"] = "field";
            netbios["outboundTag"] = "block";
            netbios["port"] = "137,138,139";
            netbios["network"] = "udp";
            rules.append(netbios);
        }
        {
            std::vector<std::string> dnsForRules = tunnelDnsServers;
            if (dnsForRules.empty())
            {
                dnsForRules.push_back("1.1.1.1");
                dnsForRules.push_back("8.8.8.8");
            }
            AppendProxyDnsRules(rules, proxyTag, dnsForRules);
        }
        {
            Json::Value privateRule(Json::objectValue);
            privateRule["type"] = "field";
            privateRule["outboundTag"] = "direct";
            privateRule["ip"] = PrivateDirectIps();
            rules.append(privateRule);
        }

        std::vector<std::string> bypass = directBypassCidrs;
        CollectHostsFromOutbounds(outbounds, bypass);
        AppendDirectBypassRules(rules, bypass);

        {
            Json::Value catchAll(Json::objectValue);
            catchAll["type"] = "field";
            catchAll["outboundTag"] = proxyTag;
            catchAll["network"] = "tcp,udp";
            rules.append(catchAll);
        }

        Json::Value routing(Json::objectValue);
        routing["domainStrategy"] = "AsIs";
        routing["rules"] = rules;

        Json::Value root(Json::objectValue);
        root["log"] = Json::Value(Json::objectValue);
        root["log"]["loglevel"] = "warning";
        // Access log floods UI with Windows NetBIOS / link-local chatter on TUN.
        root["log"]["access"] = "none";
        root["inbounds"] = Json::Value(Json::arrayValue);
        root["inbounds"].append(tunInbound);
        root["outbounds"] = outbounds;
        root["routing"] = routing;

        Json::StreamWriterBuilder wb;
        wb["indentation"] = "";
        fullConfigJson = Json::writeString(wb, root);
        return true;
    }
}
