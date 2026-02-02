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
                return v;
            }
        }

        return "";
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