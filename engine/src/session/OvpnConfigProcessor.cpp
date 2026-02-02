#include "OvpnConfigProcessor.h"

#include <algorithm>
#include <cstring>
#include <sstream>

namespace datagate::session
{
    bool OvpnConfigProcessor::StartsWithTokenTrimLeft(const std::string& line, const char* token)
    {
        size_t i = 0;
        while (i < line.size() && (line[i] == ' ' || line[i] == '\t'))
            i++;

        const size_t n = std::strlen(token);
        if (line.size() < i + n)
            return false;

        if (line.compare(i, n, token) != 0)
            return false;

        if (line.size() == i + n)
            return true;

        const char c = line[i + n];
        return c == ' ' || c == '\t';
    }

    std::string OvpnConfigProcessor::PatchOvpnRemoteToLocal(
        const std::string& ovpn,
        const std::string& localHost,
        uint16_t localPort)
    {
        std::string patched;
        patched.reserve(ovpn.size() + 128);

        patched += "remote ";
        patched += localHost;
        patched += " ";
        patched += std::to_string(localPort);
        patched += "\n";

        size_t start = 0;
        while (start < ovpn.size())
        {
            size_t end = ovpn.find('\n', start);
            if (end == std::string::npos)
                end = ovpn.size();

            std::string line = ovpn.substr(start, end - start);
            if (!line.empty() && line.back() == '\r')
                line.pop_back();

            if (!StartsWithTokenTrimLeft(line, "remote"))
            {
                patched += line;
                patched += "\n";
            }

            start = (end < ovpn.size()) ? (end + 1) : end;
        }

        return patched;
    }

    std::string OvpnConfigProcessor::PrependWindowsDriverWintun(const std::string& ovpn)
    {
        std::string out;
        out.reserve(ovpn.size() + 64);
        out += "windows-driver wintun\n";
        out += ovpn;
        return out;
    }

    std::string OvpnConfigProcessor::FirstLines(const std::string& s, size_t maxLines, size_t maxChars)
    {
        std::string out;
        out.reserve(std::min(maxChars, s.size()));

        size_t lines = 0;
        for (size_t i = 0; i < s.size() && out.size() < maxChars; ++i)
        {
            const char c = s[i];
            out.push_back(c);
            if (c == '\n')
            {
                ++lines;
                if (lines >= maxLines)
                    break;
            }
        }
        return out;
    }

    std::string OvpnConfigProcessor::ExtractLinesWithPrefix(const std::string& s, const char* prefix, size_t maxHits)
    {
        std::istringstream iss(s);
        std::string line;
        std::ostringstream out;

        size_t hits = 0;
        while (std::getline(iss, line))
        {
            if (line.rfind(prefix, 0) == 0)
            {
                out << line << "\n";
                if (++hits >= maxHits)
                    break;
            }
        }
        return out.str();
    }

    int OvpnConfigProcessor::CountRemoteLines(const std::string& s)
    {
        int count = 0;

        std::istringstream iss(s);
        std::string line;
        while (std::getline(iss, line))
        {
            if (!line.empty() && line.back() == '\r')
                line.pop_back();

            if (StartsWithTokenTrimLeft(line, "remote"))
                count++;
        }

        return count;
    }

    bool OvpnConfigProcessor::Contains(const std::string& s, const char* needle)
    {
        return s.find(needle) != std::string::npos;
    }

    OvpnDiagnostics OvpnConfigProcessor::BuildDiagnostics(const std::string& ovpn)
    {
        OvpnDiagnostics d{};
        d.bytes = ovpn.size();

        d.hasCa = Contains(ovpn, "<ca>");
        d.hasCert = Contains(ovpn, "<cert>");
        d.hasKey = Contains(ovpn, "<key>");
        d.hasTlsCrypt = Contains(ovpn, "<tls-crypt>");

        d.previewFirstLines = FirstLines(ovpn, 40, 2000);
        d.windowsDriverLines = ExtractLinesWithPrefix(ovpn, "windows-driver", 8);
        d.devLines = ExtractLinesWithPrefix(ovpn, "dev", 8);

        return d;
    }

    OvpnBuildResult OvpnConfigProcessor::BuildForLocalBridge(
        const std::string& ovpnContentUtf8,
        const std::string& localHost,
        uint16_t localPort)
    {
        OvpnBuildResult r{};
        r.config = PatchOvpnRemoteToLocal(ovpnContentUtf8, localHost, localPort);
        r.config = PrependWindowsDriverWintun(r.config);
        r.diag = BuildDiagnostics(r.config);
        return r;
    }

    bool OvpnConfigProcessor::ValidateSingleRemote(const std::string& ovpn, std::string& outError)
    {
        const int n = CountRemoteLines(ovpn);
        if (n != 1)
        {
            outError = "WSS mode requires exactly one remote (127.0.0.1).";
            return false;
        }
        return true;
    }
}