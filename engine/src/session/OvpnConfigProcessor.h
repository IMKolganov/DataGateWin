#pragma once

#include "SessionController.h"

#include <cstdint>
#include <string>

namespace datagate::session
{
    struct OvpnDiagnostics
    {
        size_t bytes = 0;

        bool hasCa = false;
        bool hasCert = false;
        bool hasKey = false;
        bool hasTlsCrypt = false;

        std::string previewFirstLines;
        std::string windowsDriverLines;
        std::string devLines;
    };

    struct OvpnBuildResult
    {
        std::string config;
        OvpnDiagnostics diag;
    };

    class OvpnConfigProcessor
    {
    public:
        OvpnBuildResult BuildForLocalBridge(
            const std::string& ovpnContentUtf8,
            const std::string& localHost,
            uint16_t localPort);

        // Validates that patched config contains exactly 1 "remote" line.
        bool ValidateSingleRemote(const std::string& ovpn, std::string& outError);

    private:
        static bool StartsWithTokenTrimLeft(const std::string& line, const char* token);

        static std::string PatchOvpnRemoteToLocal(
            const std::string& ovpn,
            const std::string& localHost,
            uint16_t localPort);

        static std::string PrependWindowsDriverWintun(const std::string& ovpn);

        static std::string FirstLines(const std::string& s, size_t maxLines, size_t maxChars);
        static std::string ExtractLinesWithPrefix(const std::string& s, const char* prefix, size_t maxHits);

        static int CountRemoteLines(const std::string& s);
        static bool Contains(const std::string& s, const char* needle);

        static OvpnDiagnostics BuildDiagnostics(const std::string& ovpn);
    };
}
