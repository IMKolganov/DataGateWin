#include "DatagateJsonLite.h"

#include <cctype>
#include <stdexcept>

namespace datagate::jsonlite
{
    static bool Hex4ToUInt16(const std::string& s, size_t pos, uint16_t& out)
    {
        if (pos + 4 > s.size()) return false;

        uint16_t v = 0;
        for (size_t i = 0; i < 4; i++)
        {
            const char c = s[pos + i];
            uint16_t n = 0;

            if (c >= '0' && c <= '9') n = (uint16_t)(c - '0');
            else if (c >= 'a' && c <= 'f') n = (uint16_t)(10 + (c - 'a'));
            else if (c >= 'A' && c <= 'F') n = (uint16_t)(10 + (c - 'A'));
            else return false;

            v = (uint16_t)((v << 4) | n);
        }

        out = v;
        return true;
    }

    static void AppendUtf8FromCodepoint(std::string& out, uint32_t cp)
    {
        char buf[4];
        int len = 0;

        if (cp <= 0x7F)
        {
            buf[0] = (char)cp;
            len = 1;
        }
        else if (cp <= 0x7FF)
        {
            buf[0] = (char)(0xC0 | ((cp >> 6) & 0x1F));
            buf[1] = (char)(0x80 | (cp & 0x3F));
            len = 2;
        }
        else if (cp <= 0xFFFF)
        {
            buf[0] = (char)(0xE0 | ((cp >> 12) & 0x0F));
            buf[1] = (char)(0x80 | ((cp >> 6) & 0x3F));
            buf[2] = (char)(0x80 | (cp & 0x3F));
            len = 3;
        }
        else
        {
            buf[0] = (char)(0xF0 | ((cp >> 18) & 0x07));
            buf[1] = (char)(0x80 | ((cp >> 12) & 0x3F));
            buf[2] = (char)(0x80 | ((cp >> 6) & 0x3F));
            buf[3] = (char)(0x80 | (cp & 0x3F));
            len = 4;
        }

        out.append(buf, buf + len);
    }

    std::string UnescapeJsonString(const std::string& s)
    {
        std::string out;
        out.reserve(s.size());

        for (size_t i = 0; i < s.size(); i++)
        {
            const char c = s[i];
            if (c != '\\')
            {
                out.push_back(c);
                continue;
            }

            if (i + 1 >= s.size())
                break;

            const char n = s[++i];

            switch (n)
            {
            case '\\': out.push_back('\\'); break;
            case '"':  out.push_back('"');  break;
            case 'n':  out.push_back('\n'); break;
            case 'r':  out.push_back('\r'); break;
            case 't':  out.push_back('\t'); break;

            case 'u':
            {
                // \uXXXX, possibly surrogate pair
                if (i + 4 >= s.size()) { out.push_back('?'); break; }

                uint16_t u1 = 0;
                if (!Hex4ToUInt16(s, i + 1, u1)) { out.push_back('?'); break; }
                i += 4;

                uint32_t cp = u1;

                // surrogate pair?
                if (u1 >= 0xD800 && u1 <= 0xDBFF)
                {
                    // expect \uXXXX
                    if (i + 6 < s.size() && s[i + 1] == '\\' && s[i + 2] == 'u')
                    {
                        uint16_t u2 = 0;
                        if (Hex4ToUInt16(s, i + 3, u2) && u2 >= 0xDC00 && u2 <= 0xDFFF)
                        {
                            i += 6; // consumed "\u" + 4 hex
                            cp = 0x10000 + (((uint32_t)(u1 - 0xD800) << 10) | (uint32_t)(u2 - 0xDC00));
                        }
                    }
                }

                AppendUtf8FromCodepoint(out, cp);
                break;
            }

            default:
                // Keep unknown escapes "as-is" to avoid silently losing data.
                out.push_back(n);
                break;
            }
        }

        return out;
    }

    bool TryGetStringField(const std::string& json, const char* field, std::string& outValue)
    {
        const std::string key = std::string("\"") + field + "\"";
        auto p = json.find(key);
        if (p == std::string::npos) return false;

        p = json.find(':', p);
        if (p == std::string::npos) return false;

        p = json.find('"', p);
        if (p == std::string::npos) return false;

        // Find closing quote with escape awareness
        auto e = p + 1;
        bool escaped = false;
        for (; e < json.size(); e++)
        {
            const char c = json[e];
            if (escaped) { escaped = false; continue; }
            if (c == '\\') { escaped = true; continue; }
            if (c == '"') break;
        }
        if (e >= json.size()) return false;

        outValue = json.substr(p + 1, e - (p + 1));
        outValue = UnescapeJsonString(outValue);
        return true;
    }

    bool TryGetBoolField(const std::string& json, const char* field, bool& outValue)
    {
        const std::string key = std::string("\"") + field + "\"";
        auto p = json.find(key);
        if (p == std::string::npos) return false;

        p = json.find(':', p);
        if (p == std::string::npos) return false;

        auto v = json.substr(p + 1);
        while (!v.empty() && std::isspace((unsigned char)v.front()))
            v.erase(v.begin());

        if (v.rfind("true", 0) == 0)  { outValue = true;  return true; }
        if (v.rfind("false", 0) == 0) { outValue = false; return true; }

        return false;
    }

    bool TryGetUInt16Field(const std::string& json, const char* field, uint16_t& outValue)
    {
        const std::string key = std::string("\"") + field + "\"";
        auto p = json.find(key);
        if (p == std::string::npos) return false;

        p = json.find(':', p);
        if (p == std::string::npos) return false;

        p++;
        while (p < json.size() && std::isspace((unsigned char)json[p]))
            p++;

        size_t e = p;
        while (e < json.size() && std::isdigit((unsigned char)json[e]))
            e++;

        if (e == p) return false;

        unsigned long v = std::stoul(json.substr(p, e - p));
        if (v > 65535) return false;

        outValue = (uint16_t)v;
        return true;
    }
}
