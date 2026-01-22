#pragma once

#include <cstdint>
#include <string>

namespace datagate::jsonlite
{
    // Converts JSON string content (without surrounding quotes) into UTF-8:
    // supports: \\ \" \n \r \t and \uXXXX (including surrogate pairs)
    std::string UnescapeJsonString(const std::string& s);

    bool TryGetStringField(const std::string& json, const char* field, std::string& outValue);
    bool TryGetBoolField(const std::string& json, const char* field, bool& outValue);
    bool TryGetUInt16Field(const std::string& json, const char* field, uint16_t& outValue);
}
