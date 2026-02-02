#pragma once

#include <string>

namespace datagate::session::ovpn
{
    std::string TryGetProtoFromOvpn(const std::string& ovpnContentUtf8);
    std::string AppendQueryParam(std::string path, const char* key, const char* value);
}