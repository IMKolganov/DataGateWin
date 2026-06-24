#pragma once

#include <string>

class ArgParser
{
public:
    static std::string GetValue(int argc, char** argv, const char* key);
    static bool HasFlag(int argc, char** argv, const char* flag);
};
