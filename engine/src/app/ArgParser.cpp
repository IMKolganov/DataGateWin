#include "ArgParser.h"

#include <string>

std::string ArgParser::GetValue(int argc, char** argv, const char* key)
{
    for (int i = 1; i < argc; i++)
    {
        if (std::string(argv[i]) == key && i + 1 < argc)
            return argv[i + 1];
    }
    return {};
}
