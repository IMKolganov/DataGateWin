#pragma once

#include <string>

class CrashReporter
{
public:
    static void Install();
    static void ReportFatal(const std::string& exceptionName, const std::string& message);
    static void ReportNonFatal(const std::string& exceptionName, const std::string& message);
};
