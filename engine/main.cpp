#include "AppMain.h"

#include "src/app/CrashReporter.h"

#include <iostream>
#include <openvpn/common/exception.hpp>

int main(int argc, char** argv)
{
    try
    {
        AppMain app;
        return app.Run(argc, argv);
    }
    catch (const openvpn::Exception& e)
    {
        CrashReporter::ReportFatal("openvpn::Exception", e.what());
        std::cerr << "openvpn::Exception: " << e.what() << std::endl;
        return 10;
    }
    catch (const std::exception& e)
    {
        CrashReporter::ReportFatal("std::exception", e.what());
        std::cerr << "std::exception: " << e.what() << std::endl;
        return 11;
    }
    catch (...)
    {
        CrashReporter::ReportFatal("unknown", "Unknown native exception escaped engine main");
        std::cerr << "unknown exception" << std::endl;
        return 12;
    }
}
