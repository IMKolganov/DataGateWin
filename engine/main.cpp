#include "AppMain.h"

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
        std::cerr << "openvpn::Exception: " << e.what() << std::endl;
        return 10;
    }
    catch (const std::exception& e)
    {
        std::cerr << "std::exception: " << e.what() << std::endl;
        return 11;
    }
}
