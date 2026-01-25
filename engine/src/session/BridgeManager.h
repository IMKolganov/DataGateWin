#pragma once

#include "SessionController.h"

#include <cstdint>
#include <memory>
#include <string>

namespace datagate::session
{
    class BridgeManager
    {
    public:
        BridgeManager();
        ~BridgeManager();

        BridgeManager(const BridgeManager&) = delete;
        BridgeManager& operator=(const BridgeManager&) = delete;

        bool Start(const StartOptions& opt, std::string& outError);
        void Stop();

        bool IsRunning() const;

        std::string ListenIp() const;
        uint16_t ListenPort() const;

        static std::string DefaultListenIp(const StartOptions& opt);
        static uint16_t DefaultListenPort(const StartOptions& opt);

    private:
        struct Impl;
        std::unique_ptr<Impl> _impl;
    };
}
