#pragma once

#include <cstdint>
#include <functional>
#include <memory>
#include <string>

namespace datagate::session
{
    struct StartOptions;

    class BridgeManager
    {
    public:
        using LogCallback = std::function<void(const std::string&)>;

        BridgeManager();
        ~BridgeManager();

        void SetLog(LogCallback cb);

        bool Activate(const StartOptions& opt, std::string& outError);
        void Deactivate();

        void Stop();

        bool IsRunning() const;

        std::string ListenIp() const;
        uint16_t ListenPort() const;

    private:
        static std::string DefaultListenIp(const StartOptions& opt);
        static uint16_t DefaultListenPort(const StartOptions& opt);

        struct Impl;
        std::unique_ptr<Impl> _impl;
    };
}
