#include <iostream>
#include <string>
#include <mutex>
#include <condition_variable>
#include <atomic>
#include <sstream>
#include <iomanip>
#include <stdexcept>

#include <eh.h>

#include <client/ovpncli.hpp>
#include <openvpn/common/file.hpp>
#include <openvpn/common/exception.hpp>

static void SehTranslator(unsigned int code, _EXCEPTION_POINTERS*)
{
    std::ostringstream oss;
    oss << "SEH exception 0x"
        << std::hex << std::uppercase << std::setw(8) << std::setfill('0')
        << code;
    throw std::runtime_error(oss.str());
}


class MyClient : public openvpn::ClientAPI::OpenVPNClient {
public:
    std::mutex mtx;
    std::condition_variable cv;
    std::atomic<bool> done{false};
    bool connected = false;
    std::string last_event_name;
    std::string last_event_info;

    bool pause_on_connection_timeout() override { return false; }

    void event(const openvpn::ClientAPI::Event& ev) override {
        {
            std::lock_guard<std::mutex> lock(mtx);
            last_event_name = ev.name;
            last_event_info = ev.info;

            std::cout << "[event] name=" << ev.name << " info=" << ev.info << std::endl;

            if (ev.name == "CONNECTED") {
                connected = true;
                done = true;
            }
            if (ev.name == "DISCONNECTED" || ev.name == "AUTH_FAILED") {
                connected = false;
                done = true;
            }
        }
        cv.notify_all();
    }

    void acc_event(const openvpn::ClientAPI::AppCustomControlMessageEvent& /*ev*/) override {
        std::cout << "[acc_event]" << std::endl;
    }

    void log(const openvpn::ClientAPI::LogInfo& log) override {
        std::cout << "[log] " << log.text << std::endl;
    }

    void external_pki_cert_request(openvpn::ClientAPI::ExternalPKICertRequest& req) override { (void)req; }
    void external_pki_sign_request(openvpn::ClientAPI::ExternalPKISignRequest& req) override { (void)req; }
};

int main() {
    _set_se_translator(SehTranslator);

    try {
        const char* ovpnPath = "F:\\C++\\DataGateWin\\ovpnfiles\\win-test-udp-0.ovpn";
        std::cout << "ovpnPath: " << ovpnPath << std::endl;

        MyClient client;

        openvpn::ClientAPI::Config cfg;
        cfg.content = openvpn::read_text_utf8(ovpnPath);

        auto eval = client.eval_config(cfg);
        std::cout << "eval.error: " << eval.error << std::endl;
        std::cout << "eval.message: " << eval.message << std::endl;
        std::cout << "eval.windowsDriver: " << eval.windowsDriver << std::endl;

        if (eval.error) {
            std::cerr << "Config evaluation failed" << std::endl;
            return 2;
        }

        std::cout << "Connecting..." << std::endl;

        auto status = client.connect();
        std::cout << "connect() error: " << status.error
                  << " status: " << status.status
                  << " message: " << status.message << std::endl;

        {
            std::unique_lock<std::mutex> lock(client.mtx);
            client.cv.wait(lock, [&] { return client.done.load(); });
        }

        if (client.connected) {
            std::cout << "Connected successfully." << std::endl;
            std::cout << "Press Enter to disconnect..." << std::endl;
            std::string line;
            std::getline(std::cin, line);

            client.stop();
            std::cout << "stop() called" << std::endl;
        } else {
            std::cout << "Not connected. Last event: " << client.last_event_name
                      << " info: " << client.last_event_info << std::endl;
            return 3;
        }

        return 0;
    }
    catch (const openvpn::Exception& e) {
        std::cerr << "openvpn::Exception: " << e.what() << std::endl;
        return 10;
    }
    catch (const std::system_error& e) {
        std::cerr << "std::system_error: " << e.what()
                  << " | code=" << e.code().value()
                  << " category=" << e.code().category().name()
                  << " message=" << e.code().message()
                  << std::endl;
        return 13;
    }
    catch (const std::exception& e) {
        std::cerr << "std::exception: " << e.what() << std::endl;
        return 11;
    }
    catch (...) {
        std::cerr << "unknown non-std exception" << std::endl;
        return 12;
    }
}
