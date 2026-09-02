#pragma once

#include <cstdint>

namespace datagate::session
{
    // OpenVPN default when `remote host` omits the port (openvpn man / remotelist).
    constexpr uint16_t kOpenVpnDefaultRemotePort = 1194;

    // Local WSS↔OpenVPN bridge on loopback (UI StartSession + engine IPC default).
    constexpr uint16_t kLocalBridgeDefaultListenPort = 18080;

    // If the preferred listen port is busy, try this many ports (preferred + shuffled pool).
    // Sized closer to Android's local-bridge port search breadth.
    constexpr uint16_t kLocalBridgeListenPortAttempts = 64;
}
