<p align="center">
  <img src="assets/logo.png" width="120" alt="DataGate" />
</p>

<h1 align="center">DataGate</h1>
<p align="center"><strong>Windows 🪟 VPN client — OpenVPN over WebSocket Secure (WSS)</strong></p>

<p align="center">
  <img src="https://img.shields.io/badge/platform-Windows%2010%2F11-0078d6?logo=windows" alt="Windows 10/11" />
  <img src="https://img.shields.io/badge/C%2B%2B-OpenVPN3-green" alt="OpenVPN3" />
  <img src="https://img.shields.io/badge/OpenVPN-WSS-blue" alt="OpenVPN over WSS" />
</p>

---

## What is this?

**DataGate** is a native Windows desktop app that connects to your VPN backend and establishes an **OpenVPN** tunnel. Traffic can be carried over **WebSocket Secure (WSS)** from the machine to your server, which forwards it to the real OpenVPN server — so you can run OpenVPN behind HTTPS/WSS (e.g. nginx) and avoid direct UDP/TCP to the VPN port.

- **UI (WPF)** handles Connect/Disconnect, status, settings, and logs; starts the Engine and attaches via IPC.
- **Engine (native)** is the single source of truth for VPN state: tunnel (Wintun), routes, DNS, OpenVPN3 core.

Details: [Architecture (UI ↔ Engine IPC)](ARCHITECTURE.md).

## Features

| Feature | Description |
|--------|-------------|
| **OpenVPN over WSS** | Tunnel traffic over WebSocket Secure; no direct VPN port exposure. |
| **WPF UI** | System tray, Connect/Disconnect, status, logs, and settings. |
| **Engine process** | Separate native process; UI and tunnel lifecycle are independent (restart-safe). |
| **Wintun** | Uses Wintun driver for the VPN interface. |

## Requirements

- **Windows 10 or 11**
- **Visual Studio 2022** (or compatible) with C++ and .NET workloads
- **CMake** (for OpenVPN3 / native build)
- **Wintun** driver (see `drivers/wintun`)

## Setup

### 1. Clone

```bash
git clone <repo-url>
cd DataGateWin
```

### 2. Submodules and drivers

Initialize submodules and ensure Wintun is available (see `drivers/wintun/README.md`).

### 3. Build

Build the solution (e.g. in Visual Studio) or use the project’s build scripts. The result includes the **UI** app and the **Engine** native process; the installer (in `DataGateWin.Installer`) can package them for distribution.

## Project layout

| Path | Description |
|------|-------------|
| **DataGateWin.UI/** | WPF application (UI, IPC client). |
| **engine/** | Native Engine process (OpenVPN3, WSS bridge, Wintun). |
| **openvpn3/** | OpenVPN3 core (submodule or vendored). |
| **drivers/** | Wintun and related drivers. |
| **DataGateWin.Installer/** | WPF installer (download release ZIP, install, shortcuts). |
| **assets/** | Logo and images for the repo (e.g. README). |

## License

See `LICENSE.md`.
