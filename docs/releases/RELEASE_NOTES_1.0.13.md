# DataGate for Windows — release 1.0.13

## Summary

Hardens **Windows DNS recovery**, improves the **UDP WSS bridge**, and shows clear **Home session identity** (server, VPN IP, external IP). Syncs **OpenVPN 3.11.7** with Android. App, engine, and installer versions are aligned at **1.0.13**.

---

## For users

- **Home**: after connect, footer shows server name, VPN tunnel IP, and external IP (not a bare “Connected” status).
- **Manual servers**: list loads automatically; only OpenVPN + WSS endpoints are offered.
- **DNS**: safer recovery after crash/kill (SearchList restore, Dnscache reload); installer/engine recovery paths aligned.
- **Connect reliability**: UDP WSS bridge fixes, shuffled local listen ports, loopback-only binds, OVPN proto forced to match the local bridge.
- **OpenVPN**: engine handshake / version string `3.11.7_datagate_windows_1.0.13` (aligned with Android tip).

---

## Artifacts

- **DataGateWin.v1.0.13.zip** — full portable build (app + engine + bundled installer).
- **DataGateWin.Installer.exe** — standalone installer executable.

Install .NET 10 Desktop Runtime if prompted. Run the installer as administrator.

---

## Upgrade from 1.0.12

Run the new installer or extract the ZIP and use `Installer\DataGateWin.Installer.exe`.

If the in-app updater does not appear, download the installer from the release page and run it manually.
