# DataGate for Windows — release 1.0.7

## Summary

Fixes **stale DNS after VPN disconnect, reboot, or crash** on Windows. Improves **graceful shutdown**, **uninstall reliability**, and **Apps & Features** registration. App, engine, and installer versions are aligned at **1.0.7**.

---

## For users

- **DNS recovery**: removes leftover OpenVPN NRPT rules and flushes the DNS cache on engine startup and during uninstall — fixes “no internet after reboot while VPN was connected”.
- **Graceful exit**: the UI stops the VPN session cleanly before closing instead of killing the engine abruptly.
- **Installer / uninstall**: uninstall from Windows Settings now points at the installer inside `Program Files`; legacy `DataGate OpenVPN 3` registry entries are migrated to **DataGate** with the correct icon.
- **openvpn3** core updated (fmt 12, OpenSSL cleanup, test hooks).

---

## Artifacts

- **DataGateWin.v1.0.7.zip** — full portable build (app + engine + bundled installer).
- **DataGateWin.Installer.exe** — standalone installer executable.

Install .NET 10 Desktop Runtime if prompted. Run the installer as administrator.

---

## Upgrade from 1.0.6

Run the new installer or extract the ZIP and use `Installer\DataGateWin.Installer.exe`. Updating refreshes registry entries and uninstall shortcuts.

If uninstall from Settings fails on an old install, run:

`"C:\Program Files\DataGate\Installer\DataGateWin.Installer.exe" --uninstall`
