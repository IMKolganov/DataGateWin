# DataGate for Windows — release 1.0.10

## Summary

Fixes **VPN server list** after the SharedModels migration (1.0.8). The client now uses the **v3 backend API** for server status, restoring WSS server selection for paid and free plans. App, engine, and installer versions are aligned at **1.0.10**.

---

## For users

- **VPN connect works again**: server list is fetched from `api/v3/open-vpn-servers/get-all-with-status` with correct JSON mapping and per-plan access flags (`isAccessibleForUserQuotaPlan`).
- **Server picker & Access tab**: use the same v3 response; eligible WSS servers appear in the manual server dropdown again.

---

## Artifacts

- **DataGateWin.v1.0.10.zip** — full portable build (app + engine + bundled installer).
- **DataGateWin.Installer.exe** — standalone installer executable.

Install .NET 10 Desktop Runtime if prompted. Run the installer as administrator.

---

## Upgrade from 1.0.8 / 1.0.9

If VPN showed “no WSS servers” or failed to connect after login, update to **1.0.10**.

Run the new installer or extract the ZIP and use `Installer\DataGateWin.Installer.exe`.

If the in-app updater does not appear, download the installer from the release page and run it manually.
