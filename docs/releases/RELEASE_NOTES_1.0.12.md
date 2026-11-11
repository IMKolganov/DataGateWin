# DataGate for Windows — release 1.0.12

## Summary

Fixes **duplicate VPN servers** in Access (dual JSON keys from v3 API) and restores the **DataGate** product name in Windows Search / Start Menu after updates. App, engine, and installer versions are aligned at **1.0.12**.

---

## For users

- **Access / Connect**: deduplicates server list when API returns both `vpnServerWithStatuses` and legacy `openVpnServerWithStatuses`.
- **Start Menu name**: updates now refresh shortcuts and remove old **DataGate OpenVPN 3** entries; app metadata shows **DataGate**.
- **Regression tests**: include a live v3 API JSON fixture.

---

## Artifacts

- **DataGateWin.v1.0.12.zip** — full portable build (app + engine + bundled installer).
- **DataGateWin.Installer.exe** — standalone installer executable.

Install .NET 10 Desktop Runtime if prompted. Run the installer as administrator.

---

## Upgrade from 1.0.10 / 1.0.11

Run the new installer or extract the ZIP and use `Installer\DataGateWin.Installer.exe`.

If Start Menu still shows the old name, install 1.0.12 once — shortcuts are refreshed on update.

If the in-app updater does not appear, download the installer from the release page and run it manually.
