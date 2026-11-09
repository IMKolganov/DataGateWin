# DataGate for Windows — release 1.0.11

## Summary

Polishes **Access** and **Connect** after the v3 VPN fix (1.0.10). App, engine, and installer versions are aligned at **1.0.11**.

---

## For users

- **Access tab**: shows WSS-capable servers only (hides xray/non-WSS rows irrelevant to Windows).
- **Plan name**: falls back to the v3 API `userQuotaPlan` when the quota assignment API has no active plan row.
- **Connect**: stops endless reconnect when no eligible WSS servers are available.

---

## Artifacts

- **DataGateWin.v1.0.11.zip** — full portable build (app + engine + bundled installer).
- **DataGateWin.Installer.exe** — standalone installer executable.

Install .NET 10 Desktop Runtime if prompted. Run the installer as administrator.

---

## Upgrade from 1.0.10

Run the new installer or extract the ZIP and use `Installer\DataGateWin.Installer.exe`.

If the in-app updater does not appear, download the installer from the release page and run it manually.
