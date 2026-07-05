# DataGate for Windows — release 1.0.8

## Summary

Adds **Free/Default tier onboarding** (Telegram channel subscription or account link code). Migrates API contracts to **`DataGateMonitor.SharedModels` 1.0.40** and removes the legacy NuGet package. App, engine, and installer versions are aligned at **1.0.8**.

---

## For users

- **Free/Default onboarding**: after sign-in, users on the free plan see a guided flow to subscribe to the required Telegram channel or request a link code for `/link_account` in the bot.
- **Torrent warning**: detects common torrent clients while VPN is active and prompts the user to close them.
- **API contracts**: client updated for the renamed shared models package (no user-visible change except onboarding support).

---

## Artifacts

- **DataGateWin.v1.0.8.zip** — full portable build (app + engine + bundled installer).
- **DataGateWin.Installer.exe** — standalone installer executable.

Install .NET 10 Desktop Runtime if prompted. Run the installer as administrator.

---

## Upgrade from 1.0.7

Run the new installer or extract the ZIP and use `Installer\DataGateWin.Installer.exe`. Updating refreshes registry entries and uninstall shortcuts.
