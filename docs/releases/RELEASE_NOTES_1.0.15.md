# DataGate for Windows — release 1.0.15

## Summary

Stability patch for the WinUI 3 client: Access no longer kills the process, crash reports still reach the backend, Home shows the connected server flag and can scroll to the engine log. App, engine, and installer versions are aligned at **1.0.15**.

---

## For users

- **Access**: opening the page after connect no longer crashes the app (WinUI UI-thread marshalling).
- **Crashes**: fatal errors are flushed to the crash ingest API before the process exits.
- **Home**: country flag on the connected server row (above VPN IP).
- **Home**: the page scrolls like Access / Settings; **Show engine log** is visible without maximizing the window.
- **Login**: Google sign-in cancel / permission errors show a clear message instead of a raw exception.

---

## Artifacts

- **DataGateWin.v1.0.15.zip** — full portable build (WinUI app + engine + bundled installer).
- **DataGateWin.Installer.exe** — standalone installer executable.

The ZIP is self-contained (WinUI + Windows App SDK). Run the installer as administrator.

---

## Upgrade from 1.0.14

Run the new installer or extract the ZIP and use `Installer\DataGateWin.Installer.exe`.

If the in-app updater does not appear, download the installer from the release page and run it manually.
