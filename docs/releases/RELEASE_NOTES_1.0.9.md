# DataGate for Windows — release 1.0.9

## Summary

Fixes **auto-update detection** and **in-app update installation** on Windows. App, engine, and installer versions are aligned at **1.0.9**.

---

## For users

- **Auto-update**: checks for updates on the login screen and again after free-tier onboarding closes; no longer missed when the app was not fully signed in yet.
- **Installer update flow**: fixes a crash (`Update failed`) after confirming “close running processes” during an in-app update.
- **Reliability**: installer logging and progress UI now run on the correct WPF thread; process enumeration handles are cleaned up properly.

---

## Artifacts

- **DataGateWin.v1.0.9.zip** — full portable build (app + engine + bundled installer).
- **DataGateWin.Installer.exe** — standalone installer executable.

Install .NET 10 Desktop Runtime if prompted. Run the installer as administrator.

---

## Upgrade from 1.0.8

Run the new installer or extract the ZIP and use `Installer\DataGateWin.Installer.exe`.

If the in-app updater failed on 1.0.8, close DataGate completely and run the installer manually from the link above.

If uninstall from Settings fails on an old install, run:

`"C:\Program Files\DataGate\Installer\DataGateWin.Installer.exe" --uninstall`
