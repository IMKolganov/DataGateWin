# DataGate for Windows — release 1.0.14

## Summary

Ships the **WinUI 3** unpackaged client as the Windows app (replacing WPF), adds **Xray** alongside OpenVPN, and polishes Home, Access, tray, and installer packaging. App, engine, and installer versions are aligned at **1.0.14**.

---

## For users

- **WinUI 3**: same product name and install path (`DataGateWin.exe`); Start Menu / Desktop shortcuts keep using `Images\favicon.ico`.
- **Xray**: import and connect Xray profiles in addition to OpenVPN over WSS.
- **Login**: TOTP (authenticator) when the backend requires it.
- **Home**: live In/Out traffic, session identity, connect/disconnect next to status.
- **Access**: scrollable page; traffic quota bar with used / remaining (red when over quota).
- **Tray**: balloon on connect and disconnect; icons on the right-click menu (Open / Connect / Disconnect / Exit).
- **UI**: icons on commands and page headings; language switch updates the visible page immediately.
- **Servers**: country flags next to server names.

---

## Artifacts

- **DataGateWin.v1.0.14.zip** — full portable build (WinUI app + engine + bundled installer).
- **DataGateWin.Installer.exe** — standalone installer executable.

The ZIP is self-contained (WinUI + Windows App SDK). Run the installer as administrator.

---

## Upgrade from 1.0.13

Run the new installer or extract the ZIP and use `Installer\DataGateWin.Installer.exe`.

If the in-app updater does not appear, download the installer from the release page and run it manually.
