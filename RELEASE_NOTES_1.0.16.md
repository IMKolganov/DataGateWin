# DataGate for Windows — release 1.0.16

## Summary

Fixes a process kill on **Connect**: unpackaged WinUI FailFasted (`0x80073B01` / `Microsoft.UI.Xaml.dll`) when the Home connected-server flag was shown. App, engine, and installer versions are aligned at **1.0.16**.

---

## For users

- **Connect**: the app no longer closes the moment a session comes up.
- Flags and the profile photo load from image files without hitting the WinUI resource loader crash.
- Access crash-safety from 1.0.15 is unchanged (UI work stays on the UI thread).

---

## Artifacts

- **DataGateWin.v1.0.16.zip**
- **DataGateWin.Installer.exe**

Run the installer as administrator.

---

## Upgrade from 1.0.15

Install over 1.0.15, or uninstall first and run the new installer.
