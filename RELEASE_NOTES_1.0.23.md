# DataGate for Windows — release 1.0.23

## Summary

Import → Browse file uses the Windows App SDK picker (`Microsoft.Windows.Storage.Pickers`) so the dialog can run in an elevated unpackaged process. The old `Windows.Storage.Pickers.FileOpenPicker` fails as Administrator with a generic “Something went wrong”.

## For users

- **Import:** choosing a `.ovpn` / Xray file no longer dies immediately on Release (UAC / `requireAdministrator`).
- Uses WASDK 2.4 `FileOpenPicker(WindowId)` as documented for elevated desktop apps.

## Artifacts

- **DataGateWin.v1.0.23.zip**
- **DataGateWin.Installer.exe**

## Upgrade

Install 1.0.23 over 1.0.22 (or earlier).
