# DataGate for Windows — release 1.0.23

## Summary

- Imported OpenVPN profiles that need a username/password (and dynamic challenge) can now connect.
- Import → Browse file uses the Windows App SDK picker (`Microsoft.Windows.Storage.Pickers`) so the dialog can run in an elevated unpackaged process. The old `Windows.Storage.Pickers.FileOpenPicker` fails as Administrator with a generic “Something went wrong”.
- Every request to the DataGate backend now says which app and build sent it (`X-Client-Name: windows`, `X-Client-Version: 1.0.23`).

## For users

- **Import:** choosing a `.ovpn` / Xray file no longer dies immediately on Release (UAC / `requireAdministrator`). Uses WASDK 2.4 `FileOpenPicker(WindowId)` as documented for elevated desktop apps.
- **Imported OpenVPN with login:** DataGate asks for the credentials (and the challenge response, when the server sends one) instead of failing.
- **Unsupported build:** if the server stops supporting this build, DataGate shows **Update required** once (with a download link) instead of a generic error. You stay signed in.

## Under the hood

- `ClientIdentityHandler` (in `DataGateWin.CrashReporting`, shared by Core, WinUI, the WPF fallback and the installer) adds the headers to the auth client, the authenticated API client (including the retry after a token refresh) and crash ingest. Header names come from `DataGateMonitor.SharedModels` 1.0.90.
- VPN node traffic (WSS `/api/proxy`), GitHub update checks, Google sign-in and avatars are not touched.

## Artifacts

- **DataGateWin.v1.0.23.zip**
- **DataGateWin.Installer.exe**

## Upgrade

Install 1.0.23 over 1.0.22 (or earlier).
