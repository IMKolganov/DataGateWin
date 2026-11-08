# DataGate for Windows — release 1.0.23

## Summary

Every request to the DataGate backend now says which app and build sent it (`X-Client-Name: windows`, `X-Client-Version: 1.0.23`).

## For users

- Nothing changes while the server accepts the build.
- If the server stops supporting this build, DataGate shows **Update required** once (with a download link) instead of failing with a generic error. You stay signed in.

## Under the hood

- `ClientIdentityHandler` (in `DataGateWin.CrashReporting`, shared by Core, WinUI and the installer) adds the headers to the auth client, the authenticated API client (including the retry after a token refresh) and crash ingest. Header names come from `DataGateMonitor.SharedModels` 1.0.90.
- VPN node traffic (WSS `/api/proxy`), GitHub update checks, Google sign-in and avatars are not touched.

## Artifacts

- **DataGateWin.v1.0.23.zip**
- **DataGateWin.Installer.exe**

## Upgrade

Install 1.0.23 over 1.0.22 (or earlier).
