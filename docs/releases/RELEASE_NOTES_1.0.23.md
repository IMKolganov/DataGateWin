# DataGate for Windows — 1.0.23

## Changes

- Added a server map with server locations, status markers and IP location.
- Improved statistics filters, date ranges and traffic charts.
- Added manual update checking in Settings and corrected version comparisons.
- Installer: project information and links, themed language picker, Back navigation and retry after failure.
- New installer validates downloads and upgrade versions, restores files after copy failures, and stops only processes from the target installation.
- Improved VPN connection preparation, imported OpenVPN credentials/challenges and startup DNS recovery.
- Fixed elevated file import, startup sizing, account display and runtime themes.
- Updated backend client identification and libXray to v26.10.31.
- Removed WinRT build warnings.

## Downloads

- **DataGateWin.Installer.exe** — Windows x64 installer.
- **DataGateWin.v1.0.23.zip** — complete Windows x64 application, engine and bundled installer.
- **SHA256SUMS.txt** — artifact checksums.

## Upgrade

Install over 1.0.22 or an earlier supported version, or accept the update in the app. Existing versions continue to use the numeric release tag and the `DataGateWin.v*.zip` asset.

The old updater preserves its own running executable during an in-app update. Run the new standalone installer to replace that legacy helper and obtain the new installer behavior.

The welcome screen is translated into Russian and English; other languages use English fallback. Back navigation is translated into all 40 supported locales.

Windows 10/11 x64. The ZIP includes the required .NET/Windows App SDK runtime, WinUI language resources and VPN engine dependencies.
