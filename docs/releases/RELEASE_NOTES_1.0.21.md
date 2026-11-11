# DataGate for Windows — release 1.0.21

## Summary

Fixes GitHub ZIP packaging so install-from-release actually launches (1.0.20 FailFast).

## For users

- **Critical:** release ZIP now includes WinUI MUI locale satellites (`en-us\Microsoft.ui.xaml.dll.mui`, …). Missing MUI caused `0xC000027B` / `0x80073B01` right after main window on installs from GitHub, while local `publish` still worked.
- Keeps 1.0.20 product fixes: update-loop hardening, Settings fail-soft, card chrome without ThemeResource, engine-log `ToggleSwitch`.
- Release gate: ZIP must contain `*.mui`; smoke must run from the **ZIP**, not only from the publish folder.

## Artifacts

- **DataGateWin.v1.0.21.zip**
- **DataGateWin.Installer.exe**

## Upgrade

Install 1.0.21 over any previous build (including a broken 1.0.20 local install).
