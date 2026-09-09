# DataGate for Windows — release 1.0.17

## Summary

**Replaces 1.0.16.** Connect still died on some PCs because one `BitmapImage` flag was reused across multiple WinUI `Image` controls (`InvalidCastException` → FailFast `0xc000027b`). 1.0.16 only fixed file-URI / MUI loading; this build fixes the real shared-source crash.

## For users

- **Connect** no longer kills the process when the connected-server flag appears.
- Flag PNGs are cached as **bytes**; every `Image` gets a **new** bitmap.
- Home server ComboBox shows text only (no flag images in the list) — flags remain on the network footer.
- Access / avatar still load pictures via stream (`SetSource`), never `file://` URIs.

## Artifacts

- **DataGateWin.v1.0.17.zip**
- **DataGateWin.Installer.exe**

Run the installer as administrator. If you installed 1.0.16, install over it (or uninstall first).

## Upgrade from 1.0.15 / 1.0.16

Install 1.0.17 over the previous build.
