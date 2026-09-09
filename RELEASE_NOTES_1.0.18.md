# DataGate for Windows — release 1.0.18

## Summary

Fixes unpackaged WinUI **FailFast after Install** (`0x80073B01` / `0xc000027b`): title-bar and login brand images no longer use `ms-appx:///`. They load from loose files next to the exe (same model as flags). Also keeps the 1.0.17 shared-`BitmapImage` fix and full installer EULA for every UI locale.

## For users

- **Connect / Install** no longer dies on MUI resource lookup for the favicon.
- Missing flag/brand PNGs are hidden — the app keeps running.
- Installer: full EULA in all app languages (UiLocale list).

## Artifacts

- **DataGateWin.v1.0.18.zip**
- **DataGateWin.Installer.exe**

## Upgrade

Install 1.0.18 over the previous build (or uninstall first).
