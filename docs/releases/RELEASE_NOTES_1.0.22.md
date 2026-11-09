# DataGate for Windows — release 1.0.22

## Summary

Runtime language switch no longer FailFasts the process; LiveCharts stay usable under RTL/LTR changes.

## For users

- **Language switch:** no longer flips process UI culture or mutates `MergedDictionaries` / ComboBox `Items.Clear` during selection (those paths FailFast unpackaged WinUI with `0xC000027B` / `0x80070490`). Strings reload in memory; UI refresh is deferred.
- **Charts:** CartesianChart forces `LeftToRight`; after language change charts are re-pinned LTR so Arabic/Farsi (and FlowDirection flips) do not blank LiveCharts.
- Managed language errors still surface via Settings error panel where possible; WinUI FailFast cannot be caught as a soft dialog.

## Artifacts

- **DataGateWin.v1.0.22.zip**
- **DataGateWin.Installer.exe**

## Upgrade

Install 1.0.22 over 1.0.21 (or earlier). Prefer the GitHub ZIP/installer, not a hand-copied publish folder alone.
