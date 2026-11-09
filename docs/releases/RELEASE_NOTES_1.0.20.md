# DataGate for Windows — release 1.0.20

## Summary

Hardens in-app updates and Settings crash safety, and restores card chrome without ThemeResource FailFast.

## For users

- **Update loop fix:** version comes from `DataGateWin.exe` in the install folder (not the Installer exe); update mode always downloads from GitHub (no accidental offline `DataGateWinBuild*` reuse).
- **Settings** no longer kills the process on theme-resource FailFast — UI is built in code; nav failures show an error panel instead of crashing.
- **Home / Access / Import / Statistics** card backgrounds restored safely (no `{ThemeResource}` markup).
- LiveCharts chrome is left alone so traffic/statistics charts render correctly.
- **Show engine logs** uses the same `ToggleSwitch` style as Dark mode in Settings.

## Artifacts

- **DataGateWin.v1.0.20.zip**
- **DataGateWin.Installer.exe**

## Upgrade

Install 1.0.20 over the previous build.
