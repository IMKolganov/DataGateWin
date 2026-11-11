# Release validation: Windows 1.0.23

- Release source: current develop, including merged PRs #34, #35 and #36, plus release packaging checks.
- Release .NET test suite: 733 passed, 0 failed.
- Native engine Release build, WinUI self-contained publish and single-file installer publish completed. Final publish log contains no warnings or errors.
- App EXE, app DLL and standalone installer report FileVersion 1.0.23.
- Package contains 172 WinUI MUI entries across 86 locale directories and includes app-local x64 VC++ runtime beside the engine.
- Published engine loads successfully and returns its expected exit code 2 without a session ID; no VPN session is started.
- Historical 1.0.22 release ZIP was downloaded from GitHub. The historical checker/parser and installer helper sources from its pinned installer commit 7598c612 were compiled in an isolated compatibility runner.
- Legacy logic accepts numeric tag 1.0.23 and the DataGateWin.v1.0.23.zip asset, resolves the install root from Installer/, and deploys over a real extracted 1.0.22 package while its helper is locked. SHA-256 matches all 720 newly deployed files. The old helper is preserved, as expected.
- Elevated startup smoke tests on the final ZIP and upgraded 1.0.22 fixture both reached ShowMain and stayed alive for 20 seconds. The standalone installer started and stayed alive for 10 seconds. Smoke cleanup targets only its own processes.

## SHA-256

```
77bb110facb698d4efbfcc6acf144206bb76cf8f8c2a97ef90d0be90099e0ce5  DataGateWin.v1.0.23.zip
09917a44090b83dd9b58d3f826aacd0ee093868c6c1f33033b1d56d2a3d16c18  DataGateWin.Installer.exe
```

## Limits

The legacy compatibility check exercises historical parsing/copy code and real release files; it does not drive the entire old installer UI or its network download. System installation, registry/shortcut registration, clean Windows VM testing and a live VPN connection were not exercised. Rollback tests cover copy failures, not power loss or registration failures. Old updaters retain their running executable; installing the new standalone installer replaces that legacy helper.
