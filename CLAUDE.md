# DataGateWin — notes for Claude

## Layout (single UI)

- `src/DataGateWin.UI/` — the only UI (WinUI 3, builds `DataGateWin.exe`). All UI work goes here.
- `src/DataGateWin.Core/` — UI-free logic (auth, IPC client, VPN servers, profiles, update policy). **Must not reference WinUI/WPF types**; inject UI behavior through interfaces (e.g. `IUpdatePrompter`).
- `src/DataGateWin.CrashReporting/`, `src/DataGateWin.Installer/` (WPF installer, git submodule).
- `tests/DataGateWin.Tests/` — xUnit; many tests read source files by repo-relative path (`src/...`, `scripts/...`), update them when moving files.
- `engine/` — native C++ engine. `scripts/` — build/release (`Build-Engine.ps1`, `Build-Release.ps1`). `tools/` — locale tooling.
- The old WPF UI (`DataGateWin.UI` submodule) was removed. Do not reintroduce it.

## Build / test

```powershell
dotnet build src/DataGateWin.UI/DataGateWin.UI.csproj -c Debug -p:Platform=x64
dotnet test tests/DataGateWin.Tests/DataGateWin.Tests.csproj -c Debug
```

## Localization

Strings live in `src/DataGateWin.UI/Localization/Strings.*.xaml` (`x:String`). The WPF installer reuses them; its csproj converts `x:String` → `sys:String` into `obj/` at build time.
