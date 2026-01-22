## Quick orientation for AI coding agents

This repo contains two cooperating parts: a native C++ "engine" (the VPN runtime) and a .NET WPF UI (`DataGateWin.UI`). The UI authenticates users and controls the engine over a local IPC channel.

Keep the guidance short and actionable — aim to make small, safe changes and point to exact files when you need context.

### Big picture
- engine (C++): `engine/` — contains `AppMain.cpp` and `src/ipc` implementing a named-pipe JSON IPC server. It exposes commands (StartSession, StopSession, GetStatus, StopEngine) and events (EngineReady, StateChanged, Log, Connected, Disconnected).
- UI (C# WPF): `DataGateWin.UI/` — a small WPF app that handles auth (Google OAuth loopback), UI navigation, and starting/stopping the engine process. App entry: `App.xaml.cs`; main window: `MainWindow.xaml.cs`.

### Key files to inspect first
- `engine/AppMain.cpp` — wiring between session controller and IPC (good for understanding engine lifecycle and events).
- `engine/src/ipc/IpcProtocol.h` and `engine/src/ipc/IpcServer.{h,cpp}` — concrete IPC pipe names and message format.
- `DataGateWin.UI/App.xaml.cs` — startup checks (must run as Administrator) and configuration loading.
- `DataGateWin.UI/Services/GoogleAuthService.cs` and `GoogleAuthLoopback.cs` — browser-based Google OAuth (loopback listener) implementation and expected config keys.
- `DataGateWin.UI/DataGateWin.csproj` and `appsettings.example.json` — target framework and required runtime settings (ClientId, RedirectPort).

### IPC / integration notes (critical)
- Transport: Windows named pipes. Pipe names follow `datagate.engine.<sessionId>.control` and `datagate.engine.<sessionId>.events` (see `IpcProtocol.h`).
- Protocol: JSON lines. Commands are objects with `type`, `id`, `payloadJson` fields; events are simple JSON payloads. See `IpcServer.cpp` parsing and `AppMain.cpp` command handlers.
- Typical flow: UI launches `engine.exe` (with `--session-id <id>`), waits for `EngineReady` event, then sends `StartSession` with `ovpnContent` (and bridge fields).

### Build & run workflows (concrete)
- Engine (Visual Studio / CMake): the repo uses CMake. A build directory is already present (`build/`) with generated .sln files. On Windows the usual steps are:

```powershell
cmake -S . -B build -G "Visual Studio 17 2022" -A x64
cmake --build build --config Release
```

- UI (.NET WPF): target framework set in `DataGateWin.csproj` (example: `net10.0-windows`). You can open `DataGateWin.slnx` in Visual Studio or build with dotnet:

```powershell
dotnet build DataGateWin.UI\DataGateWin.csproj -c Release
```

- To run the integrated app locally: ensure `engine.exe` is built and accessible to the UI (either copy next to UI exe or run from build output). The UI requires `appsettings.json` next to the executable (see `appsettings.example.json`) and must be started as Administrator.

### Runtime requirements & pitfalls
- The UI enforces Administrator privileges at startup (`App.xaml.cs`). If not elevated it will show a blocking dialog and exit.
- `appsettings.json` is required next to the UI exe; missing file causes immediate shutdown. Use `appsettings.example.json` as a template.
- Google OAuth loopback default port: `51723` (configurable in `appsettings.json`). The `GoogleAuthService` opens the system browser and listens on `http://127.0.0.1:<port>/` for the redirect.
- Engine crash handling: `engine/AppMain.cpp` writes mini-dumps on unhandled exceptions — inspect the executable directory for generated `.dmp` files when investigating crashes.

### Project-specific conventions
- Manual, small-scale DI: the app creates service instances (e.g., `new AuthStateStore()` in `App.xaml.cs`) rather than using a full DI container.
- Navigation: `MainWindow` uses `NavigationView` + `ContentFrame` (see `MainWindow.xaml.cs`) to host pages under `Pages/`.
- IPC command names and required payload fields are validated in `AppMain.cpp` — follow those exact field names (`ovpnContent`, `host`, `port`, `path`, `listenIp`, `listenPort`, etc.) when creating messages from the UI.

### Debugging tips for contributors
- Use the engine helper scripts in `engine/checks/` to experiment with the IPC pipes (`Send-Command.ps1`, `Listen-Events.ps1`). They show expected pipe names and usage.
- For UI troubleshooting, reproduce with `dotnet run` or start from Visual Studio with elevated privileges. Check `appsettings.json` and `app.manifest` for UAC settings.

### Where to change behavior safely
- UI-only tweaks: `DataGateWin.UI/Pages/`, `ViewModels/`, `Services/` — these are high-level and safe to iterate.
- Engine protocol or behavior: modify `engine/src/ipc/*` and `engine/src/session/*`. Be careful: changing message formats requires coordinated UI changes.

If anything above is unclear or you want me to include more specific examples (e.g., a sample StartSession JSON payload or how the UI currently constructs the engine launch command), tell me what to expand and I will update this file.
