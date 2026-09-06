# WinUI 3 unpackaged publish layout

Contract for installer / portable ZIP / in-app updater after cutover from WPF.

## Build command

```powershell
dotnet publish DataGateWin.WinUI\DataGateWin.csproj `
  -c Release -r win-x64 `
  -p:Platform=x64 `
  -p:WindowsPackageType=None `
  -p:WindowsAppSDKSelfContained=true `
  -p:SelfContained=true `
  -p:PublishTrimmed=false
```

Primary output (publish folder):

`DataGateWin.WinUI\bin\Release\net10.0-windows10.0.26100.0\win-x64\publish\`

Or use `DataGateWin.UI\Build-Release.ps1` (post-cutover: publishes WinUI, stages engine + installer, packs ZIP).

## Required layout (next to `DataGateWin.exe`)

| Path | Role |
|------|------|
| `DataGateWin.exe` | WinUI shell (`AssemblyName=DataGateWin`) |
| `DataGateWin.pri` | WinUI XAML/resources (must be full EmbeddedData PRI, typically ≥ ~100KB — tiny PRI breaks LoadComponent) |
| `DataGateWin.Core.dll` + deps | Portable logic |
| `DataGateWin.CrashReporting.dll` | Crash queue / ingest |
| Windows App SDK / WinUI / Skia native DLLs | Self-contained runtime (many files) |
| `appsettings.json` | API + GoogleAuth (+ CrashReporting optional) |
| `appsettings.example.json` | Template |
| `Images\favicon.ico`, `Images\favicon.png` | Icons |
| `Assets\IpLists\*.txt` | Fallback CIDR lists |
| `Localization\Strings.*.xaml` | UI strings (copied to output) |
| `engine\engine.exe` | Native VPN engine |
| `engine\wintun.dll`, OpenSSL/lz4/jsoncpp | Engine runtime |
| `Installer\DataGateWin.Installer.exe` | Bundled updater/installer (in release ZIP) |

## Packaging notes

- **Unpackaged only** (`WindowsPackageType=None`). Do not ship MSIX as the sole format.
- **Do not trim** (`PublishTrimmed=false`) — WinUI/WinRT metadata breaks.
- **Self-contained** WASDK + .NET so users are not required to install a separate Windows App SDK runtime.
- Installer still looks for **`DataGateWin.exe`** (`InstallerConstants.ExeName`).
- Min OS: Windows 10 **1809** (build 17763) per WinUI project `TargetPlatformMinVersion`; claim Win10 + Win11 after smoke on a real Win10 VM.

## Smoke checklist (manual)

1. Publish Release win-x64 as above; stage `engine\` next to exe.
2. Run elevated `DataGateWin.exe` (Release manifest = requireAdministrator).
3. First-run / login / Main nav load.
4. Tray: close hides; Open / Exit work.
5. Home: engine starts, IPC status, connect / disconnect / reconnect.
6. DNS recovery path after kill (installer or engine `--recover-dns`).
7. Statistics chart renders; IP list editor saves; torrent warning if a known client is running.
8. Compare folder size vs previous WPF `net10.0-windows` output (WinUI self-contained is larger — expected).
   - Measured locally after cutover publish: **WinUI Release win-x64 publish ≈ 301 MB** vs **WPF framework-dependent Release app ≈ 12 MB** (excluding engine/Installer/zips). Larger download is the trade-off for bundling .NET + Windows App SDK.

## Win10 VM

If a Win10 VM is available, run the smoke list there and tick Phase 0 items in `WINUI3_PARITY_CHECKLIST.md`. If not, leave those items marked blocked on VM.
