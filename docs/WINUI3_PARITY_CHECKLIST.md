# WinUI 3 parity checklist

Tracks feature parity vs WPF `DataGateWin.UI` @ 1.0.13.

## Scaffolding (Phase 0)

- [x] Unpackaged WinUI project (`WindowsPackageType=None`, self-contained WASDK)
- [x] `DataGateWin.Core` class library; WPF + WinUI both reference Core
- [x] Solution includes Core + WinUI; Debug x64 build green
- [x] Assembly name `DataGateWin` (installer / ZIP / App Paths contract)
- [x] Elevation manifests: Release `requireAdministrator`, Debug `asInvoker`

## Phase 0 spike

- [ ] Hello window starts unpackaged on Win10 + Win11 *(blocked on Win10 VM if unavailable; Win11 local build OK)*
- [x] Start `engine.exe` from app directory *(HomeController / EngineSessionService)*
- [x] Named-pipe IPC: session attach / status via Core
- [x] Tray icon + Connect / Disconnect *(tray Open/Exit; connect on Home)*
- [x] Document publish folder layout for installer / zip — `docs/WINUI3_PUBLISH_LAYOUT.md`
- [x] Go/no-go: publish size vs WPF documented *(WinUI ~301 MB self-contained vs WPF ~12 MB FDD; Win10 VM smoke still optional)*

## Shell (Phase 1)

- [x] Login / first-run window
- [x] Free-tier onboarding
- [x] Main navigation: Home / Access / Statistics / Settings / About
- [x] Localization (`WinUiLanguageService` + Core `Loc.Resolver`)
- [x] Theme light / dark

## Feature parity (Phase 2)

### Home / session

- [x] Server list load + selection
- [x] Connect / disconnect / reconnect
- [x] Session status + network footer
- [x] DNS recovery / engine-missing UX
- [x] Auto-reconnect policy

### Access / auth

- [x] Google OAuth loopback
- [x] Token store / session restore
- [x] Access / plan / quota display
- [x] Free-tier access flags

### Statistics

- [x] Charts (LiveCharts2 area/line series)
- [x] Statistics API client wired to UI

### Settings / About / update

- [x] Language picker
- [x] Update check (ContentDialog)
- [x] Crash report entry points *(same as WPF: silent CrashReporter only; no dedicated crash UI)*
- [x] About page content parity

### Tray / chrome

- [x] Tray menu parity (Win32 NotifyIcon)
- [x] Title bar / window chrome
- [x] Avatar in pane footer *(taskbar overlay skipped — best-effort N/A on WinUI)*

### Security / misc

- [x] Torrent process detection + user warning UX
- [x] IP list / route config UI (`IpListSettingsWindow`)
- [x] Support / Telegram links

## Ship cutover (Phase 3)

- [x] Installer / deploy scripts point at WinUI publish layout (`Build-Release.ps1`, `Build-Engine.ps1`, `_local_deploy_elevated.ps1`)
- [x] Portable zip layout documented (full publish folder + engine + Installer)
- [x] Updater still expects `DataGateWin.exe` (`InstallerConstants.ExeName` unchanged)
- [x] `ARCHITECTURE.md` updated (UI = WinUI 3 + Core)
- [x] WPF kept in solution as fallback

## Explicit non-goals (leave unchecked / N/A)

- [ ] MSIX Store-only as sole ship format
- [ ] Android / MAUI unification
- [ ] Emoji-font flag experiments as migration driver
