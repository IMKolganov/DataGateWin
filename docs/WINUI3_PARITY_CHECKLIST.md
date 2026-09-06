# WinUI 3 parity checklist

Tracks feature parity vs WPF `DataGateWin.UI` @ 1.0.13.  
Scaffolding only is checked; everything else stays open until implemented and verified.

## Scaffolding (Phase 0)

- [x] Unpackaged WinUI project (`WindowsPackageType=None`, self-contained WASDK)
- [x] `DataGateWin.Core` class library with copied portable logic (WPF untouched)
- [x] Solution includes Core + WinUI; Debug x64 build green
- [x] Assembly name `DataGateWin.WinUI` (no clash with WPF `DataGateWin.exe`)
- [x] Elevation manifests: Release `requireAdministrator`, Debug `asInvoker`

## Phase 0 spike (remaining)

- [ ] Hello window starts unpackaged on Win10 + Win11
- [ ] Start `engine.exe` from app directory
- [ ] Named-pipe IPC: `GetStatus` / session ping
- [x] Tray icon + Connect / Disconnect smoke *(Open / Exit tray via Win32 NotifyIcon; Connect/Disconnect live on Home)*
- [ ] Document publish folder layout for installer / zip
- [ ] Go/no-go: publish size vs WPF, elevation, Win10 VM

## Shell (Phase 1)

- [x] Login / first-run window
- [x] Free-tier onboarding
- [x] Main navigation: Home / Access / Statistics / Settings / About
- [x] Localization strategy (ResourceDictionary vs `.resw` / `Loc` resolver) *(en base + overlay via `WinUiLanguageService` + Core `Loc.Resolver`)*
- [x] Theme light / dark (no WPF-UI) *(ElementTheme / Application.RequestedTheme)*

## Feature parity (Phase 2)

### Home / session

- [x] Server list load + selection
- [x] Connect / disconnect / reconnect *(HomeController + EngineSessionService from Core)*
- [x] Session status + network footer
- [x] DNS recovery / engine-missing UX *(ContentDialog; Core `EngineDnsRecoveryRunner` public)*
- [x] Auto-reconnect policy

### Access / auth

- [x] Google OAuth loopback
- [x] Token store / session restore
- [x] Access / plan / quota display
- [x] Free-tier access flags

### Statistics

- [ ] Charts (replace OxyPlot.Wpf) *(text summary stub only — TODO(parity))*
- [x] Statistics API client wired to UI

### Settings / About / update

- [x] Language picker
- [x] Update check (UI prompts behind interface; no WPF `MessageBox`) *(WinUI `GitHubUpdateChecker` + ContentDialog)*
- [ ] Crash report entry points *(CrashReporter wired at startup; no dedicated UI entry)*
- [x] About page content parity *(About ContentDialog)*

### Tray / chrome

- [x] Tray menu parity (WPF-UI.Tray → Win32 / toolkit) *(Win32 NotifyIcon: Open / Exit; close hides to tray)*
- [x] Title bar / window chrome *(WinUI TitleBar + Mica)*
- [ ] Taskbar / avatar overlay (if kept)

### Security / misc

- [ ] Torrent process detection + user warning UX
- [ ] IP list / route config UI (if exposed) *(Settings toggle works; configure dialog stubbed — TODO(parity))*
- [x] Support / Telegram links

## Ship cutover (Phase 3)

- [ ] Installer points at WinUI output layout
- [ ] Portable zip + GitHub release artifacts
- [ ] Updater validates WinUI folder contract
- [ ] `ARCHITECTURE.md` updated (UI = WinUI 3)
- [ ] WPF kept as fallback one release, then retired

## Explicit non-goals (leave unchecked / N/A)

- [ ] MSIX Store-only as sole ship format
- [ ] Android / MAUI unification
- [ ] Emoji-font flag experiments as migration driver
