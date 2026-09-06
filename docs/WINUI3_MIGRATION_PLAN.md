# Plan: migrate DataGate UI from WPF to WinUI 3

Status: **planning only** (no UI rewrite started).  
Base: `develop` @ 1.0.13.  
Goal: keep engine / IPC / installer model; replace the WPF shell with WinUI 3 + Windows App SDK.

---

## 1. Decision summary

| Question | Answer for DataGate |
|----------|---------------------|
| Must we migrate? | **No.** WPF on .NET 10 remains supported. |
| Why consider WinUI 3? | Official modern Windows UI, Fluent, better color emoji/theme. |
| Worth it for flags alone? | **No** — use PNG/SVG flags on WPF instead. |
| Can we keep zip + custom installer? | **Yes**, if we stay **unpackaged** (`WindowsPackageType=None`) + **self-contained** Windows App SDK. |
| Windows 10? | **Yes**, with a floor (typically Win10 1809+ / current WASDK matrix). Not Win7/8. |
| Biggest risk | Full UI rewrite + tray/charts/theme deps, not the engine. |

**Recommended packaging path:** unpackaged + `WindowsAppSDKSelfContained=true` + folder/zip deploy (same mental model as today).  
**Avoid for v1 of migration:** Store-only MSIX as the only ship format (harder elevation, VPN drivers, side-by-side with `engine.exe`).

---

## 2. What stays / what changes

### Unchanged (do not rewrite)

- `engine/` (OpenVPN3, WSS bridges, DNS recovery)
- Named-pipe IPC contract (`scheme.ipc`, session commands/events)
- `DataGateWin.CrashReporting`
- SharedModels / API clients (logic layer)
- OpenVPN / Wintun driver layout next to `engine.exe`
- Product versioning policy (UI / engine / installer aligned)

### Must rewrite (UI shell)

| Today (WPF) | WinUI 3 target |
|-------------|----------------|
| `DataGateWin.UI` (`UseWPF`) | New WinUI 3 unpackaged project (or evolve submodule) |
| WPF-UI + WPF-UI.Tray | WinUI controls + custom tray (Win32 notify icon or CommunityToolkit) |
| `Window` / `Page` / `NavigationView` (Wpf.Ui) | `Microsoft.UI.Xaml` Window + NavigationView / Frame |
| ResourceDictionary localization (`Strings.*.xaml`) | WinUI resources / `.resw` / keep code-driven `Loc` with WinUI ResourceDictionaries |
| OxyPlot.Wpf (Statistics) | OxyPlot alternative, LiveCharts2, or custom Win2D/Skia |
| FluentWindow chrome helpers | WinUI title bar / `AppWindow` APIs |
| Manifest elevate (Release) | Same: unpackaged exe can still request `requireAdministrator` |

### Installer / launch

| Concern | Impact |
|---------|--------|
| `DataGateWin.Installer.exe` | Keep; point it at new UI output folder layout |
| Portable zip | Keep; ship self-contained WinUI + `engine\` + assets |
| In-app GitHub updater | Keep logic; validate published folder layout still matches |
| F5 debug / Cursor attach | Still works for unpackaged; Debug can stay `asInvoker` like today |
| Launch UX for user | Still `DataGateWin.exe` (or renamed); no Store requirement |

---

## 3. Launch & install — will it feel the same?

### Launch

- **Unpackaged WinUI 3** starts like a normal Win32/.NET exe.
- User double-clicks the app / Start Menu shortcut — same as now.
- App still can spawn/attach `engine.exe` and talk over named pipes.
- First-run / Google OAuth / local redirect port — same patterns; re-validate WinUI window lifetime.

### Install

- Custom installer **can remain** the primary path (copy files, shortcuts, optional elevate, DNS recovery helpers).
- Zip portable **can remain**.
- Optional later: MSIX *in addition* for Store — not required for parity.

### What would restrict us

| Choice | Restriction |
|--------|-------------|
| **MSIX packaged only** | Harder true admin elevation, driver/helper layout, classic “replace folder” updates |
| **Framework-dependent WASDK** | Extra runtime installer on user PCs |
| **Self-contained unpackaged** (recommended) | Larger download; closest to current freedom |

**Conclusion:** migration does **not** force Store/MSIX and does **not** have to change how you install today, if we deliberately stay unpackaged + self-contained.

---

## 4. Windows 10 support

- WinUI 3 / Windows App SDK targets **Windows 10 and Windows 11** (exact minimum build depends on the WASDK version we pin — lock this in Phase 0 spike).
- Plan: **Win10 LTSC/retail we care about + Win11** in the compatibility matrix before cutting over.
- Out of scope unless requested: Windows 7/8, ARM-only first ship (x64 first, ARM64 later if needed).

Spike checklist:

1. Blank unpackaged WinUI 3 app on net10-windows, self-contained publish.
2. Run on a real Win10 VM (oldest SKU we claim).
3. Elevate, tray icon, start `engine.exe` from app dir, named pipe attach.
4. Measure publish size vs current WPF folder.

---

## 5. Migration strategy (phased)

Do **not** big-bang replace the shipping UI. Prefer a parallel shell.

### Phase 0 — Spike (1–2 weeks)

- New project `DataGateWin.WinUI` (unpackaged, self-contained).
- Hello world: window + start engine + `GetStatus` over existing IPC.
- Tray + single Connect/Disconnect button.
- Document publish layout for installer.
- **Go/no-go** on Win10 VM + size + elevation.

### Phase 1 — Shell parity

- Login / first-run / free-tier onboarding windows.
- Main navigation: Home / Access / Statistics / Settings / About.
- Localization strategy decided (port ResourceDictionaries vs `.resw`).
- Theme (light/dark) without WPF-UI.

### Phase 2 — Feature parity

- Home session UI, server list, reconnect, network footer.
- Access + quota/plan flags.
- Statistics charts (replace OxyPlot.Wpf).
- Settings language picker, update check, crash report entry points.
- Tray menu parity.

### Phase 3 — Ship cutover

- Installer + zip + GitHub release artifacts point to WinUI build.
- Keep WPF project in repo one release as fallback (`DataGateWin.UI` tagged).
- Update `ARCHITECTURE.md` (UI = WinUI 3).
- Remove WPF ship path only after one stable WinUI release.

### Parallelism rule

- Engine/DNS/IPC work continues on WPF until Phase 3.
- Shared non-UI code can move to a thin class library both shells reference (optional early extract).

---

## 6. Dependency replacements

| Current | Options |
|---------|---------|
| WPF-UI | WinUI `NavigationView`, custom styles, or a maintained WinUI kit |
| WPF-UI.Tray | Win32 `NOTIFYICONDATA` wrapper / CommunityToolkit tray patterns |
| OxyPlot.Wpf | LiveCharts2 (WinUI), OxyPlot if available for WinUI, or Skia chart |
| CommunityToolkit.Mvvm | Keep (works with WinUI) |
| Microsoft.Extensions.Configuration | Keep |

Flag emoji: still prefer **image assets by ISO code** even on WinUI (predictable, no geo-font politics).

---

## 7. Risks & mitigations

| Risk | Mitigation |
|------|------------|
| Large UI rewrite slips releases | Phase 0 go/no-go; ship WPF until Phase 3 |
| Tray / multi-window bugs | Spike early; automate smoke on login + tray exit |
| Charting gap | Spike Statistics in Phase 0/1 |
| Publish layout breaks updater/installer | Freeze folder contract; add installer smoke test |
| Win10 regressions | Explicit VM matrix before cutover |
| Team velocity (one maintainer) | Only start Phase 1 after Phase 0 success criteria met |

---

## 8. Success criteria (cutover)

- [ ] Unpackaged self-contained zip installs via existing installer UX
- [ ] Elevate Release path works; DNS recovery still available
- [ ] Connect / disconnect / reconnect / crash-recover DNS parity with 1.0.13 WPF
- [ ] Tray + autostart behavior acceptable
- [ ] Win10 + Win11 smoke passed
- [ ] Release notes + updater path documented

---

## 9. Explicit non-goals (this branch)

- No WinUI project scaffolding yet (plan only).
- No MSIX Store submission.
- No Android/MAUI unification.
- No emoji-font experiments as a migration driver.

---

## 10. Next concrete actions

1. Approve this plan (or adjust Win10 floor / packaging).
2. Phase 0 spike PR: empty WinUI unpackaged app + IPC ping.
3. Decide whether WinUI lives in `DataGateWin.UI` repo (replace) or new submodule.
4. Keep WPF shipping until Phase 3.
