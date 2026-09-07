# Xray Windows — remaining work (post S0–S5)

Status after starter wiring: **engine IPC + libXray load + Core API stub exist**.  
**Do not unlock Access / Import Xray UI until S4 lab smoke is green.**

Branch: `feature/winui3-migration`.

---

## Done (starter)

| Area | Notes |
|------|--------|
| libXray pin v26.7.28 | `scripts/libxray/fetch-windows.ps1`, `docs/BUILD_LIBXRAY_WINDOWS.md` |
| `XrayRuntime` / TUN config | `engine/src/xray/*` |
| IPC `protocol=xray` | Mutual exclusion via single session |
| `XrayClientLinksApiClient` | Not wired into connect path yet |
| UI lock | Import coming-soon; selector hides Xray |

---

## Remaining (priority)

### P0 — before / during S4 lab smoke

| # | Gap | Why | Status |
|---|-----|-----|--------|
| P0.1 | Proxy/API **direct bypass** CIDRs in routing | Without this, outbound to VLESS host can hairpin into TUN | ✅ Engine + Core mirror (`CollectProxyEndpointCidrs`) |
| P0.2 | Verify **`getXrayState.running`** after `runXrayFromJson` | Avoid sticky Connected when TUN never up | ✅ `SessionController::StartXray` |
| P0.3 | Emit **Disconnected** on user Stop for Xray | OpenVPN gets VPN callback; Xray must publish explicitly | ✅ `user_stop` on Xray Stop |
| P0.4 | **S4 manual smoke** | Paste known Android share-link → start → traffic → stop → `--recover-dns` | ⬜ Human / lab |

### P1 — before catalog / Import unlock (Phase C–D)

| # | Gap | Why | Status |
|---|-----|-----|--------|
| P1.1 | `extractShareLink` + issued JSON `{vless,dnsServers,mux}` normalize | API/download body is not always raw `vless://` | ✅ partial (engine + Core); connect path not wired |
| P1.2 | Mux normalize on first outbound | Android catalog profiles | ✅ builder |
| P1.3 | DNS-from-profile (`dnsServers` → proxy-before-private rules) | Private CIDR otherwise steals VPN DNS | ✅ builder; Home DNS push still TBD |
| P1.4 | `StartSessionPayloadBuilder` Xray branch + Home wiring | Connect path still OpenVPN-only | ⬜ |
| P1.5 | `IsXrayWindowsSupported` + Access/Home rows | Selector currently rejects all Xray | ⬜ (locked on purpose) |
| P1.6 | Import unlock + loc | After S4 | ⬜ |

### P2 — polish

| # | Gap |
|---|-----|
| P2.1 | Xray death watchdog (poll `getXrayState` → Disconnected) |
| P2.2 | CMake reconfigure when DLL appears after configure |
| P2.3 | Update `DNS_AND_CONNECT_HISTORY.md` when DNS pipeline lands |
| P2.4 | Optional `xray.exe` fallback |

---

## Test strategy (no live VPN)

| Suite | Asserts |
|-------|---------|
| `XrayWindowsConfigBuilderTests` | Private→direct, bypass before catch-all, strip `sendThrough`, mux, share extract, DNS proxy rules, chunking |
| `XrayClientLinksApiClientTests` | download / create-when-missing / 404 / errors / issued JSON profile |
| `XrayUiLockContractTests` | Import/Home/selector still hide Xray; payload builder has no `xrayShareLinks` |
| `XrayEngineContractTests` | Source wiring + fetch pin + staged DLL + build scripts |
| `XrayLocalizationContractTests` | en/ru lock strings present |

S4 remains a **manual** checklist in `BUILD_LIBXRAY_WINDOWS.md`.
