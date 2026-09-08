# Xray Windows — remaining work (post unlock)

Status: **Access / Home / Import Xray unlocked** for manual lab check.  
Catalog connect uses `XrayClientLinksApiClient` → IPC `protocol=xray`.  
RDP safety: run `scripts/rdp-vpn-safety-kill.ps1 -Minutes 2` in a separate terminal (not in-app).

Branch: `feature/winui3-migration`.

---

## Done

| Area | Notes |
|------|--------|
| libXray pin v26.7.28 | `scripts/libxray/fetch-windows.ps1`, `docs/BUILD_LIBXRAY_WINDOWS.md` |
| `XrayRuntime` / TUN config | `engine/src/xray/*` |
| IPC `protocol=xray` | Mutual exclusion via single session |
| `XrayClientLinksApiClient` | Wired into `StartSessionPayloadBuilder` |
| Selector | OpenVPN+WSS **and** Xray (`IsXrayWindowsSupported`) |
| Import | Xray paste/browse + `ImportedXrayPayloadBuilder` |
| UI unlock | Access list, Home combo, Import connect |

---

## Remaining

### Lab / polish

| # | Gap | Status |
|---|-----|--------|
| P0.4 | **S4 manual smoke** (catalog + import share-link → traffic → stop → `--recover-dns`) | ⬜ Human |
| P1.3b | Home DNS push from profile `dnsServers` | TBD |
| P2.1 | Xray death watchdog | later |
| P2.3 | Update `DNS_AND_CONNECT_HISTORY.md` | later |

---

## Test strategy (no live VPN)

| Suite | Asserts |
|-------|---------|
| `XrayWindowsConfigBuilderTests` | Private→direct, bypass, mux, share extract, DNS proxy rules |
| `XrayClientLinksApiClientTests` | download / create-when-missing / issued JSON |
| `XrayUiUnlockContractTests` | selector shows Xray; payload has `xrayShareLinks`; Import unlocked |
| `ImportedXrayPayloadBuilderTests` | imported IPC payload shape + validator |
| `XrayEngineContractTests` | engine wiring + fetch pin |
| `XrayLocalizationContractTests` | en/ru unlock strings |

Manual RDP tip:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\rdp-vpn-safety-kill.ps1 -Minutes 2
```
