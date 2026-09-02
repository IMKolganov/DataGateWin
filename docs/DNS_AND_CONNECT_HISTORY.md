# DNS and connect history (Windows + Android)

This document records why Windows DNS recovery exists, what Android already solved for connect/DNS, and rules so we do not brick user machines again.

## Windows: leftover NRPT / “no internet after VPN”

### What went wrong

OpenVPN3 on Windows applies tunnel DNS by mutating **machine-wide** state, not a session-scoped VPN network like Android:

| Mechanism | Location | Risk if process dies without `TunWin::Setup::destroy()` |
|-----------|----------|--------------------------------------------------------|
| **NRPT** | `OpenVPNDNSRouting-{pid}` under Policies + Dnscache `DnsPolicyConfig` | Catch-all `"."` can point all DNS at a **private** resolver (e.g. `10.x`) that only exists inside the tunnel |
| **netsh dnsservers** | VPN adapter | Usually cleaned with adapter; less sticky than NRPT |
| **SearchList** | `TCPIP\Parameters` / DNSClient policy; temps `OriginalSearchList` / `InitialSearchList` | Can leave a modified search list if restore never runs |
| **WFP block-outside-dns** | Optional | Leftover filters if used |

After **crash**, **hard reboot while connected**, or **`taskkill`** of `engine.exe`, `destroy()` may never run. NRPT remains → DNS fails for the whole OS until rules are deleted. Some users treated this as “Windows is broken” and **reinstalled the OS**. The product failure mode is the same: no usable DNS without VPN.

### Product fix timeline

| When | What |
|------|------|
| Pre-1.0.7 | No automatic leftover cleanup; “no internet after reboot while VPN was connected” |
| `3f9e403` / **1.0.7** | Engine startup + uninstall: delete `OpenVPNDNSRouting*` NRPT, then `ipconfig /flushdns` ([`DnsStartupRecovery.cpp`](../engine/src/app/DnsStartupRecovery.cpp), [`WindowsDnsRecovery.cs`](../DataGateWin.Installer/WindowsDnsRecovery.cs)) |
| Later hardening (this work) | WOW64 NRPT views in engine, SearchList restore, Dnscache `PARAMCHANGE`, UI startup + post-kill `--recover-dns`, broader tests |

Custom in-process DNS proxy was removed earlier (`b79299e`); do **not** reintroduce permanent DNS writers outside OpenVPN3 + paired restore.

### User recovery (instead of reinstalling Windows)

Run as Administrator from the install / portable folder:

```text
engine\engine.exe --recover-dns
```

Or reinstall/uninstall via the DataGate installer (uninstall also runs DNS recovery), or simply start DataGate (engine recovers on every start).

### Rule for future changes

**Do not** add permanent DNS writers (physical NIC static DNS, SearchList, NRPT) without the same PR also wiring **startup / uninstall / `--recover-dns`** restore for that state.

---

## Android connect / DNS inventory (DataGateAndroid)

Android DNS is almost always **session-scoped** (`VpnService.Builder.addDnsServer`). Tearing down the VPN restores underlay DNS automatically. Focus there is *which* DNS to apply and keeping control-plane sockets off the TUN.

### Important commits (portable meaning)

| Commit | Summary | Windows takeaway |
|--------|---------|------------------|
| `5d166daf` | OpenVPN pushed DNS; Access shows VPN IP/DNS | Prefer pushed DNS; surface tunnel DNS in UI when useful |
| `2f1bff56` | Issued `dnsServers` / `dnsIdentityEnabled`; `/32` force DNS through proxy; owner-scoped session clear | If DNS is in a private range, force it through the tunnel before LAN/bypass rules; own session cleanup |
| `c4b34485` | Unit tests for ConnectDnsPlan / session races / Private DNS hint | Test DNS *plans* and recovery without a live TUN |
| `545aa470` | IPv6 blackhole + LAN exclude | Do not blackhole IPv6; keep LAN sensible |
| Protect-before-connect (`e34e5b04` and factories) | Protect sockets before `connect` | WSS/OpenVPN remote must not enter the tunnel first |
| WSS reconnect hardening | Bridge loss / stall reconnect | Already partial in Win bridge; keep separate from DNS PRs |
| `f522aca6` | Per-app split tunnel | Large follow-up; not DNS recovery |

Repo path used for this inventory: `F:\Android\DataGateAndroid`.

### What not to port wholesale

- **Xray / libXray** DNS pipeline — Windows client is OpenVPN over WSS only for now.
- Relying on “TUN teardown = DNS fixed” — **false on Windows**; always keep NRPT/SearchList recovery.

---

## Recovery pipeline (current target)

Order of operations for stale-state cleanup:

1. Delete leftover `OpenVPNDNSRouting*` NRPT (HKLM, 64-bit and 32-bit views, both NRPT roots)
2. Best-effort SearchList restore from `OriginalSearchList` / clear OpenVPN temp values
3. Signal `Dnscache` (`SERVICE_CONTROL_PARAMCHANGE`)
4. `ipconfig /flushdns`

### Port defaults (not magic)

| Constant | Value | Meaning |
|----------|-------|---------|
| OpenVPN default remote port | **1194** | Spec default when `remote host` omits a port — not our listen port |
| Local WSS bridge | **18080** (+ up to 63 shuffled fallbacks) | Loopback UI↔engine OpenVPN bridge; if busy, engine tries a shuffled pool |

See `engine/src/session/EnginePortDefaults.h` and `DataGateWin.UI/Services/Ipc/EnginePortDefaults.cs`.

### `--recover-dns` safety

- **Refuse while VPN/engine looks active** (engine mutex held, or live `OpenVPNDNSRouting-{pid}` owner process) — exit code `3`.
- **ACCESS_DENIED** on HKLM without Administrator — exit code `5` (Debug UI is `asInvoker`; Release requires elevation).
- Call sites: engine process start (always; session not up yet), `engine.exe --recover-dns`, installer uninstall, UI after killing stale engine / on exit.

