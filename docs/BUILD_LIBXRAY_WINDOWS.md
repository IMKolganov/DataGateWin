# Building / shipping libXray for Windows (DataGate engine)

## Pin

| Item | Value |
|------|--------|
| Upstream | [XTLS/libXray](https://github.com/XTLS/libXray) |
| Release tag | **v26.7.28** (matches Android AAR / Go mirror **v1.260728.0**) |
| Artifact | `libxray-windows-x64.zip` → `libXray.dll` + `libXray.h` |
| API | `CGoInvoke` / `CGoFree` JSON bridge (`apiVersion` 1) |

No Go toolchain is required for the Windows client: we consume the official prebuilt DLL.

## Fetch

From repo root:

```powershell
pwsh -File .\scripts\libxray\fetch-windows.ps1
```

Stages into `engine\third_party\libxray\`:

- `libXray.dll`
- `libXray.h`
- `VERSION.txt`

If `third_party\libxray\libxray-windows-x64.zip` already exists, the script uses that zip instead of downloading.

`Build-Engine.ps1` / `Build-Release.ps1` call the fetch script when the DLL is missing, then copy `libXray.dll` next to `engine.exe` (same folder as `wintun.dll`).

## Runtime layout

```
engine\
  engine.exe
  wintun.dll          # required for Xray TUN (system stack)
  libXray.dll         # LoadLibrary by XrayRuntime
  libcrypto-3-x64.dll
  ...
```

## Lab smoke (S4)

1. Build engine (Release) and ensure `libXray.dll` is beside `engine.exe`.
2. Start engine elevated if needed for TUN.
3. Send IPC `StartSession` with:

```json
{
  "protocol": "xray",
  "xrayShareLinks": "vless://… or vmess://… (Android-known working link)"
}
```

4. Confirm logs: `[xray] convert…`, `runXrayFromJson`, `connected`.
5. `StopSession` → Idle; optional `--recover-dns` still clean.
6. Do **not** unlock Access/Import Xray UI until this path is green.

## Notes

- OpenVPN and Xray are mutually exclusive: one `SessionController` session at a time.
- Default IPC protocol remains OpenVPN (`ovpnContent` + WSS bridge).
- DLL is gitignored (`*.dll`); CI/dev machines fetch via the script.
