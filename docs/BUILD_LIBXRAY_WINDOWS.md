# Building / shipping libXray for Windows (DataGate engine)

## Pin

| Item | Value |
|------|--------|
| Upstream | [XTLS/libXray](https://github.com/XTLS/libXray) |
| Release tag | **v26.10.31** (matches Android AAR / Go mirror **v1.261031.0**) |
| Artifact | `libxray-windows-x64.zip` → `libXray.dll` + `libXray.h` |
| API | `CGoInvoke` / `CGoFree` JSON bridge (`apiVersion` 3, `runXray` payload `xrayJson`) |

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

Existing files are reused only when `VERSION.txt` matches the requested release. Cached archives must include the release in their name: `libxray-windows-x64-v26.10.31.zip`, in `third_party\libxray\` or the output directory. An unversioned archive is not reused.

`Build-Engine.ps1` / `Build-Release.ps1` call the fetch script before building, then copy `libXray.dll` next to `engine.exe` (same folder as `wintun.dll`).

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

4. Confirm logs: `[xray] convert…`, `runXray`, `connected`.
5. `StopSession` → Idle; optional `--recover-dns` still clean.
6. Do **not** unlock Access/Import Xray UI until this path is green.

## Notes

- OpenVPN and Xray are mutually exclusive: one `SessionController` session at a time.
- Default IPC protocol remains OpenVPN (`ovpnContent` + WSS bridge).
- The pinned DLL, header and version stamp are committed together; the fetch script refreshes them when the release changes.
