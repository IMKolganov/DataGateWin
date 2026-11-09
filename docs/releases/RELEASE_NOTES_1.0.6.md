# DataGate for Windows — release 1.0.6

## Summary

Client and installer bumped to **1.0.6**, improved VPN engine deployment (Wintun, vcpkg runtime DLLs), clearer messaging when DLLs fail to load or the loader exits with **0xC0000135**, and handling when **engine.exe** is missing. The engine build script also publishes the Windows installer to `bin\Release\net10.0-windows\Installer`.

---

## For users

- **App and installer versions** are aligned at **1.0.6** for easier matching of builds.
- **Wintun**: the official **wintun.dll** (amd64) is shipped next to **engine.exe** to avoid adapter load failures on first connect.
- If a **DLL is missing** or the engine exits with loader code **0xC0000135**, the UI and logs show **actionable hints** (including reinstalling from the official installer).
- If **engine.exe** is missing, a dialog offers the download page and optionally running the bundled installer when present.

---

## For developers / build

- **`DataGateWin.UI\Build-Engine.ps1`**: for **Debug**, runtime DLLs are copied from `vcpkg\...\x64-windows\debug\bin` (including **lz4d.dll**); for **Release**, from `...\bin`. **OpenSSL**, **jsoncpp** / **lz4**, and **wintun.dll** from `drivers\wintun` are copied next to the engine.
- After building the **Release** engine, the script runs **`dotnet publish`** for the installer into **`bin\Release\net10.0-windows\Installer`** without **`.pdb`** in that folder.
- Switches: **`-SkipInstaller`** — skip publishing the installer; **`-SkipConfigure`** — skip CMake configure when a cache already exists.

---

## Known limitations

- If copying **engine.exe** to the **Release** output fails because the file is in use, close the app/engine and rerun the script.
- CMake may warn about a platform mismatch with an old cache; delete **`build\CMakeCache.txt`** and reconfigure if needed.

---

## Artifacts

- Main app: **DataGateWin.exe** in the UI project’s build output.
- Installer: **`DataGateWin.UI\bin\Release\net10.0-windows\Installer\DataGateWin.Installer.exe`** (after a successful `Build-Engine.ps1` run with installer publish enabled).
- Engine: **`...\bin\<Debug|Release>\net10.0-windows\engine\engine.exe`** plus the copied DLLs.

---

*Use this text for GitHub Releases or similar. Add issue/PR links from your tracker if you want a fuller changelog.*
