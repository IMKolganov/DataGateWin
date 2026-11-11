## Quick orientation for AI coding agents

This repo has a native C++ engine (`engine/`) and a WinUI 3 UI (`src/DataGateWin.UI`) on top of a UI-free library (`src/DataGateWin.Core`). The UI authenticates users and controls the engine over a local named-pipe IPC. See `CLAUDE.md` for layout and build commands and `docs/ARCHITECTURE.md` for the IPC model.

### Rules
- UI changes go in `src/DataGateWin.UI`; logic that does not need UI types goes in `src/DataGateWin.Core`.
- IPC contract: `engine/src/ipc/IpcProtocol.h`, `engine/src/ipc/IpcServer.*`, handlers in `engine/AppMain.cpp`. Keep message field names in sync with `DataGateWin.Core/Services/Ipc`.
- Release/build scripts live in `scripts/`.
