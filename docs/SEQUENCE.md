============================================================
SEQUENCE FLOWS
UI ↔ ENGINE INTERACTION
Project: DataGate
============================================================

This document describes interaction flows between UI and Engine
in plain, step-by-step form.

Engine is the source of truth.
UI always synchronizes state using GetStatus.

============================================================
SCENARIO 1
UI starts, Engine is NOT running
============================================================

1. UI starts.
2. UI tries to attach to Engine IPC.
3. IPC is not available.
4. UI starts Engine process.
5. Engine initializes IPC and enters Idle state.
6. UI attaches to Control and Events channels.
7. UI requests GetStatus.
8. Engine returns state = Idle.
9. UI displays "Disconnected".

------------------------------------------------------------

Result:
- Engine is running.
- No active VPN session.
- UI and Engine are synchronized.

============================================================
SCENARIO 2
UI starts, Engine is already running
============================================================

1. UI starts.
2. UI attaches to Control and Events IPC channels.
3. UI requests GetStatus.
4. Engine returns current state:
    - Idle
    - Connecting
    - Connected
    - Disconnecting
    - Error
5. UI renders state immediately.
6. UI continues listening for Events updates.

------------------------------------------------------------

Result:
- UI reflects real Engine state.
- No assumptions made by UI.

============================================================
SCENARIO 3
User clicks CONNECT, Engine is NOT running
============================================================

1. User clicks Connect in UI.
2. UI detects that Engine is not attached.
3. UI starts Engine process.
4. Engine initializes and enters Idle state.
5. UI attaches to IPC channels.
6. UI requests GetStatus.
7. Engine returns state = Idle.
8. UI sends StartSession(profile).
9. Engine switches state to Connecting.
10. Engine emits StateChanged(Connecting).
11. Engine finishes connection:
    - Success -> StateChanged(Connected)
    - Failure -> Error event
12. UI updates state based on events.

------------------------------------------------------------

Result:
- Engine is running.
- VPN session is either Connected or failed with Error.

============================================================
SCENARIO 4
User clicks CONNECT, Engine running but no session
============================================================

1. User clicks Connect.
2. UI sends StartSession(profile).
3. Engine accepts command.
4. Engine switches to Connecting.
5. Engine emits StateChanged(Connecting).
6. Engine finishes connection:
    - Success -> Connected
    - Failure -> Error
7. UI updates state via events.

------------------------------------------------------------

Result:
- VPN session established or failed.

============================================================
SCENARIO 5
User clicks CONNECT while already Connected
============================================================

Preferred behavior (Engine idempotent):

1. User clicks Connect.
2. UI sends StartSession(profile).
3. Engine detects session already active.
4. Engine returns OK (already connected).
5. No state change occurs.

------------------------------------------------------------

Result:
- No reconnect.
- No state reset.
- UI remains in Connected state.

============================================================
SCENARIO 6
User clicks DISCONNECT while Connected
============================================================

1. User clicks Disconnect.
2. UI sends StopSession().
3. Engine accepts command.
4. Engine switches to Disconnecting.
5. Engine emits StateChanged(Disconnecting).
6. Engine finishes shutdown.
7. Engine emits StateChanged(Idle).
8. UI updates state accordingly.

------------------------------------------------------------

Result:
- VPN session stopped.
- Engine remains running in Idle state.

============================================================
SCENARIO 7
User clicks DISCONNECT while already Idle
============================================================

1. User clicks Disconnect.
2. UI sends StopSession().
3. Engine detects no active session.
4. Engine returns OK (already idle).
5. No state change occurs.

------------------------------------------------------------

Result:
- No-op.
- UI remains in Idle state.

============================================================
SCENARIO 8
UI closes, Engine continues running
============================================================

1. UI process exits.
2. IPC connections are closed.
3. Engine continues running.
4. VPN session (if active) remains connected.

Later:

5. UI starts again.
6. UI attaches to IPC.
7. UI requests GetStatus.
8. Engine returns current state.
9. UI renders correct state immediately.

------------------------------------------------------------

Result:
- VPN session survives UI restart.

============================================================
SCENARIO 9
Engine crashes while UI is running
============================================================

1. Engine process crashes or exits unexpectedly.
2. IPC connections are closed.
3. UI detects IPC disconnect.
4. UI switches to "Engine lost" state.
5. UI disables Connect/Disconnect temporarily.

Optional recovery:

6. UI restarts Engine.
7. UI attaches to IPC.
8. UI requests GetStatus.
9. UI renders actual Engine state.

------------------------------------------------------------

Result:
- UI recovers gracefully.
- No ghost states.

============================================================
UI ACTION RULES (SUMMARY)
============================================================

CONNECT:
- Ensure Engine is running.
- Attach to IPC.
- Call GetStatus.
- If state == Idle or Error -> StartSession.
- If state == Connecting or Connected -> no-op.

DISCONNECT:
- If attached -> StopSession (idempotent).
- If not attached -> no-op or show Engine not running.

============================================================
END OF FILE
============================================================
