# ARCHITECTURE.md

## Overview

This document describes the interaction model between the **UI** (WPF) and the **Engine** (native process) using IPC. The design supports all lifecycle combinations:

- UI starts first / Engine starts first
- UI can restart without breaking an active VPN session
- Engine can restart/crash and UI recovers
- Connect/Disconnect are **idempotent**

The Engine is the **single source of truth** for VPN session state.

---

## Components

### UI (WPF)
Responsibilities:
- User experience (Connect/Disconnect, status, settings, logs)
- Starting Engine (optional policy)
- Attaching to IPC channels
- Rendering the current state based on Engine snapshot + events

Non-responsibilities:
- UI does **not** own the truth about connection status.
- UI does **not** keep the tunnel alive by itself.

### Engine (Native process)
Responsibilities:
- Establish and maintain the VPN tunnel (drivers, routes, DNS)
- Session state machine (Idle/Connecting/Connected/...)
- Idempotent command handling
- Broadcasting events (state changes, logs, stats)

### IPC (Named Pipes)
Two channels:
- **Control**: request/response commands (RPC)
- **Events**: server-push stream (state/log/error/stats)

---

## Core Principles

1. **Engine is the source of truth** for connection state.
2. UI never assumes state; after attach it always requests `GetStatus`.
3. Commands are **idempotent**:
    - `StartSession` when already connected => OK (already connected)
    - `StopSession` when idle => OK (already idle)
4. Events are incremental; `GetStatus` restores full truth after reconnect.
5. UI and Engine can be started/stopped independently.
6. Engine may keep the session alive without UI (recommended).

---

## Engine State Machine

Primary states:
- `Stopped` (process not running)
- `Idle` (running, no active session)
- `Connecting`
- `Connected`
- `Disconnecting`
- `Error` (with error details and recoverability)

Allowed transitions (high level):
- `Idle -> Connecting -> Connected`
- `Connected -> Disconnecting -> Idle`
- `Connecting -> Error -> Idle` (or stay Error until next command, policy-based)
- `Any -> Error` (unexpected failures)
- `Stopped` is outside Engine FSM (process lifecycle)

---

## IPC Contract

### Control Commands (UI -> Engine)
- `GetStatus`  
  Returns a **snapshot** of current truth:
    - state, active profile, timestamps, last error, etc.
- `StartSession(profileId, options)`
- `StopSession()`
- `Shutdown()` (optional; only if UI controls Engine lifetime)
- `Ping` (optional)

### Events (Engine -> UI)
- `EngineReady`
- `StateChanged(state, details)`
- `Log(message, level, timestamp)`
- `Error(code, message, recoverable)`
- `Stats(...)` (optional)

---

## Lifecycle Policy (recommended default)

**On-demand Engine**:
- UI attempts to attach on startup.
- If attach fails, UI starts Engine and attaches.
- If UI closes, Engine can continue running to keep VPN alive.

Alternative policy:
- Engine runs as a service/daemon (always running). UI only attaches.

---

## UI Logic (high-level)

### Attach & Sync
- UI attaches to Control + Events.
- UI calls `GetStatus` immediately after attach.
- UI renders state from snapshot.
- UI listens to events to update incrementally.

### Connect Button
- Ensure attached (start Engine if needed).
- Call `GetStatus`.
- If `Idle` or `Error` => call `StartSession`.
- If `Connecting` or `Connected` => no-op (or Engine handles idempotently).

### Disconnect Button
- If attached => `StopSession` (idempotent).
- If not attached => no-op / show "Engine not running".

---

## Failure Handling

### Engine Crash / IPC Drop
- UI detects broken pipes / read loops end.
- UI shows "Engine lost" state.
- UI may auto-restart Engine (policy).
- After reattach, UI calls `GetStatus` to resync.

### UI Crash / Restart
- Engine continues.
- UI reattaches and calls `GetStatus` to restore the correct state.

---

## Notes

- Prefer **idempotency in Engine** to simplify UI logic.
- Prefer **snapshot-first** UI rendering to avoid missed events after reconnect.
- Keep the IPC protocol versioned if you expect evolution.
