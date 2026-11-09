# Offline startup DNS recovery

The November 2026 report describes connectivity returning after uninstalling the VPN
and running multiple network-reset commands. It does not establish which command
helped or prove a particular Windows update caused the outage.

An actionable startup defect was found: DNS recovery happened when the VPN engine
was started, after authentication could already require working DNS. The UI now
awaits recovery immediately after elevation and resolving the engine path, before
configuration prompts, token initialization, authentication and update requests.

The installer performs its own recovery before opening its install window or
running quiet installation. It uses built-in registry/service APIs and the system
ipconfig, so neither downloaded files nor a working installed engine is required.

Both paths detect OpenVPNDNSRouting NRPT entries and OriginalSearchList /
InitialSearchList backup values, and leave healthy systems unchanged. The installer
also rechecks for an active VPN immediately before recovery and verifies that the
artifacts disappeared. Active engines and live NRPT owner PIDs prevent cleanup;
uncertain access to an owner prevents mutation. These are OpenVPN conventions,
not exclusive DataGate ownership markers, so other OpenVPN clients must be closed
before stale-state recovery.

The recovery restores backed-up SearchList values and removes OpenVPN NRPT rules.
It does not reset physical-adapter DNS, Winsock, proxy settings, all NRPT policies,
or arbitrary routes. Remaining faults in those components require diagnosis;
successful cleanup is not a claim that Internet connectivity has been verified.

Installer diagnostics: `%LOCALAPPDATA%\DataGateWin\installer-network-recovery.log`.
Application diagnostics: `%LOCALAPPDATA%\DataGateWin\startup-error.log`.

## Validation

Automated policy tests cover healthy startup, active session refusal, successful
cleanup and verification, incomplete cleanup, a session starting during detection,
and ownership probe failure. They inject recovery operations and do not change
the developer machine's network configuration.

Before release, use an isolated Windows VM snapshot to exercise actual DNS changes:

1. With no VPN active, seed an OpenVPNDNSRouting-0 rule and OpenVPN SearchList backup
   values in the documented registry locations. Keep an unrelated NRPT rule.
2. Launch the installer without an installed engine and without logging in. Verify
   cleanup occurs before any download, SearchList is restored, and the unrelated
   rule remains. Verify subsequent DNS resolution and downloading work.
3. Repeat with the application logged out, then with an expired stored token.
   Verify recovery finishes before authentication requests.
4. Repeat on a healthy snapshot: no registry writes or cache flush should occur.
5. With a live VPN session, launch the installer: recovery must skip that session.
6. Deny registry write access: logs must indicate failure or incomplete cleanup.

The actual outage on the customer's laptop has not been reproduced locally.
