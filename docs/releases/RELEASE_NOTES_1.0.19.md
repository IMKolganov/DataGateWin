# DataGate for Windows — release 1.0.19

## Summary

Hardens Connect UX and Home traffic display after 1.0.18.

## For users

- **Disconnect** stays available while Connecting (cancel a stuck “waiting for events” without using the tray).
- Connect **watchdog** (~75s): if the tunnel never comes up, the session is stopped with a timeout instead of hanging forever.
- Live **traffic chart** shows only while Connected (hidden on start / disconnect); engine-log checkbox unchanged.
- Installer offline QA: sibling `DataGateWinBuild*` folder still skips GitHub download (from 1.0.18).

## Artifacts

- **DataGateWin.v1.0.19.zip**
- **DataGateWin.Installer.exe**

## Upgrade

Install 1.0.19 over the previous build.
