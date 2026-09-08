# Deploy (if needed) is separate. This starts RDP safety timer, then launches DataGate.
param(
    [int]$Minutes = 5,
    [string]$InstallDir = "C:\Program Files\DataGate",
    [switch]$SkipLaunch,
    [switch]$UseScheduledTask
)

$ErrorActionPreference = "Stop"
$killScript = Join-Path $PSScriptRoot "rdp-vpn-safety-kill.ps1"
if (-not (Test-Path -LiteralPath $killScript)) {
    throw "Missing $killScript"
}

$exe = Join-Path $InstallDir "DataGateWin.exe"
if (-not (Test-Path -LiteralPath $exe)) {
    throw "Missing $exe — deploy first (_local_deploy_elevated.ps1)"
}

Write-Host "=== Arm RDP VPN safety ($Minutes min) ===" -ForegroundColor Cyan
if ($UseScheduledTask) {
    & powershell.exe -NoProfile -ExecutionPolicy Bypass -File $killScript -Minutes $Minutes -InstallDir $InstallDir -AlsoScheduleTask
}
else {
    # Detached hidden sleeper — keeps running if RDP window closes (usually).
    Start-Process -FilePath "powershell.exe" -ArgumentList @(
        "-NoProfile", "-ExecutionPolicy", "Bypass",
        "-File", $killScript,
        "-Minutes", "$Minutes",
        "-InstallDir", $InstallDir
    ) -WindowStyle Hidden
    Write-Host "Safety process started (hidden). Log: $env:LOCALAPPDATA\DataGateWin\rdp-vpn-safety-kill.log"
}

if ($SkipLaunch) {
    Write-Host "SkipLaunch set — app not started."
    exit 0
}

Write-Host "=== Launch DataGateWin ===" -ForegroundColor Cyan
# Elevated launch preferred for TUN; prompt UAC if needed.
Start-Process -FilePath $exe -WorkingDirectory $InstallDir -Verb RunAs
Write-Host "Launched. You have ~$Minutes minutes before auto-kill + DNS recover."
Write-Host "Cancel safety: schtasks /Delete /TN DataGateVpnRdpSafetyKill /F"
Write-Host "  or kill the hidden powershell running rdp-vpn-safety-kill.ps1"
