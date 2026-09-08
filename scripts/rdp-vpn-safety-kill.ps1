# RDP safety: after N minutes force-stop DataGate VPN stack and recover DNS.
# Run this BEFORE connecting VPN when testing over Remote Desktop.
param(
    [int]$Minutes = 5,
    [string]$InstallDir = "C:\Program Files\DataGate",
    [switch]$AlsoScheduleTask
)

$ErrorActionPreference = "Continue"
$logDir = Join-Path $env:LOCALAPPDATA "DataGateWin"
New-Item -ItemType Directory -Force -Path $logDir | Out-Null
$log = Join-Path $logDir "rdp-vpn-safety-kill.log"

function L([string]$m) {
    $line = "[{0}] {1}" -f (Get-Date -Format "s"), $m
    Add-Content -LiteralPath $log -Value $line
    Write-Host $line
}

function Stop-DataGateStack {
    L "stopping DataGateWin + engine..."
    foreach ($n in @("DataGateWin", "engine")) {
        Get-Process -Name $n -ErrorAction SilentlyContinue | ForEach-Object {
            L ("  close {0} pid={1}" -f $_.ProcessName, $_.Id)
            try { $_.CloseMainWindow() | Out-Null } catch {}
        }
    }
    Start-Sleep -Seconds 2
    foreach ($n in @("engine", "DataGateWin")) {
        Get-Process -Name $n -ErrorAction SilentlyContinue | ForEach-Object {
            L ("  kill {0} pid={1}" -f $_.ProcessName, $_.Id)
            Stop-Process -Id $_.Id -Force -ErrorAction SilentlyContinue
        }
    }
    & taskkill.exe /F /IM engine.exe /T 2>$null | Out-Null
    & taskkill.exe /F /IM DataGateWin.exe /T 2>$null | Out-Null
}

function Invoke-DnsRecover {
    $engine = Join-Path $InstallDir "engine\engine.exe"
    if (-not (Test-Path -LiteralPath $engine)) {
        L "recover-dns skipped: engine.exe missing at $engine"
        return
    }
    L "running engine --recover-dns..."
    try {
        $p = Start-Process -FilePath $engine -ArgumentList "--recover-dns" -Wait -PassThru -WindowStyle Hidden
        L ("recover-dns exit={0}" -f $p.ExitCode)
    }
    catch {
        L ("recover-dns WARN: {0}" -f $_.Exception.Message)
    }
}

if ($AlsoScheduleTask) {
    # One-shot task survives RDP disconnect better than a console in the session.
    $when = (Get-Date).AddMinutes([Math]::Max(1, $Minutes))
    $arg = "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`" -Minutes 0 -InstallDir `"$InstallDir`""
    $tn = "DataGateVpnRdpSafetyKill"
    try {
        Unregister-ScheduledTask -TaskName $tn -Confirm:$false -ErrorAction SilentlyContinue
        $action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument $arg
        $trigger = New-ScheduledTaskTrigger -Once -At $when
        # Highest available for current user; may prompt UAC when created elevated.
        $principal = New-ScheduledTaskPrincipal -UserId $env:USERNAME -LogonType Interactive -RunLevel Highest
        Register-ScheduledTask -TaskName $tn -Action $action -Trigger $trigger -Principal $principal -Force | Out-Null
        L "scheduled task '$tn' at $($when.ToString('s')) (~$Minutes min). Log: $log"
        L "cancel: Unregister-ScheduledTask -TaskName $tn -Confirm:`$false"
        exit 0
    }
    catch {
        L ("Register-ScheduledTask failed: {0} — falling back to sleep" -f $_.Exception.Message)
    }
}

if ($Minutes -gt 0) {
    L "RDP VPN safety armed: will kill DataGate + recover-dns in $Minutes minute(s). Log: $log"
    L "Tip: cancel with: Get-Process powershell | where ... or schtasks /Delete /TN DataGateVpnRdpSafetyKill /F"
    Start-Sleep -Seconds ($Minutes * 60)
}

L "=== SAFETY FIRE ==="
Stop-DataGateStack
Start-Sleep -Seconds 1
Invoke-DnsRecover
$left = @(Get-Process -Name DataGateWin, engine -ErrorAction SilentlyContinue)
if ($left.Count -eq 0) {
    L "OK: DataGate processes gone"
}
else {
    L ("WARN still running: " + (($left | ForEach-Object { "{0}:{1}" -f $_.ProcessName, $_.Id }) -join ", "))
}
L "=== SAFETY DONE ==="
