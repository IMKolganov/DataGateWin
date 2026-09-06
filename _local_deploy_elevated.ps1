# Safe elevated stop+deploy for DataGate. Does NOT touch DNS, adapters, or OpenVPN Connect.
$ErrorActionPreference = 'Continue'
$log = 'F:\C++\DataGateWin\_local_install_deploy.log'
function L([string]$m) {
  $line = "[{0}] {1}" -f (Get-Date -Format 's'), $m
  Add-Content -Path $log -Value $line
  Write-Output $line
}

L '=== START elevated deploy ==='

# --- optional: enable RDP so owner can reconnect (no DNS/adapter changes) ---
try {
  Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server' -Name 'fDenyTSConnections' -Value 0 -Type DWord
  Enable-NetFirewallRule -DisplayGroup 'Remote Desktop' -EA SilentlyContinue
  Set-Service -Name TermService -StartupType Manual -EA SilentlyContinue
  Start-Service TermService -EA SilentlyContinue
  $deny = (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server' -Name fDenyTSConnections).fDenyTSConnections
  $tv = (Get-Service TermService -EA SilentlyContinue).Status
  L ("rdp fDenyTSConnections=$deny TermService=$tv")
} catch {
  L ("rdp enable WARN: $($_.Exception.Message)")
}

# --- stop only our processes ---
foreach ($n in @('DataGateWin', 'engine')) {
  Get-Process -Name $n -EA SilentlyContinue | ForEach-Object {
    L ("stop {0} pid={1}" -f $_.ProcessName, $_.Id)
    try { $_.CloseMainWindow() | Out-Null } catch {}
  }
}
Start-Sleep -Seconds 3
foreach ($n in @('engine', 'DataGateWin')) {
  Get-Process -Name $n -EA SilentlyContinue | ForEach-Object {
    L ("force {0} pid={1}" -f $_.ProcessName, $_.Id)
    Stop-Process -Id $_.Id -Force -EA SilentlyContinue
  }
}
Start-Sleep -Seconds 2
& taskkill.exe /F /IM engine.exe /T 2>$null | Out-Null
& taskkill.exe /F /IM DataGateWin.exe /T 2>$null | Out-Null
Start-Sleep -Seconds 2

$left = @(Get-Process -Name DataGateWin,engine -EA SilentlyContinue)
if ($left.Count -gt 0) {
  L ('FAIL still running: ' + (($left | ForEach-Object { "{0}:{1}" -f $_.ProcessName,$_.Id }) -join ', '))
  exit 2
}
L 'processes stopped'

# --- sync install (WinUI unpackaged publish layout) ---
$src = 'F:\C++\DataGateWin\DataGateWin.WinUI\bin\Release\net10.0-windows10.0.26100.0\win-x64\publish'
$dst = 'C:\Program Files\DataGate'
if (-not (Test-Path $src\DataGateWin.exe)) { L "FAIL missing $src\DataGateWin.exe — run Build-Release.ps1 first"; exit 3 }
if (-not (Test-Path $src\engine\engine.exe)) { L "FAIL missing engine.exe"; exit 3 }

New-Item -ItemType Directory -Force -Path $dst | Out-Null
# Mirror app bits; exclude release zip and pdb noise optional
& robocopy.exe $src $dst /E /XO /R:2 /W:1 /NFL /NDL /NJH /NJS `
  /XD '_local_install' `
  /XF 'DataGateWin.v*.zip' '*.pdb' | Out-Null
$rc = $LASTEXITCODE
L ("robocopy exit=$rc (0-7 ok)")
if ($rc -ge 8) { exit 4 }

$exe = Join-Path $dst 'DataGateWin.exe'
$eng = Join-Path $dst 'engine\engine.exe'
L ("exe write=$(Get-Item $exe).LastWriteTime size=$((Get-Item $exe).Length)")
L ("engine write=$(Get-Item $eng).LastWriteTime size=$((Get-Item $eng).Length)")
L ("exe FileVersion=$((Get-Item $exe).VersionInfo.FileVersion)")

# --- launch ---
Start-Process -FilePath $exe -WorkingDirectory $dst
Start-Sleep -Seconds 4
$p = Get-Process -Name DataGateWin -EA SilentlyContinue | Select-Object -First 1
if (-not $p) { L 'FAIL app did not start'; exit 5 }
L ("started DataGateWin pid=$($p.Id) WS_MB=$([math]::Round($p.WorkingSet64/1MB,1))")

# network sanity (do not modify)
$gw = Test-Connection -ComputerName 192.168.0.1 -Count 1 -Quiet
$inet = Test-Connection -ComputerName 8.8.8.8 -Count 1 -Quiet
L ("network gateway=$gw internet=$inet")
if (-not $gw) { L 'WARN gateway unreachable'; exit 6 }

L '=== DONE OK ==='
exit 0
