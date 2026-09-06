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
# Prefer non-Platform publish dir (dotnet publish -r win-x64 writes here) over bin\x64\...
$src = 'F:\C++\DataGateWin\DataGateWin.WinUI\bin\Release\net10.0-windows10.0.26100.0\win-x64\publish'
if (-not (Test-Path $src\DataGateWin.exe)) {
  $src = 'F:\C++\DataGateWin\DataGateWin.WinUI\bin\x64\Release\net10.0-windows10.0.26100.0\win-x64\publish'
}
$dst = 'C:\Program Files\DataGate'
if (-not (Test-Path $src\DataGateWin.exe)) { L "FAIL missing $src\DataGateWin.exe — run Build-Release.ps1 first"; exit 3 }
if (-not (Test-Path $src\DataGateWin.pri)) { L "FAIL missing $src\DataGateWin.pri — XAML will not load"; exit 3 }
$priLen = (Get-Item $src\DataGateWin.pri).Length
L ("src=$src priBytes=$priLen")
if ($priLen -lt 100000) { L "FAIL DataGateWin.pri too small ($priLen) — need SDK EmbeddedData PRI with themes"; exit 3 }
if (-not (Test-Path $src\engine\engine.exe)) { L "FAIL missing engine.exe"; exit 3 }

New-Item -ItemType Directory -Force -Path $dst | Out-Null
# Mirror app bits; /IS /IT force overwrite same/tweaked files (avoid stale tiny PRI).
& robocopy.exe $src $dst /E /IS /IT /R:2 /W:1 /NFL /NDL /NJH /NJS `
  /XD '_local_install' `
  /XF 'DataGateWin.v*.zip' '*.pdb' | Out-Null
$rc = $LASTEXITCODE
L ("robocopy exit=$rc (0-7 ok)")
if ($rc -ge 8) { exit 4 }

# Drop pre-1.0.7 Start Menu name "DataGate OpenVPN 3" so Start shows DataGate only.
$startFolder = Join-Path $env:ProgramData 'Microsoft\Windows\Start Menu\Programs\DataGate'
foreach ($legacy in @('DataGate OpenVPN 3.lnk', 'DataGateOpenVPN3.lnk')) {
  $p = Join-Path $startFolder $legacy
  if (Test-Path $p) {
    Remove-Item $p -Force -EA SilentlyContinue
    L ("removed legacy Start shortcut: $legacy")
  }
}
$desktopLegacy = Join-Path ([Environment]::GetFolderPath('CommonDesktopDirectory')) 'DataGate OpenVPN 3.lnk'
if (Test-Path $desktopLegacy) {
  Remove-Item $desktopLegacy -Force -EA SilentlyContinue
  L 'removed legacy Desktop shortcut: DataGate OpenVPN 3.lnk'
}
# Ensure current Start shortcut exists with ProductName=DataGate
$exe = Join-Path $dst 'DataGateWin.exe'
$lnk = Join-Path $startFolder 'DataGate.lnk'
New-Item -ItemType Directory -Force -Path $startFolder | Out-Null
$ws = New-Object -ComObject WScript.Shell
$sc = $ws.CreateShortcut($lnk)
$sc.TargetPath = $exe
$sc.WorkingDirectory = $dst
$sc.Description = 'DataGate'
$iconCandidates = @(
  (Join-Path $dst 'Images\favicon.ico'),
  (Join-Path $dst 'Assets\favicon.ico'),
  (Join-Path $dst 'Assets\AppIcon.ico')
)
$icon = $iconCandidates | Where-Object { Test-Path $_ } | Select-Object -First 1
if ($icon) { $sc.IconLocation = "$icon,0" } else { $sc.IconLocation = "$exe,0" }
$sc.Save()
L "Start shortcut refreshed: $lnk icon=$($sc.IconLocation)"

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
