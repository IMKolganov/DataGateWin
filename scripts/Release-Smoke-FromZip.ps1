# Release smoke: extract the GitHub-style ZIP and prove the app stays alive.
# This is the gate that would have caught 1.0.20 (publish folder worked; installed ZIP died).
param(
    [Parameter(Mandatory = $true)]
    [string]$ZipPath,
    [int]$AliveSeconds = 8
)

$ErrorActionPreference = "Stop"
if (-not (Test-Path -LiteralPath $ZipPath)) {
    throw "ZIP not found: $ZipPath"
}

Add-Type -AssemblyName System.IO.Compression.FileSystem
$zip = [System.IO.Compression.ZipFile]::OpenRead((Resolve-Path $ZipPath))
try {
    $mui = @($zip.Entries | Where-Object { $_.FullName -like "*.mui" }).Count
    if ($mui -lt 1) {
        throw "ZIP has zero *.mui entries — refuse smoke (install would FailFast 0x80073B01)."
    }
    Write-Host "ZIP MUI entries: $mui"
}
finally {
    $zip.Dispose()
}

$work = Join-Path $env:TEMP ("DataGateZipSmoke_" + [Guid]::NewGuid().ToString("N"))
New-Item -ItemType Directory -Force -Path $work | Out-Null
try {
    Expand-Archive -LiteralPath $ZipPath -DestinationPath $work -Force
    $exe = Join-Path $work "DataGateWin.exe"
    if (-not (Test-Path $exe)) {
        throw "DataGateWin.exe missing after extract: $work"
    }

    $log = Join-Path $env:LOCALAPPDATA "DataGateWin\startup-error.log"
    if (Test-Path $log) { Remove-Item -Force $log }

    $p = Start-Process -FilePath $exe -WorkingDirectory $work -PassThru
    Start-Sleep -Seconds $AliveSeconds

    if ($p.HasExited) {
        $tail = if (Test-Path $log) { Get-Content $log -Raw } else { "(no startup-error.log)" }
        throw "FAIL: process exited $($p.ExitCode) within ${AliveSeconds}s. Log:`n$tail"
    }

    if (-not (Test-Path $log) -or ((Get-Content $log -Raw) -notmatch "ShowMain done")) {
        Stop-Process -Id $p.Id -Force -EA SilentlyContinue
        throw "FAIL: process alive but startup-error.log missing 'ShowMain done'."
    }

    Write-Host "PASS: pid=$($p.Id) alive ${AliveSeconds}s after ShowMain done"
    Stop-Process -Id $p.Id -Force -EA SilentlyContinue
    Get-Process engine -EA SilentlyContinue | Stop-Process -Force -EA SilentlyContinue
}
finally {
    Start-Sleep -Seconds 1
    Remove-Item -LiteralPath $work -Recurse -Force -EA SilentlyContinue
}
