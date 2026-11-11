# Fetch official libXray Windows x64 release (no Go toolchain required).
# Pin matches Android and Apple clients: XTLS/libXray v26.10.31, API version 3.
param(
    [string]$Version = "v26.10.31",
    [string]$OutDir = ""
)

$ErrorActionPreference = "Stop"
$RepoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..\..")).Path
if (-not $OutDir) {
    $OutDir = Join-Path $RepoRoot "engine\third_party\libxray"
}

New-Item -ItemType Directory -Force -Path $OutDir | Out-Null
$dllOut = Join-Path $OutDir "libXray.dll"
$hdrOut = Join-Path $OutDir "libXray.h"
$stampOut = Join-Path $OutDir "VERSION.txt"
$cachedVersion = if (Test-Path -LiteralPath $stampOut) { (Get-Content -LiteralPath $stampOut -Raw).Trim() } else { "" }

if ((Test-Path -LiteralPath $dllOut) -and (Test-Path -LiteralPath $hdrOut) -and $cachedVersion -eq $Version) {
    Write-Host "Already present: $dllOut"
    Write-Host "Already present: $hdrOut"
    exit 0
}

$zipCandidates = @(
    (Join-Path $RepoRoot "third_party\libxray\libxray-windows-x64-$Version.zip"),
    (Join-Path $OutDir "libxray-windows-x64-$Version.zip")
)

$zip = $null
foreach ($c in $zipCandidates) {
    if (Test-Path -LiteralPath $c) {
        $zip = $c
        Write-Host "Using cached zip: $zip"
        break
    }
}

if (-not $zip) {
    $zip = Join-Path $OutDir "libxray-windows-x64-$Version.zip"
    $url = "https://github.com/XTLS/libXray/releases/download/$Version/libxray-windows-x64.zip"
    Write-Host "Downloading $url ..."
    Invoke-WebRequest -Uri $url -OutFile $zip -UseBasicParsing
}

$extract = Join-Path $OutDir "_extract"
if (Test-Path $extract) { Remove-Item -Recurse -Force $extract }
Expand-Archive -Path $zip -DestinationPath $extract -Force

$dll = Get-ChildItem $extract -Recurse -Filter "libXray.dll" | Select-Object -First 1
$hdr = Get-ChildItem $extract -Recurse -Filter "libXray.h" | Select-Object -First 1
if (-not $dll -or -not $hdr) { throw "libXray.dll / libXray.h not found in zip" }

Copy-Item -Force $dll.FullName $dllOut
Copy-Item -Force $hdr.FullName $hdrOut
Remove-Item -Recurse -Force $extract

# Keep a pin stamp for docs/CI.
Set-Content -Path $stampOut -Value $Version -NoNewline

Write-Host "OK: $dllOut ($((Get-Item $dllOut).Length) bytes)"
Write-Host "OK: $hdrOut"
Write-Host "Pin: $Version"
