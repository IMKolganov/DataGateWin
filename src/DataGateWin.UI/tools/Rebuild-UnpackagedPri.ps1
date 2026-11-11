param(
    [Parameter(Mandatory = $true)][string]$PublishDir,
    [Parameter(Mandatory = $true)][string]$IntermediateDir,
    [Parameter(Mandatory = $true)][string]$AssemblyName,
    [Parameter(Mandatory = $true)][string]$MakePri,
    [Parameter(Mandatory = $false)][string]$OutputPri = ''
)

$ErrorActionPreference = 'Stop'

$PublishDir = [System.IO.Path]::GetFullPath($PublishDir)
$IntermediateDir = [System.IO.Path]::GetFullPath($IntermediateDir)
if (-not (Test-Path $PublishDir)) { throw "PublishDir missing: $PublishDir" }

# Prefer the SDK-built app PRI (EmbeddedData for app XBF + merged Controls/LiveCharts themes).
# A Path-only rebuild drops Microsoft.UI.Xaml theme maps and breaks XamlControlsResources / NavigationView.
$candidates = @()
if ($OutputPri) { $candidates += $OutputPri }
$candidates += (Join-Path $IntermediateDir ($AssemblyName + '.pri'))
# OutDir is typically ..\..\..\bin\... relative to Intermediate; also search nearby bin.
$binGuess = Join-Path (Split-Path (Split-Path (Split-Path $IntermediateDir -Parent) -Parent) -Parent) ($AssemblyName + '.pri')
$candidates += $binGuess
$candidates += (Get-ChildItem -LiteralPath (Split-Path $PublishDir -Parent) -Filter ($AssemblyName + '.pri') -Recurse -ErrorAction SilentlyContinue |
    Where-Object { $_.FullName -notlike '*\publish\*' } |
    Sort-Object LastWriteTime -Descending |
    Select-Object -ExpandProperty FullName -First 3)

$srcPri = $null
foreach ($c in $candidates) {
    if ($c -and (Test-Path -LiteralPath $c)) {
        $len = (Get-Item -LiteralPath $c).Length
        # Tiny Path-only PRIs are ~1-6KB; real SDK PRI with themes is >100KB.
        if ($len -gt 100000) { $srcPri = (Get-Item -LiteralPath $c).FullName; break }
    }
}

if (-not $srcPri) {
    throw "No SDK-built $AssemblyName.pri (>100KB) found near Intermediate/Output. Candidates tried: $($candidates -join '; ')"
}

$destPri = Join-Path $PublishDir ($AssemblyName + '.pri')
Copy-Item -LiteralPath $srcPri -Destination $destPri -Force

# Also stage loose XBF for tooling/debug (LoadComponent uses EmbeddedData from PRI).
$xbfs = @(Get-ChildItem -LiteralPath $IntermediateDir -Filter '*.xbf' -File -Recurse -ErrorAction SilentlyContinue |
    Where-Object { ($_.FullName -notmatch '[\\/]Localization[\\/]') -and ($_.Name -notlike 'Strings.*.xbf') })

$publishFiles = Join-Path $PublishDir 'Files'
New-Item -ItemType Directory -Path $publishFiles -Force | Out-Null
Get-ChildItem -LiteralPath $PublishDir -Filter '*.xbf' -File -ErrorAction SilentlyContinue | Remove-Item -Force

$copied = 0
foreach ($f in $xbfs) {
    $rel = $f.FullName.Substring($IntermediateDir.Length).TrimStart('\', '/')
    if ($rel.StartsWith('embed\', [StringComparison]::OrdinalIgnoreCase) -or $rel.StartsWith('embed/', [StringComparison]::OrdinalIgnoreCase)) {
        $rel = $rel.Substring(6)
    }
    $relNorm = $rel -replace '/', '\'
    if ($relNorm -match '(?i)^Localization\\' -or $f.Name -like 'Strings.*.xbf') { continue }

    Copy-Item $f.FullName (Join-Path $PublishDir $f.Name) -Force
    $destNested = Join-Path $publishFiles $relNorm
    $destDir = Split-Path $destNested -Parent
    if (-not (Test-Path $destDir)) { New-Item -ItemType Directory -Path $destDir -Force | Out-Null }
    Copy-Item $f.FullName $destNested -Force
    $copied++
}

Write-Host ("Staged SDK PRI {0} size={1} looseXbf={2}" -f $destPri, (Get-Item $destPri).Length, $copied)
