# Compare Strings.*.xaml key sets to Strings.en.xaml
$ErrorActionPreference = 'Stop'
$loc = Join-Path $PSScriptRoot '..\DataGateWin.UI\Localization'
$enPath = Join-Path $loc 'Strings.en.xaml'
$enRaw = Get-Content $enPath -Raw -Encoding UTF8
$enKeys = [regex]::Matches($enRaw, 'x:Key="([^"]+)"') | ForEach-Object { $_.Groups[1].Value } | Sort-Object -Unique
Write-Host "Strings.en.xaml keys: $($enKeys.Count)"

$issues = @()
Get-ChildItem $loc -Filter 'Strings.*.xaml' | Where-Object { $_.Name -ne 'Strings.en.xaml' } | ForEach-Object {
    $raw = Get-Content $_.FullName -Raw -Encoding UTF8
    $keys = [regex]::Matches($raw, 'x:Key="([^"]+)"') | ForEach-Object { $_.Groups[1].Value } | Sort-Object -Unique
    $missing = Compare-Object $enKeys $keys | Where-Object SideIndicator -eq '<=' | ForEach-Object InputObject
    $extra = Compare-Object $enKeys $keys | Where-Object SideIndicator -eq '=>' | ForEach-Object InputObject
    if ($missing -or $extra -or ($keys.Count -ne $enKeys.Count)) {
        $issues += [PSCustomObject]@{
            File = $_.Name
            KeyCount = $keys.Count
            Missing = @($missing)
            Extra = @($extra)
        }
    }
}

if ($issues.Count -eq 0) {
    Write-Host 'All locale files have the same key count as EN.'
} else {
    foreach ($i in $issues) {
        Write-Host "--- $($i.File) keys=$($i.KeyCount) ---"
        if ($i.Missing.Count) { Write-Host ('  MISSING ({0}): {1}' -f $i.Missing.Count, ($i.Missing -join ', ')) }
        if ($i.Extra.Count) { Write-Host ('  EXTRA ({0}): {1}' -f $i.Extra.Count, ($i.Extra -join ', ')) }
    }
}
