# Ensures every Strings.{code}.xaml has exactly the keys in Strings.en.xaml.
# Existing translations are kept; missing keys are filled from English.
param(
    [string]$WpfRoot = "$PSScriptRoot\..\DataGateWin.UI"
)

$ErrorActionPreference = "Stop"
$locDir = Join-Path $WpfRoot "Localization"
$enPath = Join-Path $locDir "Strings.en.xaml"

function Read-StringsXaml([string]$path) {
    $d = [ordered]@{}
    if (-not (Test-Path $path)) { return $d }
    Get-Content -LiteralPath $path -Encoding UTF8 | ForEach-Object {
        $line = $_
        if ($line -match '<sys:String x:Key="([^"]+)">(.*)</sys:String>\s*$') {
            $d[$matches[1]] = $matches[2]
        }
    }
    return $d
}

function Write-StringsXaml([string]$path, [hashtable]$keyToInnerText) {
    $sb = [System.Text.StringBuilder]::new()
    [void]$sb.AppendLine('<ResourceDictionary xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"')
    [void]$sb.AppendLine('                    xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml"')
    [void]$sb.AppendLine('                    xmlns:sys="clr-namespace:System;assembly=System.Runtime">')
    [void]$sb.AppendLine()

    foreach ($key in ($keyToInnerText.Keys | Sort-Object)) {
        $inner = $keyToInnerText[$key]
        [void]$sb.AppendLine(('    <sys:String x:Key="{0}">{1}</sys:String>' -f $key, $inner))
    }

    [void]$sb.AppendLine('</ResourceDictionary>')
    [void]$sb.AppendLine()

    $utf8NoBom = New-Object System.Text.UTF8Encoding $false
    [System.IO.File]::WriteAllText($path, $sb.ToString(), $utf8NoBom)
}

$en = Read-StringsXaml $enPath
if ($en.Count -eq 0) { throw "No keys parsed from $enPath" }

Get-ChildItem -LiteralPath $locDir -Filter "Strings.*.xaml" | Where-Object { $_.Name -ne "Strings.en.xaml" } | ForEach-Object {
    $locPath = $_.FullName
    $loc = Read-StringsXaml $locPath
    $merged = @{}
    foreach ($key in ($en.Keys | Sort-Object)) {
        if ($loc.Contains($key)) {
            $merged[$key] = $loc[$key]
        }
        else {
            $merged[$key] = $en[$key]
        }
    }
    Write-StringsXaml $locPath $merged
    Write-Host "Merged $($merged.Count) keys -> $($_.Name)"
}

Write-Host "Done."
