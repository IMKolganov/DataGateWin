# Generates DataGateWin.UI Localization/Strings.{code}.xaml from Android values-*/strings.xml
# Master keys/English from Strings.en.xaml; Android snake_case keys mapped from WPF Pascal_Snake keys.

param(
    [string]$AndroidResRoot = "F:\Android\DataGateAndroid\app\src\main\res",
    [string]$WpfRoot = "$PSScriptRoot\..\DataGateWin.UI"
)

$ErrorActionPreference = "Stop"

function ConvertTo-AndroidKey([string] $wpfKey) {
    $parts = $wpfKey -split '_'
    $out = @()
    foreach ($p in $parts) {
        if ([string]::IsNullOrEmpty($p)) { continue }
        $s = [regex]::Replace($p, '(?<!^)(?=[A-Z][a-z])|(?<=[a-z])(?=[A-Z])', '_').ToLowerInvariant()
        $out += $s
    }
    ($out -join '_')
}

function Escape-XamlText([string] $t) {
    if ($null -eq $t) { return "" }
    return $t.Replace('&', '&amp;').Replace('<', '&lt;').Replace('>', '&gt;').Replace('"', '&quot;')
}

function Parse-AndroidStrings([string] $xmlPath) {
    $d = @{}
    if (-not (Test-Path $xmlPath)) { return $d }
    [xml]$x = Get-Content -LiteralPath $xmlPath -Encoding UTF8
    foreach ($el in $x.resources.string) {
        $name = $el.name
        if (-not $name) { continue }
        $inner = $el.InnerText
        if ($null -eq $inner) { $inner = "" }
        $d[$name] = $inner
    }
    return $d
}

function Parse-WpfEnKeys([string] $enXamlPath) {
    $txt = Get-Content -LiteralPath $enXamlPath -Raw -Encoding UTF8
    $keys = [regex]::Matches($txt, 'x:Key="([^"]+)"') | ForEach-Object { $_.Groups[1].Value }
    $lines = $txt -split "`n"
    $map = @{}
    foreach ($key in $keys) {
        $pattern = 'x:Key="' + [regex]::Escape($key) + '"[^>]*>([^<]*)</sys:String>'
        $m = [regex]::Match($txt, $pattern, [System.Text.RegularExpressions.RegexOptions]::Singleline)
        if ($m.Success) {
            $map[$key] = $m.Groups[1].Value.Trim()
        }
    }
    return $map
}

$folderToCode = @{
    "values"       = "en"
    "values-ar"    = "ar"
    "values-bg"    = "bg"
    "values-cs"    = "cs"
    "values-da"    = "da"
    "values-de"    = "de"
    "values-el"    = "el"
    "values-es"    = "es"
    "values-es-rMX" = "es-mx"
    "values-et"    = "et"
    "values-fa-rIR" = "fa"
    "values-fi"    = "fi"
    "values-fil"   = "fil"
    "values-fr"    = "fr"
    "values-ga"    = "ga"
    "values-hi-rIN" = "hi"
    "values-hr"    = "hr"
    "values-hu"    = "hu"
    "values-in"    = "id"
    "values-it"    = "it"
    "values-ja"    = "ja"
    "values-ko"    = "ko"
    "values-lt"    = "lt"
    "values-lv"    = "lv"
    "values-mt"    = "mt"
    "values-nl"    = "nl"
    "values-pl"    = "pl"
    "values-pt"    = "pt"
    "values-pt-rBR" = "pt-br"
    "values-ro"    = "ro"
    "values-ru"    = "ru"
    "values-sk"    = "sk"
    "values-sl"    = "sl"
    "values-sv"    = "sv"
    "values-th"    = "th"
    "values-tr"    = "tr"
    "values-uk"    = "uk"
    "values-vi"    = "vi"
    "values-zh-rCN" = "zh-hans"
    "values-zh-rTW" = "zh-hant"
}

$enXaml = Join-Path $WpfRoot "Localization\Strings.en.xaml"
$wpfMap = Parse-WpfEnKeys $enXaml

# Do not skip keys: Lang_Name_system et al. must exist in every locale (fallback to EN in loop below).
$skipKeys = @()

foreach ($kv in $folderToCode.GetEnumerator()) {
    $folder = $kv.Key
    $code = $kv.Value
    if ($code -eq "en") { continue }

    $androidPath = Join-Path (Join-Path $AndroidResRoot $folder) "strings.xml"
    $android = Parse-AndroidStrings $androidPath

    $sb = [System.Text.StringBuilder]::new()
    [void]$sb.AppendLine('<ResourceDictionary xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"')
    [void]$sb.AppendLine('                    xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml"')
    [void]$sb.AppendLine('                    xmlns:sys="clr-namespace:System;assembly=System.Runtime">')
    [void]$sb.AppendLine()

    $written = 0
    foreach ($wpfKey in ($wpfMap.Keys | Sort-Object)) {
        if ($wpfKey -in $skipKeys) { continue }

        $androidKey = ConvertTo-AndroidKey $wpfKey
        $value = $null
        if ($android.ContainsKey($androidKey)) {
            $value = $android[$androidKey]
        }
        elseif ($wpfMap.ContainsKey($wpfKey)) {
            $value = $wpfMap[$wpfKey]
        }

        if ($null -eq $value) { continue }

        $esc = Escape-XamlText $value
        [void]$sb.AppendLine(('    <sys:String x:Key="{0}">{1}</sys:String>' -f $wpfKey, $esc))
        $written++
    }

    [void]$sb.AppendLine('</ResourceDictionary>')

    $outPath = Join-Path $WpfRoot "Localization\Strings.$code.xaml"
    Set-Content -LiteralPath $outPath -Value $sb.ToString() -Encoding UTF8
    Write-Host "Wrote $outPath ($written strings)"
}

Write-Host "Done."
