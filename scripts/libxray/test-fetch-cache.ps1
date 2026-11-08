# Exercise release changes without network access or native Windows binaries.
$ErrorActionPreference = 'Stop'
$work = Join-Path ([IO.Path]::GetTempPath()) ([Guid]::NewGuid().ToString('N'))
$out = Join-Path $work 'out'
$fixture = Join-Path $work 'fixture'
$fetch = Join-Path $PSScriptRoot 'fetch-windows.ps1'

function Assert-File($path, $expected) {
    if ((Get-Content -LiteralPath $path -Raw).Trim() -ne $expected) {
        throw "Unexpected content: $path"
    }
}

function New-FixtureZip($name, $content) {
    Set-Content (Join-Path $fixture 'libXray.dll') $content -NoNewline
    Set-Content (Join-Path $fixture 'libXray.h') 'CGoInvoke / CGoFree' -NoNewline
    Compress-Archive -Path (Join-Path $fixture '*') -DestinationPath (Join-Path $out $name) -Force
}

try {
    New-Item -ItemType Directory -Path $out, $fixture -Force | Out-Null
    Set-Content (Join-Path $out 'libXray.dll') 'old' -NoNewline
    Set-Content (Join-Path $out 'libXray.h') 'old' -NoNewline
    Set-Content (Join-Path $out 'VERSION.txt') 'v0.0.0-test' -NoNewline
    New-FixtureZip 'libxray-windows-x64.zip' 'stale-unversioned'
    New-FixtureZip 'libxray-windows-x64-v0.0.1-test.zip' 'release-one'
    & $fetch -Version 'v0.0.1-test' -OutDir $out
    Assert-File (Join-Path $out 'libXray.dll') 'release-one'
    Assert-File (Join-Path $out 'VERSION.txt') 'v0.0.1-test'

    # A matching stamp should reuse the staged DLL instead of extracting again.
    New-FixtureZip 'libxray-windows-x64-v0.0.1-test.zip' 'should-not-replace'
    & $fetch -Version 'v0.0.1-test' -OutDir $out
    Assert-File (Join-Path $out 'libXray.dll') 'release-one'

    New-FixtureZip 'libxray-windows-x64-v0.0.2-test.zip' 'release-two'
    & $fetch -Version 'v0.0.2-test' -OutDir $out
    Assert-File (Join-Path $out 'libXray.dll') 'release-two'
    Assert-File (Join-Path $out 'VERSION.txt') 'v0.0.2-test'

    Remove-Item (Join-Path $out 'VERSION.txt')
    & $fetch -Version 'v0.0.1-test' -OutDir $out
    Assert-File (Join-Path $out 'libXray.dll') 'should-not-replace'
    Assert-File (Join-Path $out 'VERSION.txt') 'v0.0.1-test'
    Write-Host 'PASS: stale, matching and missing stamps; versioned archive selection'
}
finally {
    Remove-Item -Recurse -Force $work
}
