# Install a verified Juardrails release binary for Windows.
$ErrorActionPreference = 'Stop'
$architecture = switch ([System.Runtime.InteropServices.RuntimeInformation]::OSArchitecture.ToString()) {
    'X64' { 'amd64' }
    'Arm64' { 'arm64' }
    default { throw 'Unsupported Windows CPU architecture.' }
}
$asset = "juardrails-windows-$architecture.exe"
$version = if ($env:JUARDRAILS_VERSION) { $env:JUARDRAILS_VERSION } else { 'latest' }
if ($version -eq 'latest') {
    $latest = Invoke-RestMethod 'https://api.github.com/repos/abhaybhargav/juardrails/releases/latest'
    $version = [string]$latest.tag_name
}
if ($version -notmatch '^v[0-9][a-zA-Z0-9._-]*$') {
    throw 'JUARDRAILS_VERSION must be a release tag such as v0.1.0.'
}
$base = "https://github.com/abhaybhargav/juardrails/releases/download/$version"
$tempDir = Join-Path ([IO.Path]::GetTempPath()) ([Guid]::NewGuid().ToString())
New-Item -ItemType Directory -Path $tempDir | Out-Null
try {
    $binary = Join-Path $tempDir $asset
    $checksums = Join-Path $tempDir 'SHA256SUMS'
    Invoke-WebRequest "$base/$asset" -OutFile $binary
    Invoke-WebRequest "$base/SHA256SUMS" -OutFile $checksums
    $line = Get-Content $checksums | Where-Object { $_ -match ("^[0-9a-fA-F]{64}\s+" + [regex]::Escape($asset) + '$') } | Select-Object -First 1
    if (-not $line) { throw 'Release checksum is missing.' }
    $expected = ($line -split '\s+')[0]
    $actual = (Get-FileHash -Algorithm SHA256 $binary).Hash
    if ($actual -ine $expected) { throw 'Release checksum mismatch.' }
    $installDir = if ($env:JUARDRAILS_INSTALL_DIR) { $env:JUARDRAILS_INSTALL_DIR } else { Join-Path $env:LOCALAPPDATA 'Juardrails\bin' }
    New-Item -ItemType Directory -Path $installDir -Force | Out-Null
    $destination = Join-Path $installDir 'juardrails.exe'
    Copy-Item $binary $destination -Force
    Write-Host "Installed $destination"
    & $destination version
    if (($env:Path -split ';') -notcontains $installDir) {
        Write-Host "Add $installDir to PATH to run juardrails from any directory."
    }
} finally {
    Remove-Item $tempDir -Recurse -Force
}
