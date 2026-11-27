# vigil installer for Windows
#
#   irm https://raw.githubusercontent.com/suleymenb/vigil/master/install.ps1 | iex
#
# Windows 7 / PowerShell 2 (no irm):
#   (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/suleymenb/vigil/master/install.ps1') | iex
#
# Options (environment variables):
#   $env:VIGIL_VERSION = 'v0.6.0'          install a specific release (default: latest)
#   $env:VIGIL_INSTALL_DIR = 'C:\tools'    install somewhere else (default: %LOCALAPPDATA%\Programs\vigil)
#
# Downloads the binary for your Windows version and CPU from GitHub Releases,
# verifies its SHA-256 checksum, installs vigil.exe and adds the folder to
# your user PATH. No administrator rights needed.

$ErrorActionPreference = 'Stop'
$repo = 'suleymenb/vigil'
$version = if ($env:VIGIL_VERSION) { $env:VIGIL_VERSION } else { 'latest' }
$dir = if ($env:VIGIL_INSTALL_DIR) { $env:VIGIL_INSTALL_DIR } else { Join-Path $env:LOCALAPPDATA 'Programs\vigil' }

# GitHub needs TLS 1.2; old .NET defaults to TLS 1.0.
try { [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor 3072 } catch { }

$build = [Environment]::OSVersion.Version.Build
$arch = $env:PROCESSOR_ARCHITECTURE
if ($env:PROCESSOR_ARCHITEW6432) { $arch = $env:PROCESSOR_ARCHITEW6432 }
if ($build -lt 10240) {
    if ($arch -ne 'AMD64') { throw "vigil: Windows 7/8 builds exist for 64-bit x86 only (found $arch)" }
    $target = 'x86_64-win7-windows-msvc'
    Write-Host 'Windows 7/8 detected: installing the experimental build (built in CI, not tested there).' -ForegroundColor Yellow
} elseif ($arch -eq 'ARM64') {
    $target = 'aarch64-pc-windows-msvc'
} elseif ($arch -eq 'AMD64') {
    $target = 'x86_64-pc-windows-msvc'
} else {
    throw "vigil: no prebuilt binary for $arch. Build from source: cargo install --git https://github.com/$repo"
}

if ($version -eq 'latest') { $base = "https://github.com/$repo/releases/latest/download" }
else { $base = "https://github.com/$repo/releases/download/$version" }
$asset = "vigil-$target.zip"
$tmp = Join-Path ([IO.Path]::GetTempPath()) ('vigil-' + [Guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $tmp | Out-Null
$zipPath = Join-Path $tmp $asset

try {
    $wc = New-Object Net.WebClient
    Write-Host "-> downloading $asset ($version)"
    $wc.DownloadFile("$base/$asset", $zipPath)
    $wc.DownloadFile("$base/$asset.sha256", "$zipPath.sha256")

    Write-Host '-> verifying checksum'
    $sha = [Security.Cryptography.SHA256]::Create()
    $fs = [IO.File]::OpenRead($zipPath)
    try { $hash = -join ($sha.ComputeHash($fs) | ForEach-Object { $_.ToString('x2') }) } finally { $fs.Close() }
    $expected = ((Get-Content "$zipPath.sha256" | Select-Object -First 1) -split '\s+')[0].ToLower()
    if ($hash -ne $expected) { throw "vigil: checksum mismatch for $asset (expected $expected, got $hash)" }

    if (Get-Command Expand-Archive -ErrorAction SilentlyContinue) {
        Expand-Archive -Path $zipPath -DestinationPath $tmp -Force
    } else {
        # PowerShell 2-4: let Explorer's zip support do it (16 = yes to all, 4 = no progress).
        $shell = New-Object -ComObject Shell.Application
        $shell.NameSpace($tmp).CopyHere($shell.NameSpace($zipPath).Items(), 20)
    }

    New-Item -ItemType Directory -Force -Path $dir | Out-Null
    Copy-Item (Join-Path $tmp "vigil-$target\vigil.exe") (Join-Path $dir 'vigil.exe') -Force
} finally {
    Remove-Item -Recurse -Force $tmp -ErrorAction SilentlyContinue
}

$userPath = [Environment]::GetEnvironmentVariable('Path', 'User')
if (-not $userPath) { $userPath = '' }
if (($userPath -split ';') -notcontains $dir) {
    [Environment]::SetEnvironmentVariable('Path', ($userPath.TrimEnd(';') + ';' + $dir).TrimStart(';'), 'User')
    Write-Host "   added $dir to your user PATH (open a new terminal to use it)"
}
$v = & (Join-Path $dir 'vigil.exe') --version
Write-Host "OK $v installed to $dir\vigil.exe" -ForegroundColor Green
Write-Host '   run it with: vigil     (as administrator to see the event log and every process)'
Write-Host '   network doctor: vigil doctor'
