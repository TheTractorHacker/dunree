<#
.SYNOPSIS
  Installs Dunree on Windows from the release zip and registers it as a Windows service.

.DESCRIPTION
  Run from an elevated PowerShell in the unpacked zip folder:

      powershell -ExecutionPolicy Bypass -File .\install.ps1

  What it does:
    1. copies dunree.exe (and the licence files) to -InstallDir
    2. registers the service "Dunree" with "dunree.exe service install" (data folder -DataDir)
    3. starts the service

  An existing install is upgraded in place: the service is stopped, the program file is
  replaced and the service is started again. The registered service (its flags and data
  folder) and the data folder are not changed by an upgrade.

  Nothing is downloaded and nothing outside -InstallDir, -DataDir and the service
  registration is changed. Windows Firewall is only changed with -OpenFirewall.

.PARAMETER InstallDir
  Where the program goes. Default: %ProgramFiles%\Dunree

.PARAMETER DataDir
  Where the configuration, database, certificates, logs and plugins go.
  Default: %ProgramData%\Dunree (created so that only SYSTEM and Administrators can read it)

.PARAMETER ServiceArgs
  Dunree flags for the service, each written as -name=value.
  Example: -ServiceArgs '-port=127.0.0.1:8000','-webui_tls=auto'

.PARAMETER ExpectedSha256
  When given, dunree.exe must have this SHA-256 (from the signed SHA256SUMS of the release)
  or nothing is installed.

.PARAMETER NoService
  Copy the files only. Do not register or start a service.

.PARAMETER NoStart
  Register the service but do not start it.

.PARAMETER OpenFirewall
  Add inbound Windows Firewall rules for TCP 80 and 443 (and UDP 443 for HTTP/3) for dunree.exe.
  Off by default. The admin port (8000) is never opened by this script.
#>
[CmdletBinding()]
param(
    [string]$InstallDir = (Join-Path $env:ProgramFiles 'Dunree'),
    [string]$DataDir = (Join-Path $env:ProgramData 'Dunree'),
    [string[]]$ServiceArgs = @(),
    [string]$ExpectedSha256 = '',
    [switch]$NoService,
    [switch]$NoStart,
    [switch]$OpenFirewall
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

function Test-Administrator {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

if (-not (Test-Administrator)) {
    throw 'Run this script from an elevated (Administrator) PowerShell.'
}

$source = Join-Path $PSScriptRoot 'dunree.exe'
if (-not (Test-Path -LiteralPath $source -PathType Leaf)) {
    throw "dunree.exe not found next to install.ps1 ($PSScriptRoot)."
}

if ($ExpectedSha256 -ne '') {
    $actual = (Get-FileHash -LiteralPath $source -Algorithm SHA256).Hash
    if ($actual -ne $ExpectedSha256.Trim().ToUpperInvariant()) {
        throw "dunree.exe has SHA-256 $actual, expected $ExpectedSha256. Nothing was installed."
    }
    Write-Host 'Checksum of dunree.exe is correct.'
}

foreach ($a in $ServiceArgs) {
    if ($a -notmatch '^-{1,2}[A-Za-z0-9_-]+(=.*)?$') {
        throw "Service argument '$a' is not written as -name=value."
    }
}

$target = Join-Path $InstallDir 'dunree.exe'
$service = Get-Service -Name 'Dunree' -ErrorAction SilentlyContinue
$wasRunning = $false

if ($null -ne $service -and $service.Status -ne 'Stopped') {
    Write-Host 'Stopping the Dunree service for the upgrade...'
    $wasRunning = $true
    if (Test-Path -LiteralPath $target -PathType Leaf) {
        & $target service stop
        if ($LASTEXITCODE -ne 0) { throw "Could not stop the Dunree service (exit code $LASTEXITCODE)." }
    } else {
        Stop-Service -Name 'Dunree' -Force
    }
}

New-Item -ItemType Directory -Path $InstallDir -Force | Out-Null
Copy-Item -LiteralPath $source -Destination $target -Force
foreach ($doc in 'LICENSE.txt', 'NOTICE.txt', 'THIRD_PARTY_NOTICES.md', 'README-windows.txt', 'uninstall.ps1') {
    $docSource = Join-Path $PSScriptRoot $doc
    if (Test-Path -LiteralPath $docSource -PathType Leaf) {
        Copy-Item -LiteralPath $docSource -Destination (Join-Path $InstallDir $doc) -Force
    }
}
Write-Host "Program installed in $InstallDir"

if ($NoService) {
    Write-Host 'No service registered (-NoService).'
    Write-Host "Start by hand from the folder that should hold the data: `"$target`""
    return
}

if ($null -eq $service) {
    $installArgs = @('service', 'install', '--dir', $DataDir)
    if ($ServiceArgs.Count -gt 0) {
        $installArgs += '--'
        $installArgs += $ServiceArgs
    }
    & $target @installArgs
    if ($LASTEXITCODE -ne 0) { throw "dunree.exe service install failed (exit code $LASTEXITCODE)." }
} else {
    Write-Host 'The Dunree service is already registered: its flags and data folder were not changed.'
    if ($ServiceArgs.Count -gt 0 -or $PSBoundParameters.ContainsKey('DataDir')) {
        Write-Warning 'To change -DataDir or -ServiceArgs run "dunree.exe service uninstall" first, then this script again. The data folder is kept.'
    }
}

if ($OpenFirewall) {
    $rules = @(
        @{ Name = 'Dunree HTTP (TCP 80)'; Protocol = 'TCP'; Port = 80 },
        @{ Name = 'Dunree HTTPS (TCP 443)'; Protocol = 'TCP'; Port = 443 },
        @{ Name = 'Dunree HTTP/3 (UDP 443)'; Protocol = 'UDP'; Port = 443 }
    )
    foreach ($r in $rules) {
        if (-not (Get-NetFirewallRule -DisplayName $r.Name -ErrorAction SilentlyContinue)) {
            New-NetFirewallRule -DisplayName $r.Name -Direction Inbound -Action Allow -Protocol $r.Protocol -LocalPort $r.Port -Program $target | Out-Null
            Write-Host "Firewall rule added: $($r.Name)"
        }
    }
}

if ($NoStart -and -not $wasRunning) {
    Write-Host 'Service registered but not started (-NoStart). Start it with: dunree.exe service start'
    return
}

& $target service start
if ($LASTEXITCODE -ne 0) {
    throw "The Dunree service did not start (exit code $LASTEXITCODE). See the service.log file in the log folder of the data folder."
}
Write-Host ''
Write-Host 'Dunree is running. Open http://localhost:8000 on this machine to create the admin account.'
Write-Host 'The data folder and the log file are shown by: dunree.exe service status'
