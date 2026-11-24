<#
.SYNOPSIS
  Removes the Dunree Windows service and program files.

.DESCRIPTION
  Run from an elevated PowerShell:

      powershell -ExecutionPolicy Bypass -File .\uninstall.ps1

  The data folder (configuration, database, certificates, logs) is kept unless
  -RemoveData is given. Firewall rules added by install.ps1 -OpenFirewall are removed.

.PARAMETER InstallDir
  Where the program was installed. Default: %ProgramFiles%\Dunree

.PARAMETER DataDir
  The data folder. Only used with -RemoveData. Default: %ProgramData%\Dunree

.PARAMETER RemoveData
  Also delete the data folder. This cannot be undone.
#>
[CmdletBinding()]
param(
    [string]$InstallDir = (Join-Path $env:ProgramFiles 'Dunree'),
    [string]$DataDir = (Join-Path $env:ProgramData 'Dunree'),
    [switch]$RemoveData
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = New-Object Security.Principal.WindowsPrincipal($identity)
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'Run this script from an elevated (Administrator) PowerShell.'
}

$target = Join-Path $InstallDir 'dunree.exe'
if (Test-Path -LiteralPath $target -PathType Leaf) {
    & $target service uninstall
    if ($LASTEXITCODE -ne 0) { throw "dunree.exe service uninstall failed (exit code $LASTEXITCODE). Nothing was deleted." }
} elseif (Get-Service -Name 'Dunree' -ErrorAction SilentlyContinue) {
    Stop-Service -Name 'Dunree' -Force -ErrorAction SilentlyContinue
    & (Join-Path $env:SystemRoot 'System32\sc.exe') delete Dunree | Out-Null
}

foreach ($name in 'Dunree HTTP (TCP 80)', 'Dunree HTTPS (TCP 443)', 'Dunree HTTP/3 (UDP 443)') {
    Get-NetFirewallRule -DisplayName $name -ErrorAction SilentlyContinue | Remove-NetFirewallRule
}

if (Test-Path -LiteralPath $InstallDir -PathType Container) {
    # Only the files the installer put there; anything else in the folder is left alone.
    foreach ($file in 'dunree.exe', 'LICENSE.txt', 'NOTICE.txt', 'THIRD_PARTY_NOTICES.md', 'README-windows.txt') {
        $path = Join-Path $InstallDir $file
        if (Test-Path -LiteralPath $path -PathType Leaf) { Remove-Item -LiteralPath $path -Force }
    }
    $self = Join-Path $InstallDir 'uninstall.ps1'
    if ((Test-Path -LiteralPath $self -PathType Leaf) -and ($PSCommandPath -ne $self)) { Remove-Item -LiteralPath $self -Force }
    if (-not (Get-ChildItem -LiteralPath $InstallDir -Force | Where-Object { $_.Name -ne 'uninstall.ps1' })) {
        Write-Host "Program files removed from $InstallDir (delete the empty folder by hand if this script ran from it)."
    } else {
        Write-Host "Program files removed. Other files in $InstallDir were left alone."
    }
}

if ($RemoveData) {
    if (Test-Path -LiteralPath $DataDir -PathType Container) {
        Remove-Item -LiteralPath $DataDir -Recurse -Force
        Write-Host "Data folder $DataDir deleted."
    }
} else {
    Write-Host "The data folder $DataDir was kept."
}
