<#
.SYNOPSIS
  End-to-end check of the Dunree Windows service. For CI (job "windows-service") or a test machine.

.DESCRIPTION
  Needs an elevated PowerShell and a machine where no Dunree service is installed: it registers
  the real service "Dunree" with a private data folder and removes it again.

      powershell -ExecutionPolicy Bypass -File packaging\windows\test-service.ps1 -Exe .\dunree.exe

  Steps: status (not installed, exit 4) -> install -> status (stopped, exit 3) -> start ->
  admin interface answers -> status (running, exit 0) -> stop within 45 s -> files are in the
  data folder -> uninstall -> status (exit 4). The service is always removed at the end.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$Exe,
    [int]$Port = 18000
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

$Exe = (Resolve-Path -LiteralPath $Exe).Path
$data = Join-Path ([IO.Path]::GetTempPath()) ('dunree-svc-test-' + [Guid]::NewGuid().ToString('N'))
$script:failed = 0

function Step([string]$Name, [int]$WantExit, [string[]]$Arguments) {
    # Windows PowerShell 5 turns redirected error output of a program into a terminating error under 'Stop'
    $ErrorActionPreference = 'Continue'
    $output = & $Exe @Arguments 2>&1 | Out-String
    $code = $LASTEXITCODE
    if ($code -eq $WantExit) {
        Write-Host "ok    $Name (exit $code)"
    } else {
        Write-Host "FAIL  $Name : exit $code, expected $WantExit"
        Write-Host $output
        $script:failed++
    }
}

if (Get-Service -Name 'Dunree' -ErrorAction SilentlyContinue) {
    throw 'A Dunree service is already installed on this machine. This test would replace it; not running.'
}

try {
    Step 'status before install' 4 @('service', 'status')
    Step 'unknown action is a usage error' 2 @('service', 'bogus')
    Step 'unknown flag is refused at install' 2 @('service', 'install', '--', '-no_such_flag=1')
    Step 'install' 0 @('service', 'install', '--dir', $data, '--manual', '--', "-port=127.0.0.1:$Port", '-mdns=false', '-default_inbound_enabled=false', '-offline=true')
    Step 'second install is refused' 1 @('service', 'install')
    Step 'status after install' 3 @('service', 'status')

    $acl = (Get-Acl -LiteralPath $data).Access | ForEach-Object { $_.IdentityReference.Value }
    if ($acl | Where-Object { $_ -match 'Users|Everyone|Authenticated' }) {
        Write-Host "FAIL  data folder is readable by: $($acl -join ', ')"
        $script:failed++
    } else {
        Write-Host "ok    data folder is private ($($acl -join ', '))"
    }

    Step 'start' 0 @('service', 'start')
    Step 'start when running' 0 @('service', 'start')
    Step 'status when running' 0 @('service', 'status')

    $answered = $false
    for ($i = 0; $i -lt 30 -and -not $answered; $i++) {
        try {
            $r = Invoke-WebRequest -Uri "http://127.0.0.1:$Port/" -UseBasicParsing -TimeoutSec 5 -MaximumRedirection 0 -ErrorAction Stop
            $answered = $true
        } catch {
            if ($_.Exception.Response) { $answered = $true } else { Start-Sleep -Seconds 1 }
        }
    }
    if ($answered) { Write-Host 'ok    admin interface answers' } else { Write-Host 'FAIL  admin interface does not answer'; $script:failed++ }

    $watch = [Diagnostics.Stopwatch]::StartNew()
    Step 'stop' 0 @('service', 'stop')
    Write-Host ("      stop took {0:n1} s" -f $watch.Elapsed.TotalSeconds)
    if ($watch.Elapsed.TotalSeconds -gt 45) { Write-Host 'FAIL  stop took longer than 45 s'; $script:failed++ }
    Step 'stop when stopped' 0 @('service', 'stop')
    Step 'status after stop' 3 @('service', 'status')

    foreach ($item in 'conf', 'sys.uuid', 'log\service.log') {
        if (Test-Path -LiteralPath (Join-Path $data $item)) {
            Write-Host "ok    $item is in the data folder"
        } else {
            Write-Host "FAIL  $item is not in the data folder"
            $script:failed++
        }
    }
    $log = Get-Content -LiteralPath (Join-Path $data 'log\service.log') -Raw
    if ($log -notmatch 'Starting Dunree as a Windows service') { Write-Host 'FAIL  service.log has no start line'; $script:failed++ }

    # A clean stop must not count as a failure: no "terminated unexpectedly" event from the service manager.
    $crash = Get-WinEvent -FilterHashtable @{ LogName = 'System'; ProviderName = 'Service Control Manager'; Id = 7031, 7034; StartTime = (Get-Date).AddMinutes(-10) } -ErrorAction SilentlyContinue |
        Where-Object { $_.Message -match 'Dunree' }
    if ($crash) { Write-Host 'FAIL  the service manager recorded an unexpected termination'; $script:failed++ } else { Write-Host 'ok    the stop was reported as clean' }
} finally {
    & $Exe service uninstall | Out-Host
    $svcLog = Join-Path $data 'log\service.log'
    if (Test-Path -LiteralPath $svcLog) {
        Write-Host '--- service.log ---'
        Get-Content -LiteralPath $svcLog | Select-Object -Last 60 | Out-Host
    }
    Remove-Item -LiteralPath $data -Recurse -Force -ErrorAction SilentlyContinue
}

Step 'status after uninstall' 4 @('service', 'status')
Step 'uninstall when not installed' 0 @('service', 'uninstall')

if ($script:failed -gt 0) {
    Write-Host "$($script:failed) check(s) FAILED"
    exit 1
}
Write-Host 'OK, Windows service checks passed'
exit 0
