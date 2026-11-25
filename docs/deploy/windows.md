# Running Dunree on Windows

The files are in [`packaging/windows/`](../../packaging/windows/) and are described in
[`packaging/README.md`](../../packaging/README.md), section "Windows". This page is the short version for an
administrator. Nothing here was run on a real Windows machine by the authors yet: see "Known limits" at the end.

## What gets installed where

| What | Where |
|---|---|
| Program | `C:\Program Files\Dunree\dunree.exe` (one file, no runtime) |
| Data (`conf`, `sys.db`, `sys.uuid`, `log`, `plugins`) | `C:\ProgramData\Dunree`, readable by SYSTEM and Administrators only |
| Service | Windows service `Dunree`, starts at boot |
| Service log | `C:\ProgramData\Dunree\log\service.log`; start, stop and failures also go to the Application event log, source `Dunree` |

Dunree keeps its data in the folder it is started in. The service definition sets that folder; nothing in the
program is tied to these paths.

## Install

There is no download yet (see the [README](../../README.md)). Build the zip with
`tools/build_release.sh --packages --targets windows/amd64` on Linux, or build `dunree.exe` yourself
(`cd src && go build -o dunree.exe`) and put it next to `install.ps1`.

From the unpacked zip, in PowerShell **as Administrator**:

```powershell
powershell -ExecutionPolicy Bypass -File .\install.ps1               # program + service, started
powershell -ExecutionPolicy Bypass -File .\install.ps1 -OpenFirewall # also opens TCP 80/443 and UDP 443
Get-Help .\install.ps1 -Full                                         # -InstallDir, -DataDir, -NoService, -NoStart, -ExpectedSha256
```

Then open `http://localhost:8000` and create the admin account. The admin port is never opened in the firewall.

An installer with a wizard is built from [`packaging/windows/dunree.iss`](../../packaging/windows/dunree.iss)
(Inno Setup 6.3 or newer); it does the same steps.

## Manage the service

In an elevated prompt:

```
dunree.exe service status          exit code 0 running, 3 stopped, 4 not installed
dunree.exe service stop
dunree.exe service start
dunree.exe service uninstall
dunree.exe service install --dir D:\Dunree -- -port=127.0.0.1:8000
```

What follows `--` is stored with the service and used at every start. Each flag is checked when the service is
installed. Stop and a Windows shutdown run the normal stop sequence (requests are drained, statistics are saved).

## Update and remove

* **Update:** unpack the new zip and run `install.ps1` again. The Update page of the admin interface cannot replace
  the program on Windows.
* **Remove:** `powershell -ExecutionPolicy Bypass -File .\uninstall.ps1` keeps the data folder; `-RemoveData` deletes it.

## Without a service

Copy `dunree.exe` into an empty folder and start it there. The data stays in that folder. Stop it with Ctrl+C.

## Known limits

* The service code is compiled and vetted for windows/amd64 and windows/arm64. A CI job that installs, starts and
  removes the service on a Windows runner is defined (`.github/workflows/ci.yaml`) but has not run yet, and the
  scripts and the installer were not used by a person on a real machine.
* The files are not code-signed: SmartScreen warns. Check `dunree.exe` against `SHA256SUMS` of the release
  (`Get-FileHash .\dunree.exe -Algorithm SHA256`).
* No in-app update, no `-doctor` (Linux only), and plugins built for Linux do not run: an add-on needs a
  `windows_amd64` build.
* An install of the Windows build of Zoraxy is not migrated by `install.ps1`. Stop the old program, copy its `conf`, <!-- rebrand:keep -->
  `sys.db` and `sys.uuid` into the data folder before the first start, and read
  [Migrating from Zoraxy](../migrating-from-zoraxy.md). <!-- rebrand:keep -->
