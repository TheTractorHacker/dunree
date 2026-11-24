# Packaging Dunree

Everything needed to install Dunree on Windows, macOS, Linux, FreeBSD and in a container. Dunree is one program file with no runtime to install; the files here only put it in the right place and register it with the service manager of the system.

Dunree is published by Foley IT under AGPL-3.0. It is based on Zoraxy v3.3.6 by tobychui and imuslab and is an independent project that is not endorsed by them (see `NOTICE`). Every package carries `LICENSE`, `NOTICE` and `THIRD_PARTY_NOTICES.md`.

No signing key, certificate or password belongs in this folder. Release files are signed with the release key by `tools/build_release.sh` (`SHA256SUMS` and `SHA256SUMS.sig`); code signing for Windows and macOS is a step for the owner, described below.

## What is where

| System | Files | Program | Data (conf, sys.db, log, plugins) | Service |
|---|---|---|---|---|
| Windows | `windows/install.ps1`, `uninstall.ps1`, `dunree.iss` (Inno Setup), `winget/` | `%ProgramFiles%\Dunree\dunree.exe` | `%ProgramData%\Dunree` | Windows service `Dunree` |
| macOS | `macos/ie.foleyit.dunree.plist`, `build-pkg.sh`, `scripts/`, `uninstall.sh` | `/usr/local/bin/dunree` | `/usr/local/var/dunree` | launchd `ie.foleyit.dunree` |
| Linux, tarball | `linux/install.sh`, `dunree.service` | `/opt/dunree/dunree` | `/opt/dunree` | systemd `dunree.service` |
| Linux, .deb / .rpm | `linux/nfpm.yaml`, `dunree-package.service`, `dunree.default`, `scripts/` | `/usr/bin/dunree` | `/var/lib/dunree` | systemd `dunree.service`, flags in `/etc/default/dunree` |
| FreeBSD | `freebsd/dunree` (rc.d) | `/usr/local/bin/dunree` | `/var/db/dunree` | `service dunree`, settings in `/etc/rc.conf` |
| Container | `container/Dockerfile`, `compose.yaml`, `compose.socket-proxy.yaml` | `/usr/local/bin/dunree` | `/opt/dunree/config`, `/opt/dunree/plugin` | the container |

Dunree keeps its data in the folder it is started in, on every system. The service definitions set that folder; nothing in the program is tied to these paths.

## Building the release files

```bash
tools/build_release.sh -t vX.Y.Z-topic.N -b BUILD --packages
```

builds `dunree_<os>_<arch>[.exe]` for Linux (amd64, arm64, arm, 386, riscv64, mipsle), Windows (amd64, arm64) and macOS (amd64, arm64), the archives, and the `.deb` / `.rpm` when [nfpm](https://nfpm.goreleaser.com) is installed, then signs and verifies `SHA256SUMS`. Useful switches:

* `--dry-run` prints what would be built and signed. It builds nothing and needs no key.
* `--targets linux/amd64,windows/amd64` builds a subset. `freebsd/amd64` and `freebsd/arm64` are only built when named here.
* `--no-legacy-names` leaves out the `zoraxy_linux_<arch>` copies (see "Legacy names").

`packaging/build_packages.sh --dist DIR --version X.Y.Z` builds only the archives and packages from binaries that are already in `DIR`.

Two packages need their own system and are built by hand from the binaries in `dist/`:

* **Windows installer:** on Windows with Inno Setup 6.3 or newer, `iscc /DAppVersion=X.Y.Z /DArch=amd64 /DSourceExe=...\dunree_windows_amd64.exe packaging\windows\dunree.iss` (and again with `arm64`).
* **macOS package:** on macOS, `packaging/macos/build-pkg.sh --version X.Y.Z --dist dist` (a universal program for Intel and Apple silicon).

### Legacy names

The updater inside an existing install asks a release for `zoraxy_linux_<arch>`. Every Linux binary is therefore also written under that name: a byte-identical copy, listed in the same signed `SHA256SUMS`. Windows and macOS never had in-app updates, so they get no copy.

### Checks

```bash
packaging/test.sh                    # scripts, units, manifests, archive layout; .deb/.rpm when nfpm is installed
tools/build_release_test.sh          # argument handling and --dry-run (compiles nothing)
tools/build_release_test.sh --build  # really builds, packages, signs and verifies two targets with a throwaway key
```

CI (`.github/workflows/ci.yaml`) runs these, compiles all twelve targets, and runs the Windows service and the macOS package on real Windows and macOS machines.

## Windows

`dunree.exe` has the service manager built in:

```
dunree.exe service install [--dir FOLDER] [--manual] [-- -flag=value ...]
dunree.exe service uninstall | start | stop | status
```

* **Data folder.** `%ProgramData%\Dunree` unless `--dir` is given. It is created so that only SYSTEM and the Administrators group can read it (it holds the database, private keys and tokens). A folder that already exists keeps its permissions.
* **Log.** A service has no console. What Dunree would print, and the trace of a crash, go to `<data folder>\log\service.log` (moved to `service.log.1` at a start when larger than 10 MB). The normal Dunree logs are next to it. Start, stop and failures are also written to the Application event log, source `Dunree`.
* **Start and stop.** The service reports "starting" until the admin port is bound. Stop, and the notice Windows sends before a shutdown, run the normal stop sequence (in-flight requests are drained, statistics are saved) and the service then reports "stopped". A crash or a failed start is restarted by Windows after 5 s, 15 s, then every minute.
* **Flags.** What follows `--` is stored with the service and used at every start. Each flag is checked at install time; a flag that does not exist, or that would make Dunree exit at once, is refused.
* **`service status`** exits with 0 when running, 3 when stopped, 4 when not installed.

`install.ps1` (in the zip) copies the program to `%ProgramFiles%\Dunree`, registers and starts the service, and upgrades an existing install in place. `-OpenFirewall` adds inbound rules for TCP 80/443 and UDP 443; the admin port is never opened. The Inno Setup installer does the same with a wizard.

**Code signing** is not set up. Unsigned files show a SmartScreen warning. To sign, the owner adds a sign tool to Inno Setup (`SignTool=`, see the head of `dunree.iss`) and signs `dunree.exe` with `signtool` before packaging; the key stays on the signing machine or in an HSM.

**winget.** `windows/winget/*.tmpl` are the three manifest files for the identifier `FoleyIT.Dunree`. `render.sh` fills in the version, the download address and the SHA-256 of the two installers. All addresses are arguments because the home of the project is not decided. Nothing is submitted by the script.

## macOS

The `.pkg` installs the program, the launchd job and the licence files, creates `/usr/local/var/dunree` (root only) and starts the daemon. `sudo touch /usr/local/var/dunree/.no-autostart` before installing keeps it from starting. The tarball holds the same files for a manual install (`README-macos.txt`).

The package and the program are **not signed or notarised**; Gatekeeper asks the user to confirm. `build-pkg.sh --sign "Developer ID Installer: ..."` signs with an identity from the keychain of the build machine; notarisation is a separate step (see the head of the script).

## Linux

* **Tarball:** `sudo ./install.sh` installs into `/opt/dunree` and writes `/etc/systemd/system/dunree.service`. It refuses to overwrite an existing unit or binary and does not start the service unless `--start` is given. `--dry-run` shows the steps.
* **.deb / .rpm:** the service is installed but **not enabled and not started** on a first install, because another reverse proxy (for example an existing `zoraxy.service`) may hold the same ports. `sudo systemctl enable --now dunree` starts it. On an upgrade a running service is restarted. Removing the package never deletes `/var/lib/dunree`.

Both units use `Type=notify`, restart on failure and the conservative hardening of `docs/deploy/zoraxy.service`. An existing `zoraxy.service` and `/opt/zoraxy` are not touched by any of this; renaming an existing install is optional and done with `tools/install/migrate-from-zoraxy.sh`.

With the packages, the program file belongs to the package manager: upgrade with `apt` / `dnf`. The Update page cannot replace `/usr/bin/dunree` (the unit makes `/usr` read-only for the service) and says so in its preflight check.

## FreeBSD

`freebsd/dunree` is an rc.d script that runs Dunree under `daemon(8)` (restart after a crash, output to `/var/log/dunree.log`). Dunree's own flags go in `dunree_args`, not in `dunree_flags`.

## Container

```bash
docker buildx build -f packaging/container/Dockerfile --platform linux/amd64,linux/arm64 -t dunree:local .
docker compose -f packaging/container/compose.yaml up -d --build
```

The Go program is cross-compiled on the build machine, so extra architectures need no emulation. The image is compatible with the one it replaces: the same environment variables (`docker/entrypoint.py`), the same ports, and `/opt/zoraxy/config` and `/opt/zoraxy/plugin` still work because `/opt/zoraxy` is a link to `/opt/dunree`. The image name is a variable everywhere (`DUNREE_IMAGE` in compose, the repository variable `DOCKER_IMAGE` in `.github/workflows/docker.yml`); there is no default registry and the workflow is skipped until the variable is set.

`compose.yaml` publishes the admin port on `127.0.0.1` only and does not mount the Docker socket.

## Known limits

See "Deployable on every platform" under "Dunree rebrand" in `docs/ux/changes.md`.
