# Running Dunree on macOS

The files are in [`packaging/macos/`](../../packaging/macos/) and are described in
[`packaging/README.md`](../../packaging/README.md), section "macOS". This page is the short version for an
administrator. Nothing here was run on a real Mac by the authors yet: see "Known limits" at the end.

## What gets installed where

| What | Where |
|---|---|
| Program | `/usr/local/bin/dunree` (`amd64` = Intel, `arm64` = Apple silicon; the `.pkg` holds a universal program) |
| Data (`conf`, `sys.db`, `sys.uuid`, `plugins`) | `/usr/local/var/dunree`, root only |
| Log | `/usr/local/var/log/dunree/dunree.log` |
| Service | launchd job `ie.foleyit.dunree` (`/Library/LaunchDaemons/ie.foleyit.dunree.plist`): starts at boot, restarts after a crash |

Dunree keeps its data in the folder it is started in. The launchd job sets that folder; nothing in the program
is tied to these paths.

## Try it without installing

```sh
mkdir ~/dunree && cp dunree ~/dunree/ && cd ~/dunree && ./dunree
```

Open `http://localhost:8000`. Stop with Ctrl+C. The data stays in `~/dunree`. If macOS refuses to start a
downloaded copy: `xattr -d com.apple.quarantine ./dunree`.

## Install as a system service

There is no download yet (see the [README](../../README.md)). Either build the package on a Mac with
`packaging/macos/build-pkg.sh --version X.Y.Z --dist dist` and open the `.pkg`, or install by hand from the
tarball (ports 80 and 443 need root):

```sh
sudo mkdir -p /usr/local/bin /usr/local/var/dunree /usr/local/var/log/dunree
sudo chmod 750 /usr/local/var/dunree
sudo cp dunree /usr/local/bin/dunree
sudo cp ie.foleyit.dunree.plist /Library/LaunchDaemons/
sudo chown root:wheel /Library/LaunchDaemons/ie.foleyit.dunree.plist
sudo launchctl bootstrap system /Library/LaunchDaemons/ie.foleyit.dunree.plist
```

`sudo touch /usr/local/var/dunree/.no-autostart` before opening the `.pkg` keeps the package from starting the job.

## Manage the service

```sh
sudo launchctl print system/ie.foleyit.dunree | head       # state
sudo launchctl bootout system/ie.foleyit.dunree            # stop
sudo launchctl bootstrap system /Library/LaunchDaemons/ie.foleyit.dunree.plist   # start
sudo launchctl kickstart -k system/ie.foleyit.dunree       # restart
```

Flags of the program are the `ProgramArguments` of the plist; edit it, then `bootout` and `bootstrap` again.

## Update and remove

* **Update:** replace `/usr/local/bin/dunree` with the new program (or open the new `.pkg`) and restart the job.
  The Update page of the admin interface only installs Linux builds.
* **Remove:** `sudo packaging/macos/uninstall.sh` keeps the data; `--remove-data` deletes `/usr/local/var/dunree` and the logs.

## Known limits

* The package and the program are not signed or notarised: Gatekeeper asks the user to confirm.
  `build-pkg.sh --sign "Developer ID Installer: ..."` signs with an identity of the build machine; notarisation is a
  separate step described at the head of that script.
* `build-pkg.sh` was only run with `--dry-run` by the authors. A CI job that builds the package on a macOS runner is
  defined (`.github/workflows/ci.yaml`) but has not run yet.
* No in-app update, no `-doctor` (Linux only), and plugins built for Linux do not run: an add-on needs a
  `darwin_arm64` or `darwin_amd64` build.
