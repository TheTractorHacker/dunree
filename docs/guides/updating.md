# Updating Dunree

Answers Zoraxy issues #494 (how do I update a bare-metal install) and #1174 (Docker maintainer). <!-- rebrand:keep -->

Coming from Zoraxy (the original project, or a `v3.3.6-fork.N` build of the fork that became Dunree)? Read [Migrating from Zoraxy](../migrating-from-zoraxy.md) first: what the first Dunree start does, cookies, environment variables, the systemd unit and Docker. <!-- rebrand:keep -->

Names on this page: the program file is `dunree`, the service `dunree.service`, the folder `/opt/dunree`. An install that was upgraded in place keeps its old names (`zoraxy`, `zoraxy.service`, `/opt/zoraxy`, or wherever it lives): use those instead. Nothing renames them for you. <!-- rebrand:keep -->

**There is no Dunree download yet.** Until the project has a home with releases, updating means building the new version from source (`cd src && go build -o dunree`) and replacing the program file as in section B. The in-app update of section A installs Dunree releases only, so it has nothing to offer until one exists. It never moves a build of the earlier fork to Dunree: that switch is done by replacing the program file ([Migrating from Zoraxy](../migrating-from-zoraxy.md)). <!-- rebrand:keep -->

## What gets updated, where your data lives

Dunree keeps everything in paths that are **relative to the working directory it was started from** unless you
override them: `./conf/`, `./sys.db`, `./sys.uuid`, `./log/`, `./www/`, `./plugins/`, `./tmp/` (flags `-conf`,
`-dbpath`, `-uuid`, `-log`, `-webroot`, `-plugin`, `-tmp`). Starting the binary from another directory therefore
creates a second, empty installation. For a service always set `WorkingDirectory=` (systemd) or pass absolute
paths. The binary itself holds no data, so updating = replacing the binary.

## A. In-app update (Linux, not in Docker, not from a .deb / .rpm)

***System > Update***. It reads the signed releases of its release source, which is shown on the page: today
`TheTractorHacker/zoraxy`, the repository of the fork that became Dunree, until a Dunree repository has releases
(`-update_repo owner/name` changes it). Only Dunree releases count (program files named `dunree_<os>_<arch>` and a
signed list that names the product); the fork's own `v3.x` releases in that source are skipped. It asks only when you open the page or press *Check for updates*; the optional
daily check (off by default) asks once a day and only shows a badge. There is no automatic update. Channels: *stable* (default)
and *beta* (includes pre-releases). Install downloads the binary for your CPU, verifies the ed25519 signature of
`SHA256SUMS` and the file's SHA-256, runs `<binary> -version`, saves the previous binary for **rollback** (a separate
button; configuration is not reverted) and then **restarts Dunree itself** (about 5-20 seconds of downtime; the page
shows the restart method it will use). The buttons are disabled with an explanation inside Docker. With a `.deb` /
`.rpm` install the preflight check reports that the program file cannot be replaced (`/usr/bin/dunree` is read-only
for the service): update with `apt` / `dnf`.
There is also a *run migrations only* action. Details: `DEVELOPMENT.md`, section "Updating / releasing".

## B. Manual update (any install)

```bash
# 1. back up data (binary directory = where your service starts it)
cd /opt/dunree                                     # the WorkingDirectory= of your unit
systemctl stop dunree
cp -a conf sys.db sys.uuid /safe/place/            # at least these three
# 2. get the new program for your CPU: build it (cd src && go build -o dunree_linux_amd64), or take
#    dunree_linux_amd64 and SHA256SUMS from the release you were given and check the file:
sha256sum -c SHA256SUMS --ignore-missing
# 3. replace the old program, keep the same user/permissions, start
install -m 0755 dunree_linux_amd64 /opt/dunree/dunree    # the file ExecStart= of your unit names
systemctl start dunree
```

Configuration is migrated automatically on start (`-cfgupgrade` is on by default). If something is wrong, stop the
service, put the old binary and the backed-up `conf/` + `sys.db` back. `sha256sum` proves the file is the one the
list names, not who made the list: the signature of `SHA256SUMS` is checked by the in-app updater, or by hand with
`go run tools/sign_release.go -verify -dist <folder> -pub src/mod/updater/release_pubkey.pem`.

Other systems: Windows and macOS are updated by running their installer again ([Windows](../deploy/windows.md),
[macOS](../deploy/macos.md)), a `.deb` / `.rpm` install with the package manager, FreeBSD by replacing
`/usr/local/bin/dunree`. `tools/build_release.sh` builds all of them (Go version in `src/go.mod`).

"I pulled the git repository but `go build` shows no new version": a source checkout only changes when you
`git pull` the branch/tag you want **and** rebuild (`cd src && go build -o ../dunree`), then replace the running binary.

## C. Docker

There is **no published Dunree image**: the image name is a variable everywhere and no registry is set up. You build
the image yourself, and you update by building it again:

```bash
git pull                                              # or check out the tag you want
docker compose -f packaging/container/compose.yaml up -d --build     # builds dunree:local and recreates the container
```

With your own compose file: `docker buildx build -f packaging/container/Dockerfile -t dunree:local .`, then
`docker compose up -d` with `image: dunree:local`.

The mounted folders keep your data (`/opt/dunree/config` and `/opt/dunree/plugin`; a compose file that mounts the
older paths `/opt/zoraxy/config` and `/opt/zoraxy/plugin` keeps working, they are links). The in-app updater is
disabled in containers. Details, environment variables and the multi-architecture build: [docker/README.md](../../docker/README.md).

The image `zoraxydocker/zoraxy` on Docker Hub belongs to the Zoraxy project: a different product, without Dunree. <!-- rebrand:keep -->
