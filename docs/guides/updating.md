# Updating Dunree (and what this fork ships)

Answers upstream #494 (how do I update a bare-metal install) and #1174 (Docker maintainer).

Coming from Zoraxy (upstream or a `v3.3.6-fork.N` build)? Read `docs/migrating-from-zoraxy.md` first: what the first Dunree start does, cookies, environment variables, the systemd unit and Docker. <!-- rebrand:keep -->

## What gets updated, where your data lives

Dunree keeps everything in paths that are **relative to the working directory it was started from** unless you
override them: `./conf/`, `./sys.db`, `./sys.uuid`, `./log/`, `./www/`, `./plugins/`, `./tmp/` (flags `-conf`,
`-dbpath`, `-uuid`, `-log`, `-webroot`, `-plugin`, `-tmp`). Starting the binary from another directory therefore
creates a second, empty installation. For a service always set `WorkingDirectory=` (systemd) or pass absolute
paths. The binary itself holds no data, so updating = replacing the binary.

## A. In-app update (this fork, Linux, not in Docker)

*System menu > Others > **Update***. It checks the signed releases of `TheTractorHacker/zoraxy` only when you open
the page or press *Check for updates* (no background traffic, no automatic update). Channels: *stable* (default)
and *beta* (includes pre-releases). Install downloads the binary for your CPU, verifies the ed25519 signature of
`SHA256SUMS` and the file's SHA-256, runs `<binary> -version`, saves the previous binary for **rollback** (a separate
button; configuration is not reverted) and then **restarts Dunree itself** (about 5-20 seconds of downtime; the page
shows the restart method it will use). The buttons are disabled with an explanation inside Docker.
There is also a *run migrations only* action. Details: `DEVELOPMENT.md`, section "Updating / releasing".

## B. Manual update (any install)

```bash
# 1. back up data (binary directory = where your service starts it)
systemctl stop dunree                               # zoraxy on an install upgraded in place
cp -a conf sys.db sys.uuid /safe/place/            # at least these three
# 2. download the new binary for your CPU from the Releases page, e.g. dunree_linux_amd64
curl -LO https://github.com/TheTractorHacker/zoraxy/releases/download/<tag>/dunree_linux_amd64
curl -LO https://github.com/TheTractorHacker/zoraxy/releases/download/<tag>/SHA256SUMS
sha256sum -c SHA256SUMS --ignore-missing
# 3. replace the old binary, keep the same user/permissions, start
install -m 0755 dunree_linux_amd64 /opt/dunree/dunree    # the file your service starts (/opt/zoraxy/zoraxy on an upgraded install)
systemctl start dunree
```

Configuration is migrated automatically on start (`-cfgupgrade` is on by default). If something is wrong, stop the
service, put the old binary and the backed-up `conf/` + `sys.db` back. Releases are Linux-only binaries (amd64,
arm64, arm, 386, riscv64, mipsle); other platforms: build from source (`cd src && go build`, Go version in `src/go.mod`).

"I pulled the git repository but `go build` shows no new version": a source checkout only changes when you
`git pull` the branch/tag you want **and** rebuild (`cd src && go build -o ../dunree`), then replace the running binary.
Pulling `master` of upstream never contains this fork's features.

## C. Docker (#1174)

What this fork provides, honestly:

* `packaging/container/Dockerfile` (multi-architecture; `docker/Dockerfile` is the single-architecture variant) to
  **build the image yourself** from this source. The workflow `.github/workflows/docker.yml` builds the same file.
* The workflow only pushes when the repository owner configures Docker Hub credentials (`DOCKER_USERNAME`,
  `DOCKER_PASSWORD`, optional `DOCKER_ACCOUNT`/`DOCKER_REPO` variables). **None are configured today, so this fork
  publishes no container image** and the in-app updater is disabled in containers. The image
  `zoraxydocker/zoraxy` on Docker Hub is upstream's, maintained by the upstream community; it does not contain this fork's features.
* The fork has no dedicated Docker maintainer (the Docker maintenance question in #1174 concerns upstream). Contributions
  that make the fork's image publishable are welcome as pull requests.

To update a self-built container: rebuild the image from the new tag and recreate the container; the mounted
`/opt/dunree/config` volume (or `/opt/zoraxy/config`, which is a link to it) keeps your data.
