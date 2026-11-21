# CrowdSec for Zoraxy

In the release these files are named `crowdsec-setup.sh`, `crowdsec-docker-compose.yml` and `CROWDSEC-README.md`.

## What this is

[CrowdSec](https://docs.crowdsec.net/) is a separate program that keeps a list of bad IP addresses.
Zoraxy can ask it for that list (Security Center > CrowdSec) and refuse those visitors.
CrowdSec cannot be built into Zoraxy, so it has to be installed on its own, on this machine or another one.

These files only help you install CrowdSec. **Nothing here touches Zoraxy**, and **Zoraxy never installs software**
(not from the web page, not from the updater). You run these yourself.

## Which one should I use?

* **Debian or Ubuntu, CrowdSec on the host:** `crowdsec-setup.sh`.
* **Any other system, or you like containers:** `crowdsec-docker-compose.yml`.

## Option 1: the script (Debian / Ubuntu)

```bash
bash crowdsec-setup.sh --dry-run                 # only prints what it would do; changes nothing, no root needed
sudo bash crowdsec-setup.sh                      # the real run; asks before every change
sudo bash crowdsec-setup.sh --log-dir /full/path/to/zoraxy/log   # also let CrowdSec read Zoraxy's logs (optional)
```

What it does, asking each time: downloads the official CrowdSec repository installer to a temporary file and shows its
sha256 (it runs only after you say yes; `--yes` skips the questions), runs `apt install crowdsec`, optionally writes
`/etc/crowdsec/acquis.d/zoraxy.yaml` (only with `--log-dir`), and creates a bouncer key named `zoraxy-<hostname>`
unless that name already exists. It never calls `sudo` itself, writes no key to disk or logs, and stops on other operating
systems (use Docker there). Reading the logs is optional: CrowdSec has no built-in parser for Zoraxy's log lines, but the
community block list works without it (see `docs/guides/crowdsec.md`).

## Option 2: Docker

1. Copy `crowdsec-docker-compose.yml` to a folder as `compose.yaml`, read the comments at the top and edit the log folder path
   (or remove the two log-related volume lines).
2. `docker compose up -d`
3. Create the key inside the container: `docker compose exec crowdsec cscli bouncers add zoraxy-<hostname>`
   (ordinary Docker usage; CrowdSec's Docker page does not spell this exact line out).

The Local API is published on `127.0.0.1:8080` only. If Zoraxy runs on another machine, publish it on an address Zoraxy can
reach and keep it off the internet.

## Getting the key into Zoraxy

The key is printed **once**. Open Zoraxy > Security Center > CrowdSec, enter the Local API address (the script prints
`http://127.0.0.1:8080`) and the key, press **Test connection**, save, and leave the mode on **Log only** until the recent
matches look right. Use one key per Zoraxy.

If you lose the key: `sudo cscli bouncers delete zoraxy-<hostname>` and create it again.

## Stopping and uninstalling

* Switch it off in Zoraxy first (Security Center > CrowdSec, untick "Use CrowdSec decisions").
* Package: `sudo systemctl stop crowdsec` to stop it; `sudo apt remove crowdsec` to remove it (`apt purge` also deletes its
  configuration). Delete `/etc/crowdsec/acquis.d/zoraxy.yaml` if you created it. The CrowdSec repository entry stays until you
  remove it (see the CrowdSec documentation).
* Docker: `docker compose down` (add `-v` to also delete the stored data).

## Honest note

These files were checked for syntax and with `--dry-run` only. They were not run against a real CrowdSec install by the
Zoraxy project. Read the dry-run output and the CrowdSec documentation before running anything as root.
