# Migrating from Zoraxy to Dunree <!-- rebrand:keep -->

Dunree is based on Zoraxy v3.3.6 by tobychui and imuslab and reads an existing Zoraxy install as it is. <!-- rebrand:keep -->
This page is for an install that runs Zoraxy (upstream 3.3.x or the `v3.3.6-fork.N` builds) today. <!-- rebrand:keep -->
A new Dunree install needs none of it.

## In short

1. Stop the service, replace the program file with the Dunree build, start the service. Nothing else is required.
2. Configuration, database, certificates, accounts, API tokens and plugins are used unchanged. Nothing is converted.
3. The first Dunree start copies your configuration folder and database aside, once, and says so in the log.
4. Administrators stay logged in. Old environment variable names and old paths keep working.
5. Renaming the systemd service and the install folder is optional. A script does it and can be undone.

| What | What Dunree does | What you do |
|---|---|---|
| `conf/`, `sys.db`, `sys.uuid`, certificates, rules, accounts, API tokens (`zrx_...`), `plugins/` | used as they are | nothing |
| First start | copy to `conf.pre-dunree-<time>` and `sys.db.pre-dunree-<time>`, marker `conf/dunree_install.json`, notice in the log | delete the copies when you are sure you stay |
| Admin session cookie `Zoraxy`, CSRF cookie `zoraxy_csrf` <!-- rebrand:keep --> | accepted, replaced by `dunree_session` and `dunree_csrf` | nothing |
| Environment variable `ZORAXY_METRICS_TOKEN` <!-- rebrand:keep --> | still read when `DUNREE_METRICS_TOKEN` is not set, one deprecation line in the log | rename it when convenient |
| Choices stored in the browser (menu groups, pinned pages, language, diagram options) | copied once to the new key names | nothing |
| `zoraxy.service`, `/opt/zoraxy` <!-- rebrand:keep --> | keep working, are not renamed by the program | optional: `tools/install/migrate-from-zoraxy.sh` <!-- rebrand:keep --> |
| Docker image, container and volume names | volumes and mount paths stay | change the image reference only, see [Docker](#docker) |

## Before you start

Take your own backup first. With the service stopped, from the folder the service starts in:

```bash
systemctl stop zoraxy                                   # rebrand:keep
cp -a conf sys.db sys.uuid plugins /safe/place/
```

Or use *Backup & Restore* in the admin interface (full backup, with the database).

Dunree 1.0 has the configuration format of Zoraxy 3.3.6 (`conf/version` stays `336`). <!-- rebrand:keep -->
An install older than 3.3.6 is upgraded by the same automatic configuration upgrades as before (`-cfgupgrade`, on by default).

Then replace the program file as for any update (`docs/guides/updating.md`, section B) and start the service.
The program file may keep its old name: nothing depends on it.

## What the first start does

Before anything else writes to the configuration folder, Dunree looks for `conf/dunree_install.json`.
If the file is missing and the folder (or the database) already has content, this is an existing install:

- The configuration folder is copied to `<conf>.pre-dunree-<UTC time>`, next to the original, for example
  `conf.pre-dunree-20261124-101500`. `geodb/` is left out: it is downloaded data and comes back by itself.
  The copy is private (mode 0700) because it holds keys.
- The database is copied to `<dbpath>.pre-dunree-<UTC time>`, for example `sys.db.pre-dunree-20261124-101500`.
  A database larger than 1 GiB is not copied automatically. The log and the marker say so, and you can copy it by hand
  while the service is stopped.
- `conf/dunree_install.json` is written. It records the time, the version and where the copies are.
- The log has these lines, once:

```
NOTICE: first Dunree start on an existing configuration. Everything is used as it is: rules, certificates, accounts, API tokens and plugins are unchanged.
NOTICE: a copy of ./conf as it was is in conf.pre-dunree-20261124-101500 (212 files). Delete it once you are sure you will not go back.
NOTICE: a copy of the database is in sys.db.pre-dunree-20261124-101500
```

Nothing in your configuration folder is changed, moved or deleted by this step. The only new file is the marker.
Every later start sees the marker and does nothing, so there is exactly one copy.

If the copy cannot be made (disk full, a file that cannot be read), Dunree logs a warning, removes the partial copy and
starts normally. It tries again at the next start. Your configuration is not touched in that case either.

The copies are never deleted by Dunree. Remove them yourself when you no longer need them:

```bash
rm -rf conf.pre-dunree-* sys.db.pre-dunree-*
```

### Going back to the previous program

1. Stop the service.
2. Put the previous program file back.
3. If you changed settings under Dunree that you do not want to keep, restore the copies:
   `mv conf conf.dunree && mv conf.pre-dunree-<time> conf` and `mv sys.db sys.db.dunree && cp sys.db.pre-dunree-<time> sys.db`.
   Copy `conf.dunree/geodb` back into `conf/` or let it download again. Otherwise keep `conf/` and `sys.db` as they are:
   the configuration format is the same, and the previous program ignores `conf/dunree_install.json` and settings it does not know.
4. Start the service. Administrators have to log in once (the browser now holds the Dunree cookie names).

## Sessions and cookies

The admin interface now uses the cookies `dunree_session` and `dunree_csrf`. A browser that was logged in before the
upgrade still has `Zoraxy` and `zoraxy_csrf`: <!-- rebrand:keep -->

- **Session.** The old session cookie is accepted with the same checks as before (same key, same expiry, same account
  and revocation checks). On the first request it is replaced by `dunree_session` with the time it had left, and the
  old cookie is removed from the browser. Nobody is logged out and no session lives longer than it would have.
- **CSRF.** A page that was open during the upgrade keeps working: its token is checked against the old cookie, and the
  browser gets `dunree_csrf` with the same token. The old CSRF cookie is not written again and runs out within 12 hours.
- **Logout** removes the old session cookie as well.

API tokens (`Authorization: Bearer zrx_...`) are not cookies and are not affected.

### Admin interface behind another reverse proxy

Dunree checks where a change comes from: a request that saves something must come from a page of the admin interface
itself (the `Origin` header, or the `Referer` when there is none, against the address the request arrived for). The
program before did not check this. Nothing changes when the admin interface is opened directly (plain HTTP or
`-webui_tls`), from a script that sends cookie and token, or through a reverse proxy that passes the `Host` header on
or sends `X-Forwarded-Host` (a proxy rule of Dunree, Caddy, Traefik, Apache `ProxyPass`, nginx with
`proxy_set_header Host $host`).

**What can change for you:** a proxy in front of the admin interface that replaces the `Host` header and sends no
`X-Forwarded-Host` (nginx `proxy_pass` without `proxy_set_header`). Pages still load, but saving answers
`403 Forbidden - origin invalid`, and the answer and the log name the fix: start Dunree with
`-csrf_trusted_origins=<the address in the browser>`, for example `-csrf_trusted_origins=admin.example.com`, or let the
proxy pass the `Host` header on. Logging in is such a request too: the login page only shows its general error
("Something went wrong..."), the reason is in the log (`[csrf]`) and in the answer of the request.

## Environment variables

Dunree reads `DUNREE_<NAME>`. When that is not set it reads `ZORAXY_<NAME>` and logs one line per variable: <!-- rebrand:keep -->

```
DEPRECATED: environment variable ZORAXY_METRICS_TOKEN is still read because DUNREE_METRICS_TOKEN is not set. Rename it: the old name stops working in Dunree v2.
```

When both are set, the `DUNREE_` one is used and nothing is logged. The value of a variable is never logged.
The only variable the program itself reads today is `METRICS_TOKEN` (bearer token of the `-metrics_port` listener).
Variables that Dunree *sets* for your hook commands are described in the "Dunree rebrand" section of `docs/ux/changes.md`.

## Settings stored in the browser

The admin interface keeps a few choices in the browser (which menu groups are open, pinned and recent pages, language,
traffic diagram options, site editor mode). Their keys were named `zoraxy_...` and `zoraxy....` and are now <!-- rebrand:keep -->
`dunree_...` and `dunree....`. The first admin page a browser opens after the upgrade copies every old key to its new
name, once, and remembers that in `dunree.storage.migrated`. The old keys are left in place.

## systemd: renaming the service and the install folder (optional)

An upgraded install keeps running as `zoraxy.service` from `/opt/zoraxy` (or wherever it is). That is supported. <!-- rebrand:keep -->
Dunree never renames a unit or a folder by itself. If you want the new names, run the script from the source tree
as root on the machine:

```bash
sudo tools/install/migrate-from-zoraxy.sh --dry-run    # rebrand:keep (shows the plan and the unit it would write, changes nothing)
sudo tools/install/migrate-from-zoraxy.sh              # rebrand:keep
```

What it does, in this order:

1. stops `zoraxy.service`; <!-- rebrand:keep -->
2. moves `/opt/zoraxy` to `/opt/dunree` and leaves a link at `/opt/zoraxy`, so cron jobs, backup scripts and log rotation that use the old path keep working; <!-- rebrand:keep -->
3. writes `/etc/systemd/system/dunree.service`: a copy of your unit with the folder path replaced and `Conflicts=zoraxy.service` added, so the two can never run at the same time. A drop-in folder `zoraxy.service.d` is copied to `dunree.service.d`; <!-- rebrand:keep -->
4. disables `zoraxy.service`. **The old unit file is kept**, it is not deleted; <!-- rebrand:keep -->
5. reloads systemd, then enables `dunree.service` if the old unit was enabled and starts it if the old unit was running.

If a step fails (for example the new service does not start), the script undoes its steps, starts the old service again
and exits with status 1. Running it a second time is safe: it reports "Already migrated".

Options:

| Option | Meaning |
|---|---|
| `--dry-run` | show the plan and the new unit, change nothing |
| `--no-start` | enable `dunree.service` but do not start it |
| `--keep-dir` | rename the service only, leave the folder where it is |
| `--old-dir DIR`, `--new-dir DIR` | install folder today and afterwards (defaults `/opt/zoraxy`, `/opt/dunree`) <!-- rebrand:keep --> |
| `--old-unit NAME`, `--new-unit NAME` | unit names (defaults `zoraxy.service`, `dunree.service`) <!-- rebrand:keep --> |
| `--systemd-dir DIR` | where the unit file is (default `/etc/systemd/system`) |
| `--root DIR` | work below `DIR` instead of `/` (images, tests); `systemctl` is then only called when `SYSTEMCTL` names a program |

The script does not rename the program file (`ExecStart=/opt/dunree/zoraxy ...` is fine), does not change <!-- rebrand:keep -->
`SyslogIdentifier=`, `Environment=` lines or anything outside the unit, and does not touch the configuration.
When the install folder is not `/opt/zoraxy` and you pass no `--old-dir`, only the service is renamed. <!-- rebrand:keep -->
A folder that is a mount point is refused: change the mount yourself or use `--keep-dir`.

### Doing it by hand

```bash
systemctl stop zoraxy.service                                   # rebrand:keep
mv /opt/zoraxy /opt/dunree && ln -s dunree /opt/zoraxy          # rebrand:keep
sed 's#/opt/zoraxy#/opt/dunree#g' /etc/systemd/system/zoraxy.service > /etc/systemd/system/dunree.service   # rebrand:keep
# add "Conflicts=zoraxy.service" below [Unit] in dunree.service   # rebrand:keep
systemctl disable zoraxy.service                                # rebrand:keep
systemctl daemon-reload
systemctl enable --now dunree.service
```

### Going back

```bash
systemctl disable --now dunree.service
rm /opt/zoraxy && mv /opt/dunree /opt/zoraxy                    # rebrand:keep (removes the link, moves the folder back)
systemctl daemon-reload
systemctl enable --now zoraxy.service                           # rebrand:keep
# optional: rm -r /etc/systemd/system/dunree.service /etc/systemd/system/dunree.service.d
```

## Docker

Your data is in the volumes, not in the image, so the path is: keep the volumes, change the image.

1. `docker compose down` (or stop and remove the container; **do not** remove the volumes, no `-v`).
2. In `docker-compose.yml` change only the `image:` line to the Dunree image of the release you install. The image
   name is given in the release notes; the Docker registry namespace of Dunree is not final yet, and Dunree is never
   published under the upstream `zoraxydocker` namespace. <!-- rebrand:keep -->
3. Leave the `volumes:` lines exactly as they are, host side and container side:

```yaml
    volumes:
      - /path/to/zoraxy/config/:/opt/zoraxy/config/     # rebrand:keep (same host folder, same container path as before)
      - /path/to/zoraxy/plugin/:/opt/zoraxy/plugin/     # rebrand:keep
```

4. `docker compose up -d`. The first start makes its copies inside the config volume
   (`/opt/zoraxy/config/conf.pre-dunree-<time>` and `sys.db.pre-dunree-<time>`), so they are on the host folder too. <!-- rebrand:keep -->

Names:

- **Host folders** (`/path/to/zoraxy/...`) are yours. Rename them whenever you like, with the container stopped, and change the left side of the mount. <!-- rebrand:keep -->
- **Container paths** (`/opt/zoraxy/config/`, `/opt/zoraxy/plugin/`) are what the image expects. Keep them as the image's `docker/README.md` shows them. <!-- rebrand:keep -->
- **Named volumes** cannot be renamed by Docker. Keep the old name (it is only a label), or copy:
  `docker volume create dunree_config && docker run --rm -v zoraxy_config:/from -v dunree_config:/to alpine cp -a /from/. /to/` <!-- rebrand:keep -->
- **Container and service name** (`container_name: zoraxy`) can be changed freely. Other containers that reach it by that name on a Docker network must be changed too. With a renamed compose service use `docker compose up -d --remove-orphans`. <!-- rebrand:keep -->
- **Environment variables** of the image (`PORT`, `NOAUTH`, `DOCKER`, ...) have no product name in them and are unchanged.

The in-app updater stays disabled inside Docker, as before: update by pulling a new image.

## What does not change

- Flags, ports, the admin port, the configuration format and every file name inside `conf/`.
- Certificates and ACME accounts: nothing is reissued.
- API tokens keep working and keep their `zrx_` prefix.
- Log file names (`zr_*.log`) and the cookies `zr_xauth_session` / `zr_sticky_session`.
- The plugin folder and installed plugins.
- The program file name and the unit name, unless you rename them.

## Known limits

- The copy at the first start needs free disk space of about the size of `conf/` without `geodb/`, plus the database
  (up to 1 GiB). With too little space the copy is skipped with a warning and tried again at every start until it works.
- The marker lives in `conf/`. A full configuration import replaces the folder and with it the marker. The next start
  writes it again and takes no second copy as long as the first one still exists. If you deleted the first copy, a new
  one is taken.
- The copy is taken before the automatic configuration upgrades run, with the service's own permissions. It is not
  encrypted and holds private keys: it is created with mode 0700, keep it as safe as `conf/` itself.
- A LevelDB database (a folder) is copied as a folder. A database over 1 GiB is not copied.
- After going back to the previous program, administrators log in once: the old session cookie was replaced.
- A session issued by a build from before sessions carried a server side expiry is accepted under the old name on every
  request but not re-issued, so that its 30 day limit is not restarted. Such a browser keeps the old cookie name until
  the next login.
- The CSRF token of a page that was open during the upgrade gets a fresh 12 hours once.
- Browser settings are copied once per browser. A setting changed afterwards with the previous program (after going
  back and forward again) is not copied a second time.
- The login page reads the stored language under the old key name until the first admin page has made the copy.
- The script handles one unit file in one folder and plain paths (letters, digits, `. _ - /`). Units in
  `/lib/systemd/system`, template units, paths with spaces, and references to the old folder outside the unit and its
  drop-ins (cron, logrotate, backup jobs) are yours to change; the link at the old path keeps them working meanwhile.
- The script was tested against a temporary root with a fake `systemctl`, not against a live systemd.
- Variables for the release signing tools (`ZORAXY_RELEASE_KEY` and others) are handled by those tools, not by the program. <!-- rebrand:keep -->
