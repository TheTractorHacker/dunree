# Swapping the two proxies to Dunree

This page is for the two proxies that are started by systemd through `start.sh` in `/home/sysadmin`
(Proxy1, the development machine, and Proxy2, live production). The script is
`tools/install/swap-to-dunree.sh`. It needs root, no network access, and about 15 seconds of downtime
in the rehearsal (see [What was rehearsed](#what-was-rehearsed-and-what-only-the-real-run-shows)).

For an install below `/opt` whose unit starts the program directly, use
`tools/install/migrate-from-zoraxy.sh` and `docs/migrating-from-zoraxy.md` instead. <!-- rebrand:keep -->

## What the script expects

| | |
|---|---|
| Unit | `/etc/systemd/system/zoraxy.service` with `ExecStart=/home/sysadmin/start.sh` <!-- rebrand:keep --> |
| `start.sh` | one line that runs `/home/sysadmin/zoraxy` with its flags (Proxy2 also has `-fleet_port :8010`) <!-- rebrand:keep --> |
| Data | `conf/`, `sys.db`, `sys.uuid`, `plugins/`, `backups/` in `/home/sysadmin` |

It refuses anything else (a unit that does not use `start.sh`, flags that move `conf` or the database)
before it changes a file.

## What it does

1. **Checks, nothing changed yet.** Root. The new program file: SHA-256 against `--sha256`, against
   `SHA256SUMS` when that file is next to it, the ed25519 signature `SHA256SUMS.sig` with the Dunree release
   key (the one the updater has built in), and `-version` must answer as Dunree. Free disk space. The old
   service: active, admin port listening (`ss`), admin page answering (`curl -k`). Then it records what
   runs today: the ports the old program listens on, the plugin programs that run, the number of rule
   files in `conf/proxy`, and one enabled rule from `conf/proxy` that answers through the proxy on
   `127.0.0.1`.
2. **Backup** into `/home/sysadmin/backups/pre-dunree-<UTC time>/` (mode 0700): `program.tgz` (old program
   file and `start.sh`), the old unit file, `plugins.list`, and, after the stop so that the database is
   closed, `data.tgz` (`conf`, `sys.db`, `sys.uuid`, `plugins`). A `README.txt` in the folder says how to
   restore with and without the script.
3. **Stops** the old unit.
4. **Installs** the new program file as `/home/sysadmin/dunree` (root, mode 755). The old program file is
   not touched: it is what a roll back starts.
5. **Rewrites `start.sh`**: only the path of the program changes, every flag stays. The file as it was
   is kept as `start.sh.pre-dunree`.
6. **Writes `dunree.service`** from the old unit: `Description` and `SyslogIdentifier` say Dunree,
   `Conflicts=` names the old unit so the two can never run together, everything else (User,
   WorkingDirectory, ExecStart) is the same. The old unit is disabled, its file stays.
7. `daemon-reload`, `enable`, `start`.
8. **Checks for up to 60 seconds**: unit active, admin port listening, admin page answering,
   `conf/dunree_install.json` written, every plugin program that ran before runs again, every port that
   listened before listens again, the number of rule files is the same, the proxied host from step 1
   answers again. After all of them pass, the same checks must pass again five seconds later with the
   same process.
9. **Any failed check, a time-out, Ctrl+C or a dropped ssh session**: Dunree is stopped, `start.sh` and the old unit are put
   back, the old service is started and checked (active, port, admin page). The script says
   `RESULT: NOT swapped` and exits with 1. Once the roll back has begun, further Ctrl+C, `kill` or a lost
   session do not stop it; let it finish.

Every line of a step starts with `OK`, `WARN` or `FAIL`. Read the `WARN` lines: the script goes on after
them, they are things only you can judge.

| Exit status | Meaning |
|---|---|
| 0 | swapped, or already swapped, or rolled back by hand |
| 1 | a check failed, the old service runs again |
| 2 | refused before anything was changed |
| 3 | the roll back did not end with a healthy old service: act by hand, see the backup `README.txt` |

## Before you start

Put three things in one folder, `~/dunree-staging`: the program file, the script, and, when the file
comes from a signed release, `SHA256SUMS` and `SHA256SUMS.sig`.

```bash
mkdir -p ~/dunree-staging
cp ~/src/zoraxy/tools/install/swap-to-dunree.sh ~/dunree-staging/            # rebrand:keep (path of the checkout)
# a build of your own:
cd ~/src/zoraxy/src && go build -o ~/dunree-staging/dunree_linux_amd64 .     # rebrand:keep (path of the checkout)
# or the files of a release: dunree_linux_amd64, SHA256SUMS, SHA256SUMS.sig
cd ~/dunree-staging && sha256sum dunree_linux_amd64
```

Write the hash down. It is what you give to `--sha256` on both machines, so both run the file you checked.

Run the swap inside `tmux` (or `screen`) when you are connected over ssh: `tmux new -s swap`. If the
session drops during a swap without it, the script notices (SIGHUP) and rolls back to the old service on
its own; the swap is then not done. Everything the script printed is also in
`/home/sysadmin/backups/pre-dunree-<time>/swap.log`, so you can read what happened after you reconnect.
A build of your own has no signature: the script prints
`WARN the new program file is NOT verified by a signature` unless you pass `--sha256`.

## Proxy1 (this machine, development) first

```bash
cd ~/dunree-staging
sudo ./swap-to-dunree.sh --role dev --dry-run
```

The dry run does every check of step 1 and prints the `start.sh` and the unit it would write. Nothing is
changed. Look at:

- `OK layout: ...` shows the flags it found. They must be all of yours.
- `OK the old program (process N) listens on: ...` must list 80, 443 and 3000.
- `OK plugins running: 3 (Data-Shield Blocklist, Resource Monitor, ... Cloudflare WAF plugin)`.
- `OK proxied host answers through the proxy on this machine: https://<one of your hosts>:443/ (200)`.

Then the swap:

```bash
sudo ./swap-to-dunree.sh --role dev --sha256 <the hash>
```

It ends with `RESULT: swapped.` and the downtime it measured. Check yourself:

```bash
systemctl status dunree --no-pager | head -n 12
journalctl -u dunree -n 200 --no-pager | grep -E "NOTICE|Loaded plugin|error"
ls -d ~/conf.pre-dunree-* ~/sys.db.pre-dunree-*
```

and in the browser: the admin page on port 3000 (you stay logged in), *Plugin Manager* (three plugins,
running), a few of your sites, the statistics.

Leave Proxy1 on Dunree for as long as you need to trust it before you touch Proxy2.

## Proxy2 (live production)

Copy the folder, with the same three files, to Proxy2 (`scp -r ~/dunree-staging proxy2:` or however you
move files there). Then, on Proxy2:

```bash
cd ~/dunree-staging
sha256sum dunree_linux_amd64                       # the hash from Proxy1
sudo ./swap-to-dunree.sh --role live --dry-run
sudo ./swap-to-dunree.sh --role live --sha256 <the hash>
```

`--role live` is stricter than `dev`:

- the old service must be healthy (active, admin port, admin page); on `dev` these are warnings,
- at least 1 GB must be free,
- you have to type the host name of the machine before anything is changed. The prompt shows the hash of
  the file and whether it was verified.

In the dry run, the ports must also list 8010 (`-fleet_port`), and the `start.sh` it prints must end with
`-fleet_port :8010`.

Visitors get no answer between step 3 and the start in step 7. When a check fails, the proxy is down for
the time of the checks (up to 60 seconds) plus the restart of the old service.

After `RESULT: swapped.`, check as on Proxy1, and also the *Fleet* page on both machines: each must see
the other.

## Going back

By hand, at any time after a swap:

```bash
sudo ~/dunree-staging/swap-to-dunree.sh --rollback
```

It stops and disables `dunree.service`, puts `start.sh.pre-dunree` back as `start.sh`, moves
`dunree.service` into the backup folder, enables and starts the old unit and checks it. The data stays as
it is now: the old program reads what Dunree wrote. Administrators have to log in once more, because their
session cookie was replaced. `/home/sysadmin/dunree` stays where it is and is used by nothing.

To also put `conf`, `sys.db`, `sys.uuid` and `plugins` back to the moment of the swap (everything changed
since then is lost; what is there now is moved into the backup folder, not deleted):

```bash
sudo ~/dunree-staging/swap-to-dunree.sh --rollback --restore-data
```

This also works after a normal roll back, when the old service already runs: it is stopped first (so its
database is never moved away under it), and started again on the restored data.

Without the script: `backups/pre-dunree-<time>/README.txt` has the commands.

The automatic roll back of step 9 leaves the data alone too, with two exceptions where it restores
`data.tgz` by itself: the number of rule files changed while Dunree ran, or the old service does not come
up on the data as Dunree left it.

## What the first Dunree start does to the configuration

Nothing is converted. Before it writes anything, Dunree copies `conf` (without `geodb/`) to
`conf.pre-dunree-<UTC time>` (mode 0700) and `sys.db` to `sys.db.pre-dunree-<UTC time>`, writes the marker
`conf/dunree_install.json` (origin, time, where the copies are) and logs five `NOTICE` lines. Later starts
see the marker and copy nothing. Details: `docs/migrating-from-zoraxy.md`. <!-- rebrand:keep -->

In the rehearsal, after the first start the only files in `conf` and `plugins` that differed from the
backup taken at the stop were: the new marker, `conf/auth_audit.log` (a login), one new entry in
`conf/.history` and the log file of the Resource Monitor plugin. No rule file changed, `conf/version` stayed
`336`.

So after a swap there are two copies of the data from before: the script's `data.tgz` and Dunree's own
`conf.pre-dunree-*` and `sys.db.pre-dunree-*`. Neither is deleted automatically.

## What changes for you afterwards

- The unit is `dunree.service`: `systemctl status dunree`, `journalctl -u dunree`. In the journal the lines
  carry the name `dunree`. Anything of your own that names the old unit (a cron job, a monitoring check,
  a script that restarts the proxy) has to be changed by you; the script does not look for them:
  `sudo grep -rIl "zoraxy" /etc/cron* /etc/systemd/system /usr/local/bin 2>/dev/null`. <!-- rebrand:keep -->
- The program file is `/home/sysadmin/dunree`. The in-app updater replaces the file that runs, so it
  updates this one.
- Paths of the data are the same. Whatever writes `zoraxy-conf-backup-*.tgz` keeps working as long as it does not name the unit. <!-- rebrand:keep -->
- Never start the old unit by hand while Dunree runs. `Conflicts=` makes systemd stop Dunree when you do.

When you are sure you stay (the script never removes these):

```bash
sudo rm -r /home/sysadmin/backups/pre-dunree-*/  /home/sysadmin/backups/pre-dunree-latest
sudo rm -r /home/sysadmin/conf.pre-dunree-* /home/sysadmin/sys.db.pre-dunree-*
sudo rm /home/sysadmin/start.sh.pre-dunree
# last, because it ends the way back: the old program file and the old unit file
sudo rm /home/sysadmin/zoraxy /etc/systemd/system/zoraxy.service && sudo systemctl daemon-reload   # rebrand:keep
```

After the last line `--rollback` cannot work any more.

## What was rehearsed, and what only the real run shows

Rehearsed on Proxy1 on 2026-11-25 in a private temporary folder (deleted afterwards), as the normal user,
with the real old program file, the freshly built Dunree, the real plugin programs and the readable part
of the real configuration, on ports 3900 (admin) and 3943 (proxy), with a stand-in for `systemctl` that
really starts and stops the programs; `ss`, `curl` and the process list were the real ones:

- A full swap: every check passed, proxy down for about 13 seconds.
- A swap to a program that starts but writes no marker: the check failed after the time-out, the automatic
  roll back ran, the old program was healthy again, program file, `start.sh` and unit were byte-identical
  to before.
- A second run: "already swapped", nothing changed.
- `--rollback` by hand: the old program started on the data Dunree had used, with its three plugins and
  its rules.
- A swap with `--role live` and a `SHA256SUMS` signed with a key made for the rehearsal.
- Dunree on the copied data: the copy and the marker were made, the admin page answered, all 63 rule files
  were loaded (62 host rules and the default site, as with the old program), a real host of the
  configuration answered 200 through the proxy port, and the three plugins built against the old SDK
  (Data-Shield Blocklist 1.3.0, Resource Monitor 1.0.3, the Cloudflare WAF plugin 0.3.4) were found,
  started and reported `running`, health `ok`.

What the rehearsal could **not** cover, because the files belong to root and it ran without root:

- **`sys.db` was not copied.** Both programs started on an empty database: no real accounts, no stored
  plugin state, no statistics, no listener settings (the proxy port came from a flag). The plugins were
  enabled because that is the default on an empty database. The copy of a 95 MB database at the stop and
  at Dunree's first start was not timed.
- **Not copied from `conf`:** `webui/` (the certificate of the admin page), `sso/`, `crowdsec/`, `ech/`,
  `zrok/`, `.cluster/`, `cluster.json`, `waf_central.json`, `.history/`, the audit logs, `visitors.json.gz`
  and 5 of the 12 files in `certs/` (private keys). So: no cluster or Fleet link, no CrowdSec, no SSO, and
  not every host had its own certificate.
- **The Cloudflare WAF plugin ran without its own settings file** (`cloudflarewaf.json`), so with its
  defaults (disabled, dry run). It started and talked to the host; what it does when enabled was not seen.
- **Real systemd:** stopping the control group, `Conflicts=`, `enable`, the journal name, running as root,
  binding ports 80 and 443, plugin processes in systemd scopes.
- **Proxy2:** `-fleet_port :8010` was only tested with stand-in programs (`test_swap.sh`), and a cluster
  with one machine on Dunree and one on the old program was not part of this rehearsal.
- **Real traffic**, ACME renewal and the in-app updater.

One thing seen that is not caused by the swap: the Data-Shield Blocklist plugin logs
`initial blocklist load failed: unexpected HTTP status 404` under the old program and under Dunree alike,
and the journal of the running Proxy1 has the same message. The address it downloads from seems to be gone.

The script itself is tested by `tools/install/test_swap.sh` (40 tests in a temporary folder with stand-in
programs: every failing check with its roll back, the interrupted run, a lost session and repeated
Ctrl+C during the roll back, a full disk during the backup, `systemctl start` and `enable` failing, the
data restore, refusals, checksum and signature, both roles, low disk space, `--no-start`, idempotency).
