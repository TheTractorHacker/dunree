# Running Dunree under systemd

The reference unit is [`dunree.service`](dunree.service) in this folder: every line has a comment saying what it is
for. `packaging/linux/dunree.service` has the same settings with shorter comments and is the file that
`packaging/linux/install.sh` installs. `zoraxy.service` in this folder is the unit of installs made before the rename; it is <!-- rebrand:keep -->
kept for them and says so in its first lines.

Other systems: [Windows](windows.md) (service built into `dunree.exe`), [macOS](macos.md) (launchd),
FreeBSD (`packaging/freebsd/`), containers ([docker/README.md](../../docker/README.md)). The table of every
platform's paths is in [`packaging/README.md`](../../packaging/README.md).

An install upgraded in place from Zoraxy keeps its unit name, its program file name and its folder (`zoraxy.service`, <!-- rebrand:keep -->
`./zoraxy`, `/opt/zoraxy`): on such an install use `zoraxy` wherever this page says `dunree`. Renaming them is optional <!-- rebrand:keep -->
and done by `tools/install/migrate-from-zoraxy.sh`; see `docs/migrating-from-zoraxy.md`. <!-- rebrand:keep -->

## Why `Type=notify`

With a plain `Type=simple` unit, systemd calls the service "active" the moment the process exists,
even if Dunree is stuck before it opens any port. With `Type=notify`, Dunree sends `READY=1` only
after the admin interface and the reverse proxy have bound their ports, and `STATUS=` lines while it
works. If you do not use the notify unit nothing changes: Dunree does nothing special when
`NOTIFY_SOCKET` is not set (terminal, Docker, `Type=simple`).

What you see in `systemctl status dunree`:

| State | Meaning |
|---|---|
| `activating (start)` | Dunree is starting. The `Status:` line says what it is doing (for example `Starting`). |
| `active (running)` and `Status: "Admin listening on [::]:8000; reverse proxy listening on port 443"` | Ready. The ports are bound. |
| `active (running)` and `Status: "...WARNING reverse proxy could not bind its port..."` | Dunree is up but another program holds the proxy port. Run `sudo ./dunree -doctor`. |
| `active (running)` and `Status: "...WARNING reverse proxy NOT started..."` | Dunree is up (admin works) but the proxy port was already in use, or the proxy is disabled in the settings. The log says which. |
| `failed` with `Result: timeout` after 120 s | The start never became ready (for example it waited on a locked database). `TimeoutStartSec=120` killed it. Run `sudo ./dunree -doctor`. |

## Switching an existing `Type=simple` unit to `Type=notify`

```bash
systemctl cat dunree                                   # note your current ExecStart= and WorkingDirectory=
sudo cp /etc/systemd/system/dunree.service /etc/systemd/system/dunree.service.bak
sudo cp docs/deploy/dunree.service /etc/systemd/system/dunree.service
sudo nano /etc/systemd/system/dunree.service           # put YOUR ExecStart= (with your flags) and WorkingDirectory= back
sudo systemctl daemon-reload
sudo systemctl restart dunree
systemctl status dunree                                # "activating (start)" for a moment, then "active (running)"
```

Only `Type=notify` (plus optionally `TimeoutStartSec=120`) is needed for the readiness check. The
rest of the reference unit is optional. If the new unit misbehaves, copy the `.bak` back, run
`sudo systemctl daemon-reload` and `sudo systemctl restart dunree`.

### Without editing the main unit: drop-ins

To keep the unit file that came with your install and change only a few settings, use a drop-in
(`sudo systemctl edit dunree` creates it). Drop-ins live in `/etc/systemd/system/dunree.service.d/*.conf`
and override single keys. For example `/etc/systemd/system/dunree.service.d/notify.conf`:

```ini
[Service]
Type=notify
TimeoutStartSec=120
```

Then `sudo systemctl daemon-reload && sudo systemctl restart dunree`. To go back, delete the file and
repeat. `systemctl cat dunree` shows the unit with all drop-ins applied.

### Slow start on a big database: tuning `TimeoutStartSec`

The timer covers everything up to `READY=1`: opening the database, loading certificates and rules,
binding ports. A very large `sys.db` or slow storage can need more than 120 seconds. Measure it
once (`systemctl status dunree` while starting, or the time between the first log line and
`Visit control panel`) and set the timeout to about three times that, with a drop-in:

```ini
[Service]
TimeoutStartSec=600
```

`TimeoutStartSec=infinity` switches the limit off, which brings back the silent hang this unit is
meant to prevent, so prefer a large number. The `Status:` line shows the last step reached.

Do not use `Type=notify` with a Dunree binary older than this feature: systemd would wait for a
`READY=1` that never comes and kill the service after the timeout.

## The Ctrl+Z incident, in 6 lines

1. Someone ran `sudo ./start.sh` next to the service and pressed `Ctrl+Z` (the shell said `Stopped sudo ./start.sh`).
2. `Ctrl+Z` sends SIGTSTP: the process is frozen, not stopped. It keeps its listening sockets.
3. The kernel keeps accepting connections into the queue of those sockets, and nobody answers: the accept queue filled up (4097/4096) and browsers got "connection refused".
4. `systemctl start dunree` started a second copy, which waited forever for the database lock the frozen copy held: `active`, 16 MB, silent log.
5. `kill <pid>` did nothing, because a frozen process cannot handle SIGTERM. Only `kill -9` works.
6. Fix: `sudo kill -9 <pid>` (and its plugins), then `sudo systemctl restart dunree`. The database recovers from a kill -9 cleanly.

Never run `start.sh` next to the service. Use `sudo systemctl restart dunree`. To stop something you
started by hand use `Ctrl+C`, never `Ctrl+Z`. `src/start.sh` now refuses to start when the service
is active or another Dunree runs (override with `FORCE=1`).

## `dunree -doctor`

A read-only check that never opens `sys.db` and never binds a port, so it is safe to run next to a
live or frozen instance. Use the same flags as your service for `-port`, `-dbpath`,
`-default_inbound_port` and `-fleet_port`, so it checks the right file and ports.

```bash
cd /opt/dunree && sudo ./dunree -doctor -dbpath ./sys.db -port :8000
```

It reports:

* other Dunree processes: PID, state (`stopped` = frozen), age, and whether they run under a service or a login session;
* who holds the database lock (read from `/proc/locks`);
* the systemd unit `dunree` (or `zoraxy` when only that one is installed: an install upgraded in place): whether it exists and is active, and its main PID;
* who owns the listening ports of this configuration (admin port, 443, 80, `-fleet_port`) and the accept queue of each
  (`4097/4096` is flagged: `connections are piling up, nothing is accepting`);
* a verdict and the exact commands to fix each problem (`kill -CONT`, `kill -9`, `systemctl restart`).

Exit code: `0` healthy, `1` problems found. It works as a normal user, but then it cannot see the
processes of other users (and which process owns a socket); it prints what it could not see. Run it
with `sudo` for the complete picture. Linux only; on other systems it says so and checks nothing.
The ports 80 and 443 are checked as "fine if not listening", because inbound can be disabled in the
settings, which `-doctor` does not read.

## CrowdSec setup files

Every release ships `crowdsec-setup.sh` (Debian/Ubuntu helper), `crowdsec-docker-compose.yml` and `CROWDSEC-README.md`
(sources in `contrib/crowdsec/`). CrowdSec is a separate program that Dunree can use as a block list
(Security Center > CrowdSec); Dunree does not install it and these files do not touch Dunree. Try
`bash crowdsec-setup.sh --dry-run` first (no root, changes nothing), then `sudo bash crowdsec-setup.sh`. See
[the CrowdSec guide](../guides/crowdsec.md).
