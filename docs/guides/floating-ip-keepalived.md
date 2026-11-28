# Floating IP (keepalived) for two Dunree nodes

Goal: two Dunree nodes keep their own static addresses, and a third unused address in the same subnet, the **floating IP**
(VIP), moves between them. Your firewall's port forward always points at the VIP, so nothing changes during a failover.
Node A normally holds the VIP. If Node A, or Dunree on Node A, stops answering, Node B takes it over.

All addresses below are placeholders from the documentation ranges: `192.0.2.x` for your LAN, `203.0.113.x` for the public
side. Replace them with your own on the Cluster / HA page. Nothing in this guide needs your real addresses.

Dunree **applies nothing** on its own. It validates your settings, **generates** the keepalived configuration and the commands,
and **reads** status. It never edits keepalived, your UniFi controller or the network settings of the host. You copy the
generated text to each node and run it yourself.

## What you need

| Item | Example | Notes |
|---|---|---|
| Node A address | `192.0.2.11` | Existing static address. |
| Node B address | `192.0.2.12` | Existing static address. |
| Floating IP | `192.0.2.10` | Unused, same subnet as both nodes, **outside the DHCP range**, not assigned to any device. |
| Public address | `203.0.113.5` | Your port forward goes from here to the floating IP. |

## 1. Pick the floating IP

1. In your router (UniFi: Settings, Networks, your proxy network) note the DHCP range and the static addresses in use.
2. Choose an address in the same subnet that is outside the DHCP range and not used by any device.
3. Do **not** create a fixed-IP client reservation for it. The VIP moves between two MAC addresses, so a reservation bound to
   one MAC is wrong by design.

## 2. Enter the settings once

On the Cluster / HA page, in the Floating IP section, enter the floating IP, the prefix (for example `24`), and both servers
with their address. Then say **which server is the main one**: the one that normally answers on the floating IP. The other is
the backup. Dunree turns that choice into the VRRP priorities itself (main 150, backup 100, further servers 99, 98, ...), so you
do not type priority numbers. In the stored settings the choice is the `main` field (the main server's address); the numbers are
filled in when you save. If you set the numbers by hand instead (the old way, and still supported), leave `main` empty. Settings
saved by an older Dunree have no `main` field and keep working unchanged.

With a shared-secret cluster, enter the settings on the **primary**: they travel to the followers with the normal sync, and
each node finds itself in the member list by its own address. Without a cluster, enter the same settings on both nodes; the
page shows a short settings fingerprint so you can compare the two.

**The password.** Choose "Automatic" and Dunree makes the VRRP password for you, once, and keeps it. You never type it and you
never put it on a server yourself: it is already inside each server's installer script (step 4). Without a linked cluster the
server makes an 8 character random password (`generatePassword=1` on the settings call); with a linked cluster it makes the
random cluster VRRP password and sends it in the encrypted snapshot. Saving again never replaces it. "Type my own" stays
available under the advanced settings.

Defaults: off until you enable it; unicast between the two nodes; the main server takes the floating IP back 60 seconds after it
is healthy again (`preempt`); the health check runs every 2 seconds and fails over after 3 failures (about 6 seconds).

Spare address ideas: the page can suggest up to three unused addresses in your network (`POST /api/cluster/vip/suggest`). It
only looks (the ARP table, the default route and a few TCP ports inside your own /24, at most 12 addresses per call). No answer
does not prove an address is free, and Dunree cannot read your router's DHCP range: you confirm that yourself.

## 3. Run the checks

The pre-flight list checks that the VIP differs from the node addresses, that all addresses share one subnet, that this node is
a member and the interface is up, that the health probe answers, and (best effort) that nothing else already answers on the VIP.
A blocked check stops generation, never saving.

## 4. Run one script on each server

Each server has its own **installer script** (`GET /api/cluster/vip/script?member=self|<index>`, or `download=1` for a `.sh`
file when your console cannot paste). The script already holds that server's name, address, network card name, health check and
the VRRP password. You paste the whole block into a terminal **on that server** (as root, or as a user with sudo). Nothing else
is typed. The first lines of the script say which server it is for, for example:

```
# Dunree floating IP installer for proxy2 (192.0.2.12) - Backup server
```

The script, in this order, and it stops with one plain sentence at the first problem:

1. checks it runs as root;
2. checks it is on the right server (its address must be on this host) and that the network card name matches;
3. installs `keepalived` and `curl` only if missing (Debian, Ubuntu, RHEL, Rocky, Alma, Fedora);
4. runs the health check as the same user keepalived will use;
5. writes the config to a temporary file and tests it with `keepalived -t`; only then does it replace the real file, keeping
   a timestamped backup of your old one (the config is `root:root 0600`);
6. when needed, sets `ip_nonlocal_bind` and allows VRRP in ufw or firewalld (idempotent, with a backup of
   `ufw/before.rules`; other firewalls are named in the final message);
7. enables and (re)starts keepalived, writes `/etc/keepalived/dunree-installed` (no password in it) so the Dunree page can see
   the progress, and prints whether this server answers on the floating IP or is standing by.

Running it twice changes nothing the second time. It never prints the password and it never downloads anything except
packages from your own package manager.

The individual commands, the raw `keepalived.conf` and the verify commands stay available as "details" (the classic
`GET /api/cluster/vip/generate` endpoint is unchanged):

```
ip -br addr show dev ens18
systemctl status keepalived --no-pager
journalctl -u keepalived -n 50 --no-pager
```

If the page could not ask the other server for its network card name and health check, the script for it is made with guesses
(listed under `guessed`); the script checks them on that server and stops safely when they are wrong.

## 5. Point the firewall at the VIP

UniFi: Settings, Security (Firewall), Port Forwarding. Set the destination to the floating IP, for example public
`203.0.113.5:443` to `192.0.2.10:443`. It never changes during a failover.

## How failover is detected

keepalived runs a small check every 2 seconds: `curl` against `/.dunree/health` on the local node. It answers 200 only while the
proxy router runs, so a node whose Dunree stopped, hung or has no running proxy is treated as failed, not only a node whose VM
is down. A failed check puts the instance in the fault state, which releases the VIP at once. Use `-health_port=:8081` for the
most predictable probe: it answers 503 when the proxy is stopped and does not depend on TLS.

The old path `/.zoraxy/health` keeps working for existing scripts; generated files use `/.dunree/health`.

## Known limits

- **The VRRP password is public on the VLAN.** keepalived PASS authentication sends it unencrypted in every advert. With
  `auth=cluster` it is random and independent of the cluster secret, so capturing it reveals nothing about the secret.
  It is stored in `conf/ha/vip.json` and synced inside the encrypted snapshot. It is still not security: use a dedicated VLAN.
- The generated configuration was checked with `keepalived -t` only when a keepalived binary was present (the Go test
  `TestKeepalivedAcceptsGolden` skips otherwise; set `KEEPALIVED_BIN`).
- The health probe always asks `127.0.0.1`, also for an IPv6 floating IP. With "reject unknown server names" on and the
  proxy listener as the only probe target, the probe cannot work: start Dunree with `-health_port` (for example `:8081`).
  `-health_port` must be a port only or an IP address.
- The page says what it observes. It does not know your firewall rule, and only the Verify tab (stop Dunree on the active
  node) proves failover. A follower report older than three sync intervals is shown as "No recent report".
- The audit log records reading the generated file or the installer script (`cluster.vip.generate`), because both hold the
  VRRP password.
- The installer script supports apt and dnf systems with systemd. Alpine, Arch, OpenRC and others get a plain refusal; use the
  raw commands. It handles ufw and firewalld; nftables-only and other firewalls are only named in its last message.
- The script runs only when you paste it: Dunree never runs it. The tests run the real script against a stub `apt`, `systemctl`,
  `keepalived`, `ip`, `ufw` and a temporary directory tree, never on a real host; `shellcheck` runs when installed.
- Progress for the other server comes from its own health JSON (a `vip` block, only sent to this host's loopback and to
  member addresses, with no secret). That check is not authentication: addresses can be spoofed on a LAN. If the other server's
  health port cannot be reached, its state is "unknown" and its script is made with guesses.
- A follower older than the release with the `main` field refuses a snapshot that carries it (strict parser). Update followers
  first; saving a `main` for the first time asks for confirmation when followers report another version.
- The role shown in a server's script ("Main server" or "Backup server") is computed from the saved priorities plus that
  server's own node-local priority override; another server's override is not known to it.
- VRRP (protocol 112) and multicast reachability cannot be tested before install without raw sockets. Blocking is only
  detectable after install.

- **Tested with fakes and a rendered config, not on two real hosts behind a real UniFi NAT.** The automated tests cover the
  validator, golden keepalived.conf files (master and backup, IPv4 and IPv6, unicast and multicast), the status reader with fake
  interfaces and a temp root, the sync between a primary and a follower, and the admin API. Run the failover checklist in
  `DEVELOPMENT.md` on your own two nodes before you rely on it.
- Dunree generates text and reads status. It never runs `keepalived`, `systemctl`, `ip`, `sysctl` or `apt`, and never talks to UniFi.
- This release has the backend and the generated output. The Fleet scope for the floating IP and Fleet per-node variables
  are not implemented yet: with Fleet, enter the settings on each node (or use a shared-secret cluster).
- A snapshot that carries the floating IP settings (the `ha` root) is refused as a whole by a follower that does not know this
  feature. Update followers first. The root only joins the snapshot after the first save, and a first save on a primary asks you
  to confirm when followers report another version.
- Followers restart themselves after an applied sync. If a follower holds the VIP, a restart is a short interruption or a
  failover; keep the highest priority on the primary.
- Split-brain detection needs heartbeats (shared-secret cluster), so a standalone pair only has the fingerprint comparison.
- "VIP already in use" is a best-effort check (ARP table and a few TCP ports); it cannot prove an address is free. The ICMP
  echo check from the design is not implemented. VRRP itself (protocol 112) cannot be tested without raw sockets.
- VRRP `PASS` authentication sends the password in clear and uses only the first 8 characters. It prevents accidental
  cross-talk, it is not security: anyone on the VLAN can take the VIP. IPv6 (VRRP version 3) has no authentication. Pick a VRID
  that no other VRRP device on the VLAN uses.
- The health probe host is 127.0.0.1 (or the bound address of `-health_port`). A plain HTTP listener bound to one specific
  address is not detected; set a node-local health target in that case.
- IPv6 output is generated and unit-tested; it has had less real-world exercise than IPv4. One VIP per instance; dual stack
  (an IPv4 and an IPv6 VIP) is not supported yet.
- ACME HTTP-01 only works on the node holding the VIP. Use a single issuer or DNS-01 on every node.
- The UniFi client list may show the VIP under alternating MACs, or an "IP conflict", after a failover. That is expected. If
  traffic still goes to the old node, set a gratuitous ARP refresh (for example 60 seconds).
