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

On the Cluster / HA page, in the Floating IP section, enter the floating IP, the prefix (for example `24`), and both nodes with
their address and priority. Give Node A the higher priority (for example 150, and 100 for Node B). The priorities have to be
different.

With a shared-secret cluster, enter the settings on the **primary**: they travel to the followers with the normal sync, and
each node finds itself in the member list by its own address. Without a cluster, enter the same settings on both nodes; the
page shows a short settings fingerprint so you can compare the two.

Defaults: off until you enable it; unicast between the two nodes; Node A takes the VIP back 60 seconds after it is healthy again
(`preempt`); the health check runs every 2 seconds and fails over after 3 failures (about 6 seconds).

## 3. Run the checks

The pre-flight list checks that the VIP differs from the node addresses, that all addresses share one subnet, that this node is
a member and the interface is up, that the health probe answers, and (best effort) that nothing else already answers on the VIP.
A blocked check stops generation, never saving.

## 4. Install on each node

Open the page on each node and copy its own configuration, or generate Node B's file from Node A (check the interface name
and health target warnings). The install commands are shown as text:

```
sudo apt update
sudo apt install -y keepalived curl
id keepalived_script >/dev/null 2>&1 || sudo useradd -r -s /usr/sbin/nologin -M keepalived_script
sudo tee /etc/keepalived/keepalived.conf >/dev/null <<'DUNREE_EOF'
# (generated file)
DUNREE_EOF
sudo chmod 600 /etc/keepalived/keepalived.conf
sudo keepalived -t -f /etc/keepalived/keepalived.conf
sudo systemctl enable --now keepalived
sudo systemctl restart keepalived
```

`keepalived -t` tests the file before the service starts. To verify afterwards:

```
ip -br addr show dev ens18
systemctl status keepalived --no-pager
journalctl -u keepalived -n 50 --no-pager
```

Two optional notes appear only when they apply: `net.ipv4.ip_nonlocal_bind` (only if a Dunree listener binds the VIP itself;
by default Dunree listens on all addresses and it is not needed) and a `before.rules` entry for hosts running ufw (ufw has no
`proto vrrp` rule).

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
- The audit log records reading the generated file (`cluster.vip.generate`), because it holds the VRRP password.

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
