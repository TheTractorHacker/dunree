# Floating IP (keepalived) on the Cluster / HA page: design

Status: design, not implemented. Owner request: two Dunree nodes keep their own static addresses, a third unused
address in the same subnet (the floating IP, "VIP") moves between them with keepalived/VRRP, and the firewall's NAT
rule always points at the VIP. Node A normally holds it. Node B takes over when Node A or **Dunree on Node A** stops
answering, not only when the VM goes down.

All addresses in this document are placeholders (`192.0.2.0/24`, `2001:db8::/32` for IPv6, `203.0.113.x` for the
public side). The owner fills in the real ones on the page. Nothing in the repo, tests or docs may hold a real address.

Cluster / HA is a first-class feature. This work adds to it and does not mark any part of it as deprecated (see
section 10 for wording that has to go).

---

## 0. What exists today (read before building)

| Piece | Where | Relevant facts |
|---|---|---|
| Shared-secret cluster (primary/follower) | `src/mod/cluster/{manager,primary,follower,snapshot,apply,settings}.go`, glue `src/cluster.go`, `src/cluster_settings.go` | `conf/cluster.json` is node local (0600, holds the secret). Followers pull a signed, AES-GCM encrypted snapshot of an **allow-list of roots** (`baseRoots` + optional `certs`, `sso`, `dbsync`). `ValidatePayload` refuses a snapshot that declares an **unknown root**, so a new root breaks older followers (the same issue `dbsync` has, documented in DEVELOPMENT.md "Known limits"). |
| Follower edit guard | `GuardLocalEdits`, `isSyncedWrite`, `syncedPrefixes` in `mod/cluster/api.go` | Non-GET writes to synced objects are refused with 403 on a follower unless `-cluster_allow_local_edits`. On a Fleet node, `fleetBlocks` refuses writes to hub-managed scopes. |
| Fleet (central management) | `fleet_*.go`, `components/fleet.html` | Scopes plug in through `RegisterScope` (items named `<scope>:<file>`). Per-node variables (`fleet_vars.go`): names `[a-z][a-z0-9_]{0,31}`, values `[A-Za-z0-9._:/@+\-\[\]]{0,253}`, reserved `id,name,group`, resolved hub side into `FleetMeta.Vars`. A node is in **one** mode: standalone, primary/follower or hub/node. |
| Health endpoint | `mod/cluster/health.go`, `mod/dynamicproxy/health.go`, `src/cluster.go` (`-health_port`) | `GET/HEAD /.dunree/health` plus the legacy alias `/.zoraxy/health`, answered on every proxy listener **before host routing** (any Host header). 200 `{"status":"ok",...,"proxyRunning":true}`, 503 when the proxy router is stopped. Optional allow-list matched against the TCP peer. `healthDisabled` makes the path fall through to normal routing. `-health_port=:8081` serves both paths on a separate listener that still answers (503) when the proxy is stopped. |
| Heartbeats | `heartbeatBody` (`primary.go`), `fleetHeartbeat`/`NodeStats` (`fleet_types.go`) | Plain `json.Unmarshal`, no `DisallowUnknownFields`, so new optional fields are ignored by older primaries/hubs. |
| Viewer role | `viewerDeniedPrefixes` in `mod/auth/router.go` | Prefixes listed here are closed to viewer accounts for GET as well. |
| Comparable "generate, apply nothing" feature | `src/netplanapi.go` (Network plan) | Writes down the network and exports firewall recommendations; applies nothing. The VIP feature follows the same contract. |
| **Existing keepalived guide** | `DEVELOPMENT.md`, section "High availability > Active/passive with keepalived (VRRP)" (about line 1189), plus "Failover test checklist" | This is the "Virtual IP failover guide" `docs/roadmap-history.md` refers to. There is **no** user-facing guide in `docs/guides/`. The example has two flaws that the generator fixes: `auth_pass change-me-8ch` is 12 characters but keepalived only uses the first 8, and the `-H 'Host: health.local'` header is not needed because health is answered before host routing. |

---

## 1. Settings: what exists and where it lives

### 1.1 The model

The owner wants to **set the VIP once and have it reach the other node**. Most VRRP settings must match on both nodes
(VIP, VRID, auth, advert interval, the health check). Only a few are really per node. So most settings are **shared**,
authored on the node that owns the configuration (the primary, the Fleet hub, or the only node), and the
node-specific parts are either **derived on each node** or set as a **node-local override**.

The key decision is that **each node finds itself in the shared member list**. The shared config lists the members
(address + priority). Each node matches the member addresses against its own interface addresses
(`net.Interfaces()` + `Addrs()`) and so learns its own real IP, its priority, its peers (every other member) and its
interface (the one holding that address). The owner's flow is then "enter Node A's IP, Node B's IP and the VIP once",
and nothing has to be typed on Node B. Node-local overrides exist for the cases where auto-detection is wrong
(several interfaces in the subnet, a bond or VLAN sub-interface that should carry the VIP, a node that keeps its own
listening ports).

### 1.2 Shared settings: `conf/ha/vip.json`

| Field | Type / range | Default | Why shared |
|---|---|---|---|
| `enabled` | bool | `false` | The feature is off until the owner turns it on. Even when on, it only **generates** text. |
| `vip` | IP (v4 or v6), canonical form | empty | The NAT target; must be the same on all nodes. |
| `prefix` | int, 1..32 (v4) / 1..128 (v6) | none: must be entered (UI pre-fills it from the detected interface prefix) | Same subnet on all nodes. |
| `vrid` | int 1..255 | `51` | VRRP group id; must match. |
| `advertInt` | int seconds 1..10 | `1` | Must match on all nodes, or keepalived logs errors and both may become MASTER. |
| `transport` | `unicast` \| `multicast` | `unicast` | Both must agree. Unicast is the default (section 6.3). |
| `members` | list, 2..8 entries of `{label, address, priority, interfaceHint}` | empty | See 1.1. `label` is display only (`[A-Za-z0-9 ._-]{1,32}`, never written to keepalived.conf). `priority` is 1..254, **distinct** per member. `interfaceHint` (optional) names the interface on that member, used only when generating the config **for another member** (section 3.5). |
| `auth` | `cluster` \| `password` \| `none` | `cluster` when a cluster secret exists, else `password` | Must match on both nodes. |
| `password` | 1..8 chars `[A-Za-z0-9._~+-]` | empty | Only for `auth=password`. Never returned by GET (only `passwordSet`). |
| `preempt` | bool | `true` | Owner wants "Node A normally owns it". |
| `preemptDelay` | int seconds 0..1000 | `60` | Node A takes the VIP back only after it has been healthy for a minute (no flapping after a restart). |
| `health.interval` | int seconds 1..60 | `2` | Same detection time on both nodes. |
| `health.timeout` | int seconds 1..60, > curl `--max-time` | `3` | |
| `health.fall` | int 1..10 | `3` | 3 x 2 s: failover after about 6 s. One more than the old guide's 2, so a 3 s self-restart (cluster sync) on its own does not trigger a failover (see 6.4). |
| `health.rise` | int 1..10 | `2` | |
| `notifyLog` | bool | `false` | Optional fixed `logger` lines on state changes (3.4). |
| `garpRefresh` | int seconds 0..3600 | `0` (off) | Repeats gratuitous ARP while MASTER, for gateways that keep stale ARP entries. |

How it is stored: as a JSON file `conf/ha/vip.json` (0600) under a new snapshot root `ha`. A file, not a database
key, because the cluster transport syncs files and the follower import path for database values (`dbsync`) is tied
to the "sync settings" switch, which ships SSO secrets. The VIP config must not depend on that switch.

Derived `auth=cluster` password: `DeriveKey(secret, "vrrp-auth", ...)` mapped to 8 characters of `[A-Za-z0-9]`. It is
the same on every node with the same secret, is **never stored**, and changes when the secret changes (the UI warns
that both nodes need the regenerated config after a secret change). Not available in Fleet mode, where there is no
shared cluster secret (there the hub writes `auth=password` with a generated value, section 1.4).

### 1.3 Node-local settings: `vipLocal` in `conf/cluster.json`

`conf/cluster.json` is already node local, 0600 and never synced, so the overrides go there as a new optional object.
An absent object means auto-detect everything, so existing files are unchanged.

| Field | Type | Default | Why node local |
|---|---|---|---|
| `interface` | interface name (2.1) | auto: the interface holding this node's member address | Interface names differ between VMs (`ens18` / `eth0`). |
| `sourceAddress` | IP | auto: the member address found on this host | For a host with several addresses in the subnet, or where auto-detection finds none. Must still equal one of `members[].address`. |
| `priorityOverride` | int 1..254 or 0 = none | 0 | Lets the owner demote a node during maintenance without touching the shared config. Shown with a warning while set. |
| `healthTarget` | `auto` or `scheme://127.0.0.1:port` / `scheme://[::1]:port` (loopback only) | `auto` | Nodes may listen on different ports (`keepLocalListener`, a different `-health_port`). |

Fleet per-node variables. In Fleet mode the hub can't write a node's `cluster.json`, so the same overrides come from
reserved-by-convention Fleet variables, if they are set: `vip_interface`, `vip_source`, `vip_priority`. They pass the
existing `ValidateVars` character check first and then the strict validator in section 2. A value set locally in
`vipLocal` wins over a Fleet variable, and the UI shows which source is in effect. This reuses the existing
variable UI and storage and needs no new hub storage.

### 1.4 How the shared file travels

| Mode | Transport | Edit rights |
|---|---|---|
| Standalone (no cluster) | None. The owner enters the same shared settings on both nodes. The page shows a "settings fingerprint" (short hash of the canonical shared JSON plus the derived/entered auth) so the two nodes can be compared at a glance. | Editable. |
| Primary | Adds root `ha` to its snapshot **only once `conf/ha/vip.json` exists** (that is, after the owner saved the section once). From then on the root stays in every snapshot, even with `enabled:false`, so a disable also reaches the followers. Before that, snapshots are byte-identical to today's. | Editable. |
| Follower | Receives `ha/vip.json` through the normal apply (staging, backup, rollback, boot guard). Adding a file under `ha` does **not** need a restart of Dunree, but the existing apply always restarts. That is acceptable and documented. | Shared part read-only (403 via the guard, section 7). `vipLocal` editable. |
| Fleet hub / node | New scope `vip` registered with `RegisterScope`, item `vip:vip.json`. Validated by the same validator on hub and node. Group selection works as for other scopes. A node writes the item to `conf/ha/vip.json` in `Commit`. With `auth=password` the hub generates the password once (8 random chars) and keeps it in the item. | Hub: editable on the Fleet page's scope editor and on the hub's own Cluster / HA page. Node: read-only while the scope is managed (`fleetBlocks`). |

Old followers: `ValidatePayload` on a follower without this feature refuses the unknown root `ha`, and so refuses the
**whole** snapshot. The same applies to old Fleet nodes with an unknown scope. Mitigation, the same as for `dbsync`:
(a) the root is only added after the owner saves the section, never by an upgrade on its own; (b) the save dialog on a
primary lists followers whose last reported `version` is older than the first version with this feature and asks for
confirmation (`ackOldFollowers=true`); (c) a known-limits note.

---

## 2. Input validation (no injection into keepalived.conf)

New package `src/mod/cluster/vip` (or files `vip_*.go` in `mod/cluster`, decided at implementation; the rest of this
document says `vip`). Two layers:

### 2.1 Field validators (run on save, on generate, on the follower after apply, on the Fleet node in `Validate`)

| Input | Rule |
|---|---|
| IP addresses (`vip`, `members[].address`, `sourceAddress`) | `netip.ParseAddr`. Reject: zone (`%`), unspecified, loopback, multicast, link-local unicast, IPv4-mapped IPv6 (`::ffff:`), broadcast address of the prefix and the network address of the prefix (v4). Stored and rendered **only** as `addr.String()`, never the raw input. |
| Address family | VIP and every member address must be the same family. One instance carries one VIP (v1 scope; dual stack = two instances, section 9). |
| `prefix` | Integer from `strconv.Atoi` on a string of at most 3 digits; v4 1..32, v6 1..128. Rendered as an int. Rule: `netip.PrefixFrom(vip, prefix).Contains(member)` for every member, and v4 prefix <= 30 (a /31 or /32 has no room for 3 hosts). |
| `vrid`, `priority`, `advertInt`, `preemptDelay`, `health.*`, `garpRefresh` | Strict decimal (`^[0-9]{1,4}$` before `Atoi`, no sign, no spaces, no hex), then the ranges in 1.2. Rendered as Go ints. `priority` 255 is refused (reserved for the address owner, and Dunree never owns the VIP as a real address). `health.timeout` must be greater than the curl `--max-time`, which is `timeout - 1` with a minimum of 1. |
| Interface name | `^[A-Za-z0-9][A-Za-z0-9_.-]{0,14}$` (Linux `IFNAMSIZ` 16 including NUL). That allows `eth0`, `ens18`, `bond0`, `vlan20`, `eth0.20`. No `:` (aliases are not interfaces), `/`, `@`, whitespace or quotes. Names `.` and `..` refused. |
| `password` | `^[A-Za-z0-9._~+-]{1,8}$`. **Longer input is refused, not truncated**: keepalived uses only the first 8 characters of a PASS password, so silently cutting it would make the UI and the file disagree. |
| `label` | `^[A-Za-z0-9 ._-]{1,32}$`. Display only, never rendered into keepalived.conf. |
| `healthTarget` | `auto` or a URL parsed by `net/url` with scheme `http`/`https`, host exactly `127.0.0.1` or `[::1]`, a port 1..65535, empty path, no userinfo, query or fragment. The generator appends the fixed path. |
| Members | 2..8 entries, addresses distinct, priorities distinct, VIP not equal to any member address. |
| Whole JSON | `encoding/json` into the typed struct with `DisallowUnknownFields`, size limit 16 KiB. |

### 2.2 Render guard (defence in depth)

The generator uses `text/template` with **typed values only**: `netip.Addr`, ints and the validated interface and
password strings. All instance and script names are constants (`VI_DUNREE`, `VI_DUNREE6`, `chk_dunree`). After
rendering, a final check runs over every substituted token: it must match `^[A-Za-z0-9._:/\[\]+~-]+$` (no whitespace,
quote, brace, `#`, `!`, `;`, `$`, backslash or control character). keepalived treats `#` and `!` as comments, braces
as blocks and quotes as script strings. A violation is an internal error (HTTP 500, logged) and no output is returned.

Tests: table tests for every rule above, plus `FuzzVIPConfig` (Go native fuzzing over the JSON body and the
node-local fields). The fuzz asserts that either validation fails, or the rendered file parses with a small test-only
keepalived tokenizer into exactly the expected block structure, with no extra keywords.

---

## 3. Generator output

`vip.Generate(shared, local, env) (Output, error)`. `env` carries what only the running process knows: the interface
list, the health listener facts (below) and the derived auth password. It is a pure function, so it can be
table-tested.

### 3.1 Health target (the exact probe)

The health path is always `cluster.HealthPath` (`/.dunree/health`). The legacy `/.zoraxy/health` alias stays served
unchanged, so existing hand-written keepalived scripts keep working, but generated configs never use it. Target
selection, first match wins:

1. `vipLocal.healthTarget` (or Fleet var) if not `auto`.
2. `-health_port` set: `http://127.0.0.1:<port>`. If the flag binds a specific address, that address is used instead
   of 127.0.0.1, but only if it is not the VIP (a VIP-bound probe fails on the BACKUP and is refused as a blocker).
   This is the **recommended** setup: the listener answers 503 when the proxy is stopped and doesn't depend on TLS.
3. Port 80 listener on (`listenP80`): `http://127.0.0.1:80`.
4. TLS on the inbound port: `https://127.0.0.1:<inbound>` with curl `-k`. The health path answers before certificate
   or host selection, and loopback makes skipping verification acceptable.
5. Plain HTTP on the inbound port: `http://127.0.0.1:<inbound>`.

If the proxy listener binds a specific non-loopback address that isn't the VIP, that address replaces 127.0.0.1 in
cases 3 to 5.

Blockers (the generator returns no config, the UI shows why):

- `healthDisabled` is on: the path would fall through to normal routing and the result would be meaningless.
- The health allow-list is non-empty and doesn't contain the probe's source address (127.0.0.1 / ::1, or the bound
  address). keepalived would see 403, the VIP would never be held, and a lockout like that is exactly what fail-open
  forbids. The UI offers a one-click "add 127.0.0.1 to the allow-list" that uses the existing `healthAllow` save.

### 3.2 keepalived.conf for one member (example for Node A, placeholders)

```
# Generated by Dunree <version> for member "node-a" (192.0.2.11). Settings fingerprint: 3f9a1c2e
# Do not edit by hand: change the Floating IP settings in Dunree and generate again.
global_defs {
    enable_script_security
    script_user keepalived_script
    vrrp_garp_master_refresh 0
}

vrrp_script chk_dunree {
    script "/usr/bin/curl -fsS --max-time 2 -o /dev/null http://127.0.0.1:8081/.dunree/health"
    interval 2
    timeout 3
    fall 3
    rise 2
}

vrrp_instance VI_DUNREE {
    state MASTER
    interface ens18
    virtual_router_id 51
    priority 150
    advert_int 1
    preempt_delay 60
    unicast_src_ip 192.0.2.11
    unicast_peer {
        192.0.2.12
    }
    authentication {
        auth_type PASS
        auth_pass Xb7kQ2mT
    }
    virtual_ipaddress {
        192.0.2.10/24 dev ens18
    }
    track_script {
        chk_dunree
    }
}
```

Rules:

- `state MASTER` for the member with the highest effective priority, `BACKUP` for the others. With `preempt=false`
  every member gets `state BACKUP` plus `nopreempt` (keepalived ignores `nopreempt` on a MASTER-state instance), and
  `preempt_delay` is omitted.
- The track script has **no `weight`**: when the check fails the instance goes to FAULT and releases the VIP at once.
  That is predictable and doesn't depend on priority arithmetic. With a weight, a failing Node A at priority 150 - 20
  could still beat Node B at 100.
- `transport=multicast` omits `unicast_src_ip`/`unicast_peer`.
- `auth=none` omits the `authentication` block. For IPv6 (VRRPv3) the block is always omitted and
  `vrrp_version 3` + `native_ipv6` are set, because VRRPv3 has no authentication. The UI says so.
- `garpRefresh > 0` sets `vrrp_garp_master_refresh <n>`. Otherwise the line is written as 0, so the file is explicit.
- The `script` string contains only the fixed curl path, fixed flags and a URL built from validated parts (no shell).
  keepalived runs it without `/bin/sh`, as `keepalived_script`, which `enable_script_security` requires to be
  unprivileged.

### 3.3 Install and enable commands (copy-paste text, shown in the UI, never run by Dunree)

```
sudo apt update
sudo apt install -y keepalived curl
id keepalived_script >/dev/null 2>&1 || sudo useradd -r -s /usr/sbin/nologin -M keepalived_script
sudo tee /etc/keepalived/keepalived.conf >/dev/null <<'DUNREE_EOF'
<generated file>
DUNREE_EOF
sudo chmod 600 /etc/keepalived/keepalived.conf
sudo keepalived -t -f /etc/keepalived/keepalived.conf
sudo systemctl enable --now keepalived
sudo systemctl restart keepalived
```

- The heredoc delimiter is quoted (no expansion), and the render guard means no generated line can equal
  `DUNREE_EOF`. A test asserts that.
- `keepalived -t` (config test) exists in the 2.x packages of Ubuntu 22.04 and 24.04. Its failure stops the owner
  before `systemctl`.
- `restart` is listed so a second run picks up a changed file. On a first install it is harmless.
- **`net.ipv4.ip_nonlocal_bind`** is only emitted when it's needed: when a Dunree listener (proxy listener or
  `-health_port`) binds the VIP itself instead of all addresses. Dunree listens on all addresses by default, so
  normally it is not needed and the page says "not needed: Dunree listens on all addresses". When needed:
  ```
  echo 'net.ipv4.ip_nonlocal_bind = 1' | sudo tee /etc/sysctl.d/60-dunree-vip.conf
  sudo sysctl --system
  ```
  (`net.ipv6.ip_nonlocal_bind` for an IPv6 VIP.)
- **Host firewall**: if `/etc/ufw/ufw.conf` says `ENABLED=yes` (a read-only file check), the page adds a note with
  the rule to put into `/etc/ufw/before.rules` (`-A ufw-before-input -p vrrp -s <peer> -j ACCEPT`, one per peer),
  because ufw has no `proto vrrp`. With `transport=multicast`, `-d 224.0.0.18` is used instead.
- Verify commands are shown after install: `ip -br addr show dev ens18`, `systemctl status keepalived --no-pager`,
  `journalctl -u keepalived -n 50 --no-pager`.

### 3.4 Notify hooks

No notify **script file** is generated. A notify script is privileged code on the host, and the
"Dunree applies nothing" rule means Dunree should not hand out shell scripts that look like a contract. The only
option is `notifyLog` (off by default), which adds fixed lines that can't take user input:

```
    notify_master "/usr/bin/logger -t dunree-vip MASTER"
    notify_backup "/usr/bin/logger -t dunree-vip BACKUP"
    notify_fault  "/usr/bin/logger -t dunree-vip FAULT"
```

They are useful for `journalctl -t dunree-vip`. Dunree does not need them for its own status (section 4 reads the
VIP from the interfaces directly).

### 3.5 Output for the other member

`GET /api/cluster/vip/generate?member=<index>` renders the file for another member. The interface comes from
`members[i].interfaceHint`, or else from this node's interface name with a visible warning ("check the interface name
on node-b"). The health target uses `auto` rules based on **this** node's listener facts, with the same warning. This
helps when Node B has no Dunree UI yet. The normal path is to open the page on each node and copy its own config.

---

## 4. Read-only status

`vip.Status(env)` runs on demand when the page polls, at most every 5 s, with results cached for 5 s. It never runs
`systemctl`, `ip`, `sudo` or any other command.

| Fact | How (read only) |
|---|---|
| This node holds the VIP | `net.Interfaces()` -> `Addrs()`: is the VIP among them, and on which interface. |
| This node's member entry, interface, prefix | Same scan, matching the member addresses. "Not a member" if none matches. |
| keepalived installed | `os.Stat("/usr/sbin/keepalived")` (also `/usr/local/sbin/keepalived`). |
| keepalived enabled | `os.Lstat("/etc/systemd/system/multi-user.target.wants/keepalived.service")`. |
| keepalived running | Read `/run/keepalived.pid`, then `/proc/<pid>/comm == "keepalived"`. Unreadable = `unknown`, never an error. |
| Installed config matches | If `/etc/keepalived/keepalived.conf` is readable, compare the settings fingerprint in its header comment with the current one. Not readable (0600, Dunree not root) = `unknown`, which is the normal case and not shown as a problem. |
| Which peer holds it | Each node adds `vip: {held, keepalived}` to its heartbeat (follower -> primary in `heartbeatBody`, node -> hub in `NodeStats`, both optional fields). The primary or hub shows per node who holds it. A follower only knows its own state plus the probe below. |
| Split brain | More than one node reporting `held:true` within the last two heartbeats: red state on the primary or hub. |
| VIP reachability | `GET http://<vip>:<port><HealthPath>` (target port per 3.1 but on the VIP) with a 2 s timeout. When this node holds the VIP the probe is local, which the UI says. Otherwise a 200 means "another host answers on the VIP". |

Nothing in the status path can change proxying. An error in any check shows `unknown` for that line and nothing else.

---

## 5. Pre-flight checks

`POST /api/cluster/vip/preflight` returns a list `{id, level: ok|warn|block, message}`. A `block` prevents
**generation**, not saving, so a half-filled config can be stored.

| Check | Level | How |
|---|---|---|
| VIP differs from every member address and from this host's own addresses (unless it is held right now as the VIP) | block | Compare `netip.Addr`. |
| VIP and members in the same prefix; prefix equals the interface's configured prefix | block / warn | `netip.Prefix.Contains`. The interface prefix comes from `Addrs()`. |
| This node is a member | block (for "generate for this node") | Address match (1.1). |
| Interface exists and is up | block / warn | `net.InterfaceByName`, `Flags&FlagUp`. |
| Health target reachable and 200 | block on network error or 403, warn on 503 ("proxy is stopped") | A real GET on the target (3.1). |
| Health allow-list admits the probe source; health not disabled | block | 3.1. |
| VIP not already in use by another host | warn (best effort; it cannot prove absence) | (a) `/proc/net/arp` entry for the VIP with flags `0x2` and a MAC not ours; (b) TCP connect to the VIP on 22/80/443 with a 500 ms timeout: `connection refused` or a connect means a host answers; (c) unprivileged ICMP echo (`golang.org/x/net/icmp`, `udp4`, already in `go.mod`) when `net.ipv4.ping_group_range` allows it, else skipped. If **this node or a member holds the VIP** (status or heartbeat) the check is skipped with "held by node-a". |
| Peer reachable | warn | TCP connect to each peer's admin or health port (when known), 1 s. VRRP itself (protocol 112) can't be tested without raw sockets, which the page says. |
| Distinct priorities, VRID set, auth matches the mode | block | Validator. |
| `auth=cluster` without a cluster secret | block | |
| Old followers would refuse the `ha` root | warn | 1.4. |
| VIP inside the Network plan's proxy network (if a plan exists) | warn when outside | `netplan` read only. |
| keepalived not installed | info | Show the install block. |

The ARP and TCP probes only go to the VIP and peers the admin typed, only on this explicit POST, and are rate
limited to 6 per minute per session.

---

## 6. Safety

### 6.1 Defaults and fail-open

- `enabled:false`, no `ha` root, no `vipLocal`: byte-identical snapshots, heartbeats without the `vip` field, no new
  files. The page shows the section collapsed with a "Set up a floating IP" call to action.
- Dunree **never** writes `/etc/keepalived`, runs `systemctl`, `ip`, `sysctl` or `apt`, or talks to UniFi. All of
  that is copy-paste text.
- The status and pre-flight code is read only and can't affect proxying or the health endpoint. A failure inside it
  shows `unknown`.
- Health stays as it is: the VIP feature adds no new condition to `/.dunree/health`. Changing what health means
  (for example "503 while a sync restart is pending") would silently change existing load balancer behaviour and is
  out of scope.

### 6.2 Split brain and preempt

- Split brain happens when the nodes can't see each other's adverts (VLAN, host firewall, VRID or auth mismatch).
  Both become MASTER and both send gratuitous ARP. The gateway follows the last one, so traffic flips. Detection:
  section 4 (two `held:true` on the primary or hub) and the "settings fingerprint" shown on both pages. Prevention:
  unicast with explicit peers, the ufw note, the same generated file version on both nodes.
- `preempt=true` with `preemptDelay=60` (default): Node A takes the VIP back 60 s after it is healthy again, so
  there's one short interruption. `preempt=false` (both BACKUP + `nopreempt`): whoever holds the VIP keeps it, with
  no second interruption, but Node B can stay the active node indefinitely. The UI explains both in one sentence each.
- The primary should be Node A (the highest priority). Followers restart themselves on every applied sync. If a
  follower held the VIP, each restart would be a short outage or a failover. The page warns when the highest-priority
  member is a follower. `fall 3` x `interval 2` also rides out the follower's 3 s restart delay in most cases.

### 6.3 VRRP authentication limits

- PASS auth sends the password in clear in every advert and uses only the **first 8 characters**. It prevents
  accidental cross-talk with another VRRP router on the same VRID. It is **not** security. AH is not offered (dropped
  in current keepalived). VRRPv3 (IPv6) has no auth at all.
- Recommendation shown on the page: unicast (default) on the proxies' own VLAN. Anyone on that VLAN can take the VIP
  anyway, so the VLAN is the security boundary. Pick a VRID that no other VRRP device on the VLAN uses; Dunree can't
  detect collisions without raw sockets.

### 6.4 UniFi / NAT / DHCP guidance (page help text and guide)

- Pick the VIP from the proxies' subnet **outside the DHCP range** (UniFi: Settings > Networks > the network > DHCP
  range). Don't create a fixed-IP client reservation for it: the VIP moves between two MACs (keepalived uses the
  node's real MAC), so a MAC-bound reservation is wrong by design.
- Point the port forward (UniFi: Settings > Security/Firewall > Port Forwarding, destination) at the VIP, for
  example public `203.0.113.5:443` -> `192.0.2.10:443`. It never changes during failover.
- UniFi's client list may show the VIP under alternating MACs, or flag an "IP conflict", after a failover. That is
  expected. If traffic still goes to the old node after a failover, turn on `garpRefresh` (for example 60 s).
- ACME HTTP-01 only works on the node holding the VIP. Use the existing "single issuer" or "DNS-01 on every node"
  advice (DEVELOPMENT.md "ACME in a cluster").

---

## 7. API

All routes are registered in `RegisterClusterAPIs` on `authRouter`, so they need the admin session and the existing
admin CSRF/origin check (`gorilla/csrf` + `mod/csrfguard`) for every non-GET. `/api/cluster/vip/` is added to
`viewerDeniedPrefixes` (GET too: internal topology, and the generated config contains the VRRP password). Not added
to `/api/v1` in this phase (adding it later means `v1Routes` + `openapi.yaml`). Every write is recorded in the
security audit log (`cluster.vip.shared`, `cluster.vip.local`) and the change history ("Cluster").

| Method + path | Body / query | Returns | Guards |
|---|---|---|---|
| `GET /api/cluster/vip/config` | | `{shared (password masked: passwordSet), local, fleetVars, effective (member, interface, priority, health target, source of each), source: "local"\|"primary"\|"hub", sharedEditable, fingerprint}` | admin |
| `POST /api/cluster/vip/shared` | `config` = JSON of the shared struct; optional `password` (empty = keep); `ackOldFollowers` | `"ok"` or `{error}` | admin, CSRF. **Refused on a follower** with the existing follower message unless `-cluster_allow_local_edits` (add the path to the follower check in `isSyncedWrite` when `ha` is part of the applied roots). **Refused on a Fleet node** while scope `vip` is managed (`fleetBlocks`). |
| `POST /api/cluster/vip/local` | `config` = JSON of `vipLocal` | `"ok"` | admin, CSRF. Allowed in every role (node-local by definition). |
| `POST /api/cluster/vip/preflight` | none | `{checks:[...]}` | admin, CSRF, 6/min |
| `GET /api/cluster/vip/generate` | `member=self\|<index>`, `download=1` (attachment `keepalived-<label>.conf`) | `{keepalivedConf, installCommands, verifyCommands, sysctl, firewallNote, warnings}` or `{error, blockers}` | admin, `Cache-Control: no-store` |
| `GET /api/cluster/vip/status` | | section 4 facts + `peers:[{id,name,held,keepalived,lastSeen}]` on the primary or hub | admin |

Validation errors return `{error}` with HTTP 200, like the existing cluster handlers (`writeErr`), so the page's
error handling stays the same. The guard refusal stays 403 JSON as today.

---

## 8. UI: the "Floating IP" section of Cluster / HA

The page currently has these cards: Status, Role, Secret, Sync/Followers, Health endpoint. The floating IP is the
part the owner sees most, so it is a **new card group right after the Status card**, and the Status card gains one
fact line ("Floating IP 192.0.2.10: held by this node" / "held by node-b" / "not set up").

Layout. The page uses one scroll: no nested scroll areas, code blocks wrap (`.zx-codeblock pre` already wraps) and
are never height-limited. A page-local section nav (`zx-sectionnav`) is added at the top because the page gets long:
Status, Floating IP, Role, Secret, Health.

### 8.1 States

| State | What the card shows |
|---|---|
| **Off** (default) | One card: "Floating IP" title, a two-sentence explanation (two nodes, a third address that moves, NAT points at it), a small inline diagram (Node A, Node B, VIP, firewall), and the button **Set up a floating IP**. Nothing else. |
| **Setup** (editing, shared editable) | Three steps in one card, all visible at once (not a wizard), each with its own heading: **1. Addresses**: VIP + prefix (prefix pre-filled from the detected interface), members table (label, address, priority, interface hint) pre-filled with this node's own address as row 1 and an empty row 2, plus a live "same subnet" hint per row. **2. Failover behaviour**: "Node A takes the VIP back" toggle (preempt) with the delay, the health check (interval, fall, rise) with the resulting "fails over after about 6 seconds" sentence, and an "Advanced" disclosure with VRID, advert interval, transport, auth mode, GARP refresh and notify log. **3. Check**: the **Run checks** button and the check list (ok/warn/block icons, text, fix links such as "add 127.0.0.1 to the health allow-list"). Footer: **Save floating IP settings** (primary button). |
| **Read-only** (follower with synced `ha`, Fleet node with managed scope) | The same fields disabled, with the existing lock callout ("Managed by the primary" / "Managed by hub") and the "This node" sub-card still editable. |
| **This node** (sub-card, every role) | Detected member, interface, priority (and where each value comes from: detected, local override, Fleet variable). Editable overrides: interface, source address, priority override, health target. Its own **Save this node's overrides** button. |
| **Install** | Shown when settings are valid and there are no blockers. Tabs inside the card (not nested scroll): "keepalived.conf", "Install commands", "Verify". Each is a `zx-codeblock` with Copy, plus **Download keepalived.conf**. A select "Config for: this node (node-a) / node-b" (3.5). A sentence: "Dunree does not change your system. Run these commands yourself on this node." Notes for sysctl and ufw appear only when relevant. |
| **Live status** | Fact list: VIP held here (yes/no, interface), keepalived installed / enabled / running, installed config matches (or "cannot read, normal"), VIP answers (latency), and on the primary or hub a per-node table "Holds VIP / keepalived / last seen". Badges: green "Active on this node", neutral "Standby", red "Split brain: node-a and node-b both hold the VIP", amber "keepalived not running", amber "Settings changed since the config was generated" (fingerprint mismatch when readable). |
| **Disabled after use** | `enabled:false` with a saved file: the off-state card plus "Settings kept. keepalived is still running on your nodes until you stop it: `sudo systemctl disable --now keepalived`." |

### 8.2 Copy and accessibility

- Every number has its unit and default in the help line ("1 to 10 seconds. Default: 2.").
- Errors appear next to the field (`zx-field--error`) with the validator message. Save is refused server side as well.
- The password field is `type=password` with "set" / "not set" state and **Generate**. With `auth=cluster` it is
  hidden and replaced by "Derived from the cluster secret, the same on every node".
- All new strings go through `t()` and are extracted with `tools/i18n/extract.py`.
- Nothing on the page says "deprecated" or "legacy" about Cluster / HA (section 10).

---

## 9. Out of scope / later

- Dual stack (one v4 and one v6 VIP as two instances) and more than one VIP. The format leaves room (`vips` list
  later; `vip` stays readable).
- `use_vmac` (virtual MAC): needs macvlan and makes the UniFi client view cleaner, but adds host-side config. Later.
- Applying anything to the host (a privileged helper). Not planned: it contradicts "Dunree applies nothing".
- Live VRRP state from keepalived (SNMP or D-Bus). Holding the VIP is the observable truth and is enough.

---

## 10. Docs and wording changes that come with it

- New user guide `docs/guides/floating-ip-keepalived.md` (placeholders only), linked from the page's "?" popover and
  from DEVELOPMENT.md. The DEVELOPMENT.md section "Active/passive with keepalived (VRRP)" keeps the hand-written
  example (fixing `auth_pass` to 8 chars and dropping the Host header) and points to the page.
- DEVELOPMENT.md "Central management (Fleet)" currently says the primary/follower mode is labelled "Legacy
  shared-secret mode" on the Cluster / HA page. The page no longer says that. Reword it to "shared-secret mode", and
  keep "legacy" only for compat names (`X-Zoraxy-*`, `/.zoraxy/health`). The `legacyMode` / `legacy` JSON fields in
  `/api/cluster/status` and Fleet info stay as API names (compat), and the UI does not render them as text.
- The `docs/roadmap-history.md` entry stays. `docs/ux/changes.md` gets an entry.
- **Known limits** note (DEVELOPMENT.md and the guide): generate-only, never applies; IPv4 only in v1; split brain
  detection needs heartbeats (shared-secret or Fleet), so a standalone pair only has the fingerprint comparison; the
  "VIP in use" check is best effort; old followers refuse a snapshot carrying `ha` (update them first); PASS auth is
  not security; tested on one host with network namespaces, not on two real VMs until the owner runs the failover
  checklist.

---

## 11. Tests (every item automated)

| Area | Test |
|---|---|
| Validator | `vip/validate_test.go`: every rule in 2.1, including the 9-character password refused, `eth0:1` refused, `%zone` refused, `/31` refused, duplicate priorities refused, VIP equal to a member refused. |
| Render guard | `FuzzVIPConfig`, plus the heredoc delimiter test. |
| Generator | Golden files for: MASTER and BACKUP, preempt on/off (BACKUP + `nopreempt`), multicast, `auth=none`, `auth=cluster` (derived password stable for a fixed secret and 8 chars), IPv6 (no auth, `vrrp_version 3`), each health-target branch (health_port, port 80, TLS `-k`, local override), and the blockers (health disabled, allow-list excludes 127.0.0.1). |
| Status | Fake interface lister and a temp root for `/run`, `/proc`, `/etc` paths (the paths are fields, not constants). |
| Sync | `snapshot_test`: no `ha` root before the first save (byte-identical payload), root present afterwards, disable propagates; follower guard refuses `POST /api/cluster/vip/shared` and allows `/local`; Fleet scope `vip` validate/apply/commit and the managed-scope block. |
| Heartbeat compat | Old `heartbeatBody` JSON without `vip` still parses; a new body parses on an old struct (unknown field ignored). |
| API | Viewer denied (GET and POST), CSRF required on POST, `writeErr` shapes. |
| UI | New `tools/ui-smoke/cluster_vip_smoke.py` (wired into `cluster_ha_run.sh`): off state; setup with placeholder addresses; field error; pre-flight list; generated config visible and copyable; follower read-only; light/dark layout; no nested scroll (assert no element in `#clusterPage` with `overflow-y: auto|scroll` and a scrollHeight above clientHeight). |
| Failover | Extend the "Failover test checklist" in DEVELOPMENT.md with the VIP steps (manual, owner run). |
