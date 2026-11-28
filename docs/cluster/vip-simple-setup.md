# Floating IP: simple guided setup (design)

Status: design, not built. It replaces the setup part of section 8 of `docs/cluster/vip-plan.md` (the "Setup" and
"Install" states, the "Configuration for" dropdown and the three tabs). The data model, validators, render guard,
read-only status and the rule "Dunree applies nothing outside itself" from `vip-plan.md` all stay. Where this file
and `vip-plan.md` disagree on the page, this file wins. `vip-plan.md` gets a pointer when this is built.

All addresses here are placeholders: `192.0.2.0/24` for the LAN, `203.0.113.x` for the public side. Example
server names are `proxy1` and `proxy2`. The page always shows the user's real names and addresses.

---

## 0. Why this exists

The owner tried the page and could not tell:

- where the password goes on each server ("it doesn't have where we put the password in on each one"),
- how "Proxy2 is my priority" maps to the page (priority numbers, Node 1/Node 2, node-a/node-b and Node A/Node B
  all at once),
- which configuration belongs to which server (the small "Configuration for" dropdown above three tabs),
- what the cluster secret has to do with it,
- why the blue "Last step, on your firewall" box shows under every tab, and why it has a shield icon.

The audits found worse: following the current page on two separate servers produces two different random passwords,
or two servers that both call themselves `node-a` with priority 150. Both cases leave both servers holding the
floating IP at once (split brain), and the page shows no error.

The owner's users are not network engineers. Every unclear step becomes a support question. The goal of this design
is that a user who reads only the big text on the page, top to bottom, ends with a working floating IP and proof
that failover works, without typing a password, a number or a command.

---

## 1. Principles (the rules every part of the page follows)

1. **Before you start** is a short checklist at the top. Dunree detects each item itself and ticks it. Each item
   that is not ticked has one button that fixes it, or takes the user to the exact place that fixes it.
2. **Plain words on the main path.** "Main server" and "Backup server". Never priority, MASTER, BACKUP, VRRP, VRID,
   preempt, unicast, GARP or fingerprint outside "Show details". The user picks the main server by clicking its
   card (name and address). Dunree turns that into priorities; the numbers are visible and editable only under
   "Show details".
3. **The floating IP step suggests addresses.** Best effort, only with the probes that exist today (ARP table read,
   TCP connect, unprivileged ICMP where allowed), no new privileges. It warns when an address looks like DHCP space
   or belongs to a server, and explains in one sentence what a floating IP is.
4. **One card per server** replaces the dropdown and the tabs. Each card says "Run this on proxy2 (192.0.2.12) -
   Backup server" and has ONE copy button for ONE self-contained installer script. The password is already inside
   the script and the page says so in one sentence. The user never types or pastes a password anywhere. The raw
   keepalived.conf and the individual commands are under "Show details".
5. **Live progress.** The page polls and each server card changes state by itself. One big "Next step" banner
   always says the one thing to do now. "It works" is said plainly. A guided "Test it" step tells the user to stop
   Dunree on the main server, watches the address move and says so.
6. **The firewall/NAT note appears once**, as the last step "Point your firewall at 192.0.2.10", with a normal info
   icon.
7. **Every failure has one plain sentence and one fix.** An optional "Why?" disclosure holds the technical reason.
8. **Two sentences and a small diagram** at the top explain what this does.
9. **Accessible, works on a phone, light and dark, one scroll.** No nested scroll areas; code wraps or the page
   scrolls as a whole.

Fork rules still hold: new behaviour is off by default (the Floating IP section stays off until the user clicks
"Set up a floating IP"); saved settings are never rewritten silently (section 9.5); every item below has an
automated test (section 13) and a known-limits note (section 14); Dunree generates text and reads status, it never
runs keepalived, ip, systemctl or a package manager.

---

## 2. Words

The page uses one name per thing, everywhere, including the status strip, the topology and error messages.

| Today | Main path says | Only under "Show details" |
|---|---|---|
| VIP, virtual IP | floating IP | VIP |
| Node 1 / node-a / Node A | the server's own name, e.g. **proxy1** (its label, which defaults to its hostname) | member index |
| priority 150 / MASTER / preferred | **Main server** | priority 150 |
| priority 100 / BACKUP | **Backup server** | priority 100 |
| holds the VIP / MASTER state | **answers on the floating IP** | |
| standby / BACKUP state | **standing by** | |
| preempt, preempt delay | "When proxy1 is back, it takes over again after 1 minute" (a single switch) | preempt, preempt_delay |
| VRRP password, auth=cluster, auth=password | not mentioned, except one sentence: "The password the two servers use to recognise each other is already inside the script." | Authentication, VRRP password, "Automatic" / "Type my own" |
| cluster secret, primary/follower | **link the servers** / **linked** (Before you start only) | the existing Role and Cluster secret cards keep their names |
| fingerprint | "Both servers use the same settings" (green) / "proxy2 runs older settings" (amber) | fingerprint value |
| VRID, advert interval, transport, GARP | not shown | as today |

Rule for the VRRP password labels: never use the word "cluster" in them (the audit showed users confuse it with the
cluster secret). The two modes are called **Automatic (made for you)** and **Type my own**. `AuthCluster` and
`AuthPassword` stay as internal names.

---

## 3. Page layout

The Floating IP section keeps its place right after the Status card. Inside it, top to bottom, one scroll:

```
+--------------------------------------------------------------------------+
| Floating IP                                                    [?] [On]  |
| Your two servers share one extra address. Your router sends visitors to  |
| that address, and whichever server is healthy answers on it.             |
|                                                                          |
|   [router] --> 192.0.2.10 (floating IP) --> proxy1  (main)               |
|                                         \-> proxy2  (backup, takes over) |
+--------------------------------------------------------------------------+
| NEXT STEP  (big banner, one sentence, one button)                        |
|  "Copy the script for proxy2 and run it on proxy2."   [Go to proxy2 card]|
+--------------------------------------------------------------------------+
| Before you start                                     4 of 5 done         |
|  [v] This server: proxy1 (192.0.2.11), fixed address                     |
|  [v] Other server found: proxy2 (192.0.2.12), Dunree 1.0.0-beta.3        |
|  [v] Servers are linked (settings stay the same on both)                 |
|  [v] Dunree answers its health check on both servers                     |
|  [!] proxy2 got its address from DHCP          [How to fix]              |
+--------------------------------------------------------------------------+
| 1  Which server should normally answer?                                  |
|   +----------------------------+  +----------------------------+         |
|   | (o) proxy1                 |  | ( ) proxy2                 |         |
|   |     192.0.2.11             |  |     192.0.2.12             |         |
|   |     You are here           |  |                            |         |
|   |     MAIN SERVER            |  |     BACKUP SERVER          |         |
|   +----------------------------+  +----------------------------+         |
|   [x] When the main server is back, it takes over again after 1 minute   |
+--------------------------------------------------------------------------+
| 2  Pick the floating IP                                                  |
|   One spare address in your network that no device uses. Visitors will   |
|   reach your proxy on it, whichever server is up.                        |
|   [ 192.0.2.10        ]   Suggestions: [192.0.2.10] [192.0.2.11..]       |
|   Your network: 192.0.2.0 to 192.0.2.255                                 |
|   [ ] I checked: this address is outside my router's DHCP range  (?)     |
|                                                [Save and make scripts]   |
+--------------------------------------------------------------------------+
| 3  Run one script on each server                                         |
|   The password the two servers use to recognise each other is already    |
|   inside each script. You never type it.                                 |
|   +--------------------------------+ +--------------------------------+  |
|   | Run this on proxy1             | | Run this on proxy2             |  |
|   | (192.0.2.11) - Main server     | | (192.0.2.12) - Backup server   |  |
|   | You are here                   | |                                |  |
|   | State: (o) Waiting for this    | | State: (o) keepalived running, |  |
|   |        server                  | |        standing by             |  |
|   | [ Copy script ]                | | [ Copy script ]  Done          |  |
|   | Can't paste? Download it       | | Can't paste? Download it       |  |
|   | > Show details                 | | > Show details                 |  |
|   +--------------------------------+ +--------------------------------+  |
+--------------------------------------------------------------------------+
| 4  Test it                                     [Start the test]          |
+--------------------------------------------------------------------------+
| 5  (i) Point your firewall at 192.0.2.10                                 |
|   [ ] I've changed the port forward                                      |
+--------------------------------------------------------------------------+
| > Show details (all settings, numbers, this server's overrides)          |
+--------------------------------------------------------------------------+
```

- The steps are all visible at once (not a modal wizard), so a user can read ahead. A step that cannot be done yet
  is dimmed (`aria-disabled`) with one line saying why ("Finish step 2 first").
- The diagram is an inline SVG drawn with theme tokens (works in light and dark), labelled with the real names and
  addresses once known, placeholders "Server 1 / Server 2" before. It has a text alternative (`<title>` plus the
  two sentences).
- The "Next step" banner is part of the normal flow (not `position: sticky`, so it never covers content on a
  phone). It is an `aria-live="polite"` region. Its button scrolls to and focuses the relevant control.
- Wide screens (>= 900 px): the two server cards in steps 1 and 3 sit side by side. Narrower: stacked, the
  "You are here" card first.
- Code under "Show details" uses the existing `.zx-codeblock pre` wrapping, never `max-height` or `overflow: auto`.
  Long lines wrap (`white-space: pre-wrap; overflow-wrap: anywhere`).
- The firewall note, the sysctl note and the host firewall rule are not separate boxes any more (section 7.5).
- The existing "This node" overrides sub-card moves under "Show details > This server's overrides" and is renamed
  "Expert: values for this server only".

---

## 4. Before you start

Runs automatically when the section opens (one preflight call, it counts towards the 6/minute limit) and again
after every fix. Each row is: icon (tick, amber "!", red "x", or a spinner while checking), one sentence, and at
most one button. Rows that are fine collapse into "All set" once every row is ticked, with a "Show" link.

| ID | Detected how (read only) | Ticked text | Not ticked: sentence + fix |
|---|---|---|---|
| `self` | `Resolve` on this host; label defaults to `os.Hostname()` (validated label charset, cut to 32) | "This server: proxy1 (192.0.2.11)" | Never fails; it only names the server. |
| `peer` | The other member's address answers on its Dunree health endpoint (see 9.4), or a follower heartbeat was seen in the last 2 sync intervals | "Other server found: proxy2 (192.0.2.12)" | "Dunree can't reach the other server yet." Fix: a field "Address of your other server" (one input, validated with `ParseAddr`), then "Look for it". "Why?": port, health allow-list, firewall. |
| `peer-version` | Version from the peer's health JSON or heartbeat; must be >= the version that knows the `main` field (9.1) | (merged into `peer`) | "proxy2 runs an older Dunree. Update it first." Fix: link to `docs/guides/updating.md`. Blocks step 3 for the peer card only. |
| `linked` | Role is primary or follower and a cluster secret is set; the peer is the follower/primary | "Servers are linked: settings stay the same on both" | Amber, not blocking: "Recommended: link the servers so proxy2 always gets the same settings." Fix: **Link the servers** (4.1). Secondary link: "Continue without linking" (4.2). |
| `fixed-addr` | Per server: the address is not DHCP-assigned (9.6) | "Both servers have a fixed address" | "proxy2 got its address from DHCP. Give it a fixed address or a DHCP reservation in your router, or the floating IP breaks when it changes." Fix: "How?" opens the router hint. |
| `health` | Existing health preflight (target, allow-list, disabled, reject unknown names), for this server; for the peer from its health JSON `probeOk` | "Dunree answers its health check on both servers" | One sentence per cause, each with one fix (section 11). |
| `platform` | `/sys/class/dmi/id/{sys_vendor,product_name}` (9.6) | not shown when fine | Cloud VM: red, blocks step 3: "Your cloud provider does not let an address move between servers this way. Use the provider's floating IP or load balancer." Override: "I know my network supports it". Proxmox/QEMU: info row "In Proxmox, turn off 'IP filter' in the VM's Firewall options, or allow protocol 112". Not blocking. |

### 4.1 "Link the servers" in one place

Today the user has to find the Role card and the Cluster secret card further down the page and understand both.
The button runs the same API calls those cards use, inline, in two short steps:

1. On this server: "Make proxy1 the main Dunree" (role primary; generates the cluster secret with the existing
   generator). The page then shows a **link code**: one string that carries this server's admin URL and the new
   secret (`dunree-link:` + base64url of `{"url":"https://192.0.2.11:8000","secret":"..."}`), one copy button, and
   the sentence "This code is shown once. Paste it on proxy2."
2. On proxy2: a "Join with a link code" field in the Role card (new, a thin wrapper over the existing join form:
   it decodes the code client side and fills URL and secret). The Before-you-start row on proxy1 ticks itself when
   proxy2's first heartbeat arrives.

The link code is the cluster secret (it is shown once, like the secret today). It is not the VRRP password; the
VRRP password is never shown on the main path.

The Role and Cluster secret cards stay where they are, unchanged, for people who set them up by hand.

### 4.2 Continue without linking

Supported, because some owners do not want a primary/follower pair. In this mode the whole setup is done on ONE
server's page, and that page makes BOTH scripts with the same random password (the user never types it). The other
server's Dunree needs no floating IP settings at all.

To stop the second server from creating its own, different password (the critical audit finding): when the page
opens on a server that has no settings, it probes the other member addresses it can find (heartbeats, or the
address typed in `peer`), and when a peer's health JSON reports floating IP settings (9.4), step 1 is replaced by:
"proxy1 already set up the floating IP. Use the script from proxy1's page. Don't set it up here again." with a link
to proxy1's page. A user can still override ("Set up here anyway", under "Why?"), which shows the split brain
warning.

The installer also writes a non-secret marker (`/etc/keepalived/dunree-installed`, section 8) that says which
server generated it, so the second server's page can say the same thing after the script ran even if the first
server is down.

---

## 5. Step 1: which server should normally answer?

- Two big selectable cards (`role="radiogroup"`, each card `role="radio"`, arrow keys move, Space/Enter selects).
  Each shows the name, the address, "You are here" when it is this host (matched by address the same way `Resolve`
  does), and a large label "MAIN SERVER" / "BACKUP SERVER" that updates on selection.
- On first setup the main server defaults to the server the page is open on, and the page says so: "proxy1 is the
  main server. Click proxy2 to change that."
- The member list is filled for the user: this server from `Resolve`, the other server from the `peer` row. The user
  only types an address when Dunree could not find the other server (then the `peer` row asks for it).
- Names: label = hostname by default. A small "Rename" link per card edits the label (validated as today).
- The switch under the cards: "When the main server is back, it takes over again after 1 minute" (preempt on,
  delay 60 s, the current defaults). Off: "The backup keeps the floating IP until it has a problem itself." The
  delay value is under "Show details".
- When the chosen main server is a follower: one amber line: "proxy2 restarts briefly each time it gets new settings
  from proxy1, which moves the floating IP for a moment. Choose proxy1 as main, or turn off 'takes over again'."
- More than two members (supported by the model, not by this simple path): step 1 shows all cards, one is main,
  the others are backups in the order shown, and a note says the order is editable under "Show details".

Behind the scenes the choice is stored as `main` (9.1) and the priorities are set to main 150, backups 100, 99, ...
"Show details" shows the numbers and a "Set the numbers by hand" switch, which clears `main` (section 9.1).

---

## 6. Step 2: pick the floating IP

- One sentence: "One spare address in your network that no device uses. Visitors reach your proxy on it, whichever
  server is up."
- The prefix field is hidden. It is filled from the interface that carries this server's address. The page shows
  the network in words: "Your network: 192.0.2.0 to 192.0.2.255". The prefix appears (under "Show details") only if
  the user wants to change it; it accepts `24` or `255.255.255.0` (converted client and server side).
- **Suggestions** (chips, click to fill): from `POST /api/cluster/vip/suggest` (9.3), up to 3 addresses with a short
  reason each ("nothing answered", "low in the range, often outside DHCP"). Under the chips: "Likely free, not
  proven. Dunree only asked the network; a device that is switched off right now would not answer."
- Warnings next to the field, one sentence each (none of them blocks except the first two, which are validator
  blocks today):
  - same as a server's address: "That is proxy2's own address. Pick a spare one."
  - outside the servers' network: "That address is not in your network (192.0.2.0 to 192.0.2.255)."
  - something answered: "A device answers on 192.0.2.10 (port 443). Pick another one."
  - looks like DHCP space: the address is numerically between the two server addresses, or in .100 to .254 when
    the servers have addresses in that range (typical consumer router pools): "This looks like it may be inside your
    router's DHCP range."
  - is the default gateway (`/proc/net/route`): "That is your router's address."
- **Required tick**: "I checked: this address is outside my router's DHCP range". The "?" opens: "In UniFi:
  Settings > Networks > your network > DHCP range. Don't make a fixed-IP reservation for the floating IP: it moves
  between two servers." The tick is stored per settings (`dhcpChecked: true`, 9.1) so it does not come back on
  every visit; changing the address clears it.
- **Save and make scripts** saves the settings (existing `POST /api/cluster/vip/shared`, plus `main`,
  `dhcpChecked`, and for "Automatic" auth a server-made password, 9.2) and runs the preflight. Errors are shown with
  the human label and server name (section 11, "blockers"), each a link that focuses the field.

---

## 7. Step 3: run one script on each server

### 7.1 The cards

One card per member, side by side (>= 900 px) or stacked. Card content, top to bottom:

1. Title (h3): **Run this on proxy2 (192.0.2.12) - Backup server**. The address is the one the user sees in their
   SSH prompt or `ip addr`. "You are here" badge on this host's card.
2. State line (section 10): an icon plus text that changes by itself.
3. ONE primary button: **Copy script**. After copying, the button says "Copied. Paste it into a terminal on proxy2"
   for 5 s. The copied text is the whole installer (section 8).
4. A small text link: "Can't paste? Download the script" (same content as a file `dunree-floating-ip-proxy2.sh`;
   the card then shows `sudo sh dunree-floating-ip-proxy2.sh`). This is for consoles that cannot paste (Proxmox
   noVNC, VMware and Hyper-V web consoles).
5. "Show details" (`<details>`): the raw keepalived.conf, the individual commands (the current install, verify,
   sysctl and ufw blocks), the settings fingerprint, the health check URL, and "Download keepalived.conf". These
   are the same texts as today, generated by the same code.

The sentence above the cards, once: "The password the two servers use to recognise each other is already inside
each script. You never type it."

There is no "Configuration for" select any more. Every card is generated for its own member, so a user cannot copy
the wrong server's file by forgetting a dropdown. In addition the script itself refuses to run on the wrong server
(section 8, check 2).

### 7.2 When a card cannot make its script yet

The card keeps its title and shows one sentence and one action instead of the button:

| Cause | Card says | Action |
|---|---|---|
| Settings not saved | "Finish step 2 first." | Go to step 2 |
| Blocker in the settings | The human blocker sentence (section 11) | Link to the field |
| Peer facts unknown (no health JSON, not linked) | Script is still made, with this server's interface name and health port as a guess, and the card says "Dunree guessed some values for proxy2. The script checks them on proxy2 and stops safely if they are wrong." | none needed |
| Peer runs an older Dunree | "Update Dunree on proxy2 first." | Link to updating guide |
| Cloud platform blocked | The platform sentence | Override link |

### 7.3 Where each card's values come from

The script for member *i* needs: its address, its interface, its health check URL, and the shared settings.

- This server: from `Resolve` and this process's `ListenerFacts`, as today.
- The other server: from its health JSON `vip` block (9.4), which reports its own interface and probe URL. Fallback
  order: the member's `interfaceHint`, then a guess from this server (flagged as in 7.2). The installer verifies the
  interface on the target (section 8), so a wrong guess fails before anything changes.

### 7.4 Audit

Copying or downloading a script calls `GET /api/cluster/vip/script` and is recorded as `cluster.vip.generate` (the
script holds the VRRP password), as the current generate endpoint is.

### 7.5 What happened to the extra boxes

- The ufw rule and the sysctl line are inside the script now (section 8, steps 7 and 8), so they need no box. They
  are still listed under "Show details" as individual commands.
- The "Last step, on your firewall" box is gone from step 3; its content is step 5.

---

## 8. The installer script

### 8.1 Shape

The copied text is one block. It must work when pasted into an interactive shell as a normal user with sudo, as
root without sudo (Proxmox LXC), and when saved as a file and run with `sudo sh file`. The outer wrapper is fixed
text; only the inner script carries values.

```sh
# Dunree floating IP installer for proxy2 (192.0.2.12) - Backup server
# Paste all of this into a terminal ON proxy2. It asks for your sudo password if needed.
if [ "$(id -u)" = 0 ]; then sh -s
elif command -v sudo >/dev/null 2>&1; then sudo sh -s
else echo "Dunree: please log in as root (type: su -) and paste this again."; cat >/dev/null
fi <<'DUNREE_SETUP_END'
<inner script>
DUNREE_SETUP_END
```

The download file is the inner script alone with a `#!/bin/sh` line. Both are POSIX `sh` (dash on Debian/Ubuntu);
no bashisms.

### 8.2 Inner script, step by step

Template (Go `text/template` is NOT used for values; the renderer builds the variable block itself, see 8.3).
Placeholders below show the rendered result for proxy2.

```sh
set -eu
umask 077
export LC_ALL=C

# ---- values (generated by Dunree 1.0.0-beta.3, settings 3f9a1c2e) ----
D_LABEL='proxy2'
D_ROLE='Backup server'
D_ADDR='192.0.2.12'
D_IFACE='ens18'
D_VIP='192.0.2.10'
D_PREFIX='24'
D_PEERS='192.0.2.11'
D_PROBE='http://127.0.0.1:8081/.dunree/health'
D_PROBE_K=''
D_MAXTIME='4'
D_FP='3f9a1c2e'
D_FROM='proxy1 (192.0.2.11)'
D_NEED_SYSCTL='0'
D_V6='0'
# ----------------------------------------------------------------------

CONF=/etc/keepalived/keepalived.conf
MARK=/etc/keepalived/dunree-installed
say()  { printf 'Dunree: %s\n' "$1"; }
fail() {
  printf '\nDunree: PROBLEM: %s\n' "$1"
  [ "${2:-}" ] && printf 'Dunree: What to do: %s\n' "$2"
  printf 'Dunree: Your previous setup was not changed by this step.\n'
  exit 1
}
hide() { sed 's/auth_pass.*/auth_pass (hidden)/'; }
```

Then, in this order. Steps 1 to 5 change nothing on the system except installing packages (step 4); any failure
before step 6 leaves the old keepalived setup untouched.

1. **Root.** `[ "$(id -u)" -eq 0 ] || fail "This must run as root." "Paste it again; it uses sudo by itself, or log in as root with: su -"`.
2. **Right server.** The address must be on this host:
   `ip -o addr show | awk '{print $4}' | cut -d/ -f1 | grep -Fxq "$D_ADDR" || fail "This is not $D_LABEL ($D_ADDR)." "Open a terminal on $D_LABEL and paste it there. The script for this server is on its own card."`
3. **Right network card.** `ip -o link show dev "$D_IFACE" >/dev/null 2>&1` and the address is on that interface
   (`ip -o addr show dev "$D_IFACE" | ... | grep -Fxq "$D_ADDR"`). Else: fail "$D_LABEL's network card is not called
   $D_IFACE." with fix "Open the Dunree page on $D_LABEL and copy its script there, or set the network card name
   for $D_LABEL under Show details." The script prints the real name it found (`ip -o addr show | awk` for the line
   with `$D_ADDR`, printed with `printf '%s'`, never evaluated).
4. **Packages, only if missing.** `command -v keepalived` and `command -v curl`. If either is missing, read
   `/etc/os-release` (`. /etc/os-release` is NOT used; the script greps `^ID=` and `^ID_LIKE=` with fixed
   patterns): Debian family `DEBIAN_FRONTEND=noninteractive apt-get update -qq` then `apt-get install -y -qq
   keepalived curl`; RHEL family `dnf install -y -q keepalived curl`; anything else: fail "This script supports
   Debian, Ubuntu, RHEL, Rocky, Alma and Fedora." "Install keepalived and curl yourself, then paste the script
   again." The `keepalived_script` user is created if missing:
   `id keepalived_script >/dev/null 2>&1 || useradd -r -M -s "$(command -v nologin || echo /bin/false)" keepalived_script`.
5. **Health check works the way keepalived will run it.** As the same user and with the same command as the
   `vrrp_script`: `runuser -u keepalived_script -- /usr/bin/curl -fsS --max-time "$D_MAXTIME" $D_PROBE_K -o /dev/null "$D_PROBE"`
   (`$D_PROBE_K` is either empty or exactly `-k`, see 8.3; it is the one value used unquoted, on purpose, so an
   empty value adds no argument). Failure: fail "Dunree on $D_LABEL does not answer its health check at
   $D_PROBE." "Check that Dunree is running on $D_LABEL, then see 'Health check' on the Dunree page."
6. **Write the config to a temporary file and test it.**
   ```sh
   mkdir -p /etc/keepalived && chmod 755 /etc/keepalived
   TMPD=$(mktemp -d /etc/keepalived/.dunree.XXXXXX)
   trap 'rm -rf "$TMPD"' EXIT INT TERM
   cat > "$TMPD/keepalived.conf" <<'DUNREE_KEEPALIVED_CONF_END'
   <generated keepalived.conf, password inside>
   DUNREE_KEEPALIVED_CONF_END
   chown root:root "$TMPD/keepalived.conf"; chmod 600 "$TMPD/keepalived.conf"
   if ! keepalived -t -f "$TMPD/keepalived.conf" >"$TMPD/test.log" 2>&1; then
     hide < "$TMPD/test.log" | tail -n 15
     fail "keepalived did not accept the generated settings." "Copy the lines above into a Dunree issue. Nothing was changed."
   fi
   ```
   `TMPD` is in the same directory as the target, so the move in step 9 is atomic. The directory is 0700 (umask).
7. **ip_nonlocal_bind, only when needed** (`D_NEED_SYSCTL=1`, the existing rule: a Dunree listener binds the VIP
   itself). Writes the fixed one-line file `/etc/sysctl.d/60-dunree-vip.conf` only if its content differs, then
   `sysctl -p /etc/sysctl.d/60-dunree-vip.conf >/dev/null`. The file content is a fixed string chosen by `D_V6`,
   never a generated value.
8. **Host firewall, only if active, idempotent.**
   - ufw: `ufw status 2>/dev/null | grep -q '^Status: active'`. Then, if `/etc/ufw/before.rules` does not already
     hold the line `# BEGIN dunree-vip`, back it up to `before.rules.dunree-backup-<UTC time>`, insert a block
     between `# BEGIN dunree-vip` and `# END dunree-vip` before the first `COMMIT` line (`awk` with fixed program
     text; peers are passed with `awk -v peers="$D_PEERS"` and split on spaces, each re-checked inside awk against
     `^[0-9.]+$` or `^[0-9a-fA-F:]+$`), then `ufw reload`. If the reload fails, the backup is restored and the
     script fails with "ufw did not accept the rule." An existing block with different peers is replaced in place.
     IPv6 uses `before6.rules`.
   - firewalld: `firewall-cmd --state >/dev/null 2>&1`. Then `firewall-cmd --permanent --add-rich-rule='rule
     protocol value="vrrp" accept'` (fixed text; already present = no change) and `firewall-cmd --reload`.
   - Neither: nothing. nftables-only or other firewalls are named in the final message as a known limit ("If you use
     another firewall on this server, allow protocol 112 (VRRP) from 192.0.2.11.").
9. **Install the config.** If `$CONF` exists and `cmp -s "$TMPD/keepalived.conf" "$CONF"`, nothing to do (record
   `CHANGED=0`). Otherwise, if `$CONF` exists, back it up once per change: `cp -p "$CONF"
   "$CONF.dunree-backup-$(date -u +%Y%m%dT%H%M%SZ)"` (mode is kept, 0600), and say "Saved your old keepalived.conf
   as <name>." Then `mv -f "$TMPD/keepalived.conf" "$CONF"` (atomic, same filesystem). `CHANGED=1`.
10. **Enable and (re)start.** `systemctl enable keepalived >/dev/null 2>&1`. If `CHANGED=1` or keepalived is not
    active: `systemctl restart keepalived`. Then wait up to 10 s for `systemctl is-active --quiet keepalived`. If it
    does not come up: print `journalctl -u keepalived -n 15 --no-pager | hide` and fail "keepalived did not start."
    "Copy the lines above into a Dunree issue. Your old file is saved as <name>." (the old config is NOT put back
    automatically: a half-working old setup is not better; the backup name is printed instead).
11. **Marker for Dunree.** Write `/etc/keepalived/dunree-installed` (0644, root) with fixed keys and the
    non-secret values: `fingerprint=<D_FP>`, `member=<D_ADDR>`, `generatedBy=<D_FROM>`, `installedAt=<UTC>`.
    Dunree reads this file (section 9.4) because it cannot read the 0600 config when it is not root. It contains no
    password.
12. **Result.** Wait up to `3 * advert + 3` seconds, then check whether `$D_VIP` is on `$D_IFACE`:
    - holds it: "OK: keepalived is running on proxy2. proxy2 answers on the floating IP 192.0.2.10 now."
    - does not: "OK: keepalived is running on proxy2. It is standing by; the other server answers on 192.0.2.10."
    - always last: "Go back to the Dunree page. It shows this server's progress by itself."

Running the script twice changes nothing the second time (steps 4, 7, 8, 9, 10 all check first), and prints the
same OK line.

### 8.3 How the script stays safe

1. **Strict inputs only.** Every value in the variable block comes from an already validated, typed source, and the
   renderer re-checks each one against a per-variable whitelist right before it writes the line. Any mismatch is an
   internal error (`BlockedError`), never a script:
   | Variable | Source | Whitelist |
   |---|---|---|
   | `D_LABEL` | member label (existing validator) | `^[A-Za-z0-9][A-Za-z0-9._-]{0,31}$` |
   | `D_ROLE` | fixed i18n-free string | exactly `Main server` or `Backup server` |
   | `D_ADDR`, `D_VIP`, `D_PEERS` | `netip.Addr.String()` (no zone) | `^[0-9.]+$` or `^[0-9a-f:]+$`; peers joined by one space |
   | `D_IFACE` | `ValidInterfaceName` | `^[A-Za-z0-9_.-]{1,15}$` (no `:`) |
   | `D_PREFIX`, `D_MAXTIME` | ints in range | `^[0-9]{1,3}$` |
   | `D_PROBE` | `ProbeTarget`, then the existing `checkScript` URL rules | `^https?://[A-Za-z0-9.:\[\]-]+/\.dunree/health$` |
   | `D_PROBE_K` | bool | exactly empty or exactly `-k` |
   | `D_FP` | fingerprint | `^[0-9a-f]{8}$` |
   | `D_FROM` | label + address of the generating server | label and address whitelists, joined by the fixed ` (` and `)` |
   | `D_NEED_SYSCTL`, `D_V6` | bool | `0` or `1` |
   None of the whitelists admits `'`, `\`, `$`, a backtick, a space (except the documented joiners), a newline or any
   control character.
2. **Values are only ever assigned inside single quotes**, in the variable block, and only ever used later as
   `"$VAR"` (double-quoted expansion). The single deliberate exception is `$D_PROBE_K`, whose whitelist is empty or
   `-k`. A Go test parses the template and fails if any `$D_` appears unquoted except `$D_PROBE_K`.
3. **The config travels in a quoted heredoc** with fixed delimiters (`DUNREE_KEEPALIVED_CONF_END` inner,
   `DUNREE_SETUP_END` outer). Quoted delimiters mean no expansion inside. Neither delimiter can occur in the content:
   the render guard checks every line of the rendered config and of the whole inner script, and refuses to render if
   any line equals either delimiter. Today no line can: every config line starts with a keepalived keyword, `}`, `#`
   or whitespace, and no value whitelist admits a whole line of that form, so the check is defence in depth. No
   random delimiter is used, so the output is reproducible and testable.
4. **The password is never printed.** It exists only inside the heredoc. The script never uses `set -x`, never
   `cat`s the config, and passes every keepalived or journal output through `hide` (which replaces anything after
   `auth_pass`). The page never shows the password on the main path; it is visible only in "Show details > raw
   keepalived.conf", as today.
5. **`set -eu`**, `umask 077`, `LC_ALL=C`. Every external command whose failure matters is wrapped in a check with a
   plain `fail` message; commands whose failure is expected (`command -v`, `grep -q`, `cmp -s`) are in `if` or `||`
   positions so `-e` does not end the script without a message.
6. **Root check** first (step 1), with a plain message. The outer wrapper also handles "no sudo".
7. **Wrong-server and wrong-interface guards** (steps 2 and 3) before any change.
8. **Backups**: an existing `/etc/keepalived/keepalived.conf` is copied to a timestamped name before it is
   replaced, only if the content differs. Same for `ufw/before.rules`.
9. **`keepalived -t -f` on the temporary file before it replaces the real one**, so a bad file never reaches
   `/etc/keepalived/keepalived.conf` and keepalived is never restarted with it.
10. **Correct owner and mode**: `root:root 0600` for the config, set on the temporary file before the atomic `mv`,
    so there is no moment when the password is world readable.
11. **Idempotent** (8.2, last paragraph).
12. **No network fetches** besides the package manager and the local health probe. The script never downloads or
    runs anything from Dunree.
13. **Tests run the real script** with `sh -n` (syntax) and in a stub sandbox (section 13) for every branch.

Rejected on purpose: a `curl http://.../install/<token> | sudo sh` one-liner. It would send the VRRP password over
plain HTTP on the LAN and run code fetched at paste time; the download link covers the "cannot paste" case without
either.

---

## 9. Backend changes

### 9.1 Main/backup choice stored as a field

`vip.Shared` gains:

```go
// Main is the address of the member that normally holds the floating IP.
// "" means the priorities were set by hand (older settings, or "Set the
// numbers by hand" under Show details). When set, the priorities are derived.
Main string `json:"main,omitempty"`
// DHCPChecked records the user's tick "outside my router's DHCP range" for
// the current VIP. Cleared by the page when the VIP changes.
DHCPChecked bool `json:"dhcpChecked,omitempty"`
```

- `ValidateShared`: `Main` must equal one member address exactly. When `Main` is set, the server overwrites every
  `Members[i].Priority` on save with the derived values: main 150, the others 100, 99, 98, ... in list order (so
  older code paths and the render stay unchanged, and the stored file always has consistent numbers).
- "Set the numbers by hand" (Show details) clears `Main` and lets the numbers be edited as today, including the
  existing node-local `priorityOverride`. The page then derives "main server" from the highest effective priority
  and labels step 1 "Custom order (set under Show details)" with the cards read-only.
- Existing settings without `main` load unchanged (no silent rewrite): step 1 shows the derived main server and a
  note "Saved before this version: the numbers were set by hand." Saving from step 1 sets `main`.
- Compatibility: `ParseShared` uses `DisallowUnknownFields`, so a follower older than this change refuses a
  snapshot whose `ha` root has `main` or `dhcpChecked`. The existing `oldFollowers` warning gets a new minimum
  version (the release that ships this), and the `peer-version` row (section 4) blocks the peer's card. Known limit.

### 9.2 Password made by the server

- `POST /api/cluster/vip/shared` accepts `generatePassword=1`. With `auth=password` and no stored password, the
  server makes an 8-character password with `crypto/rand` from the existing alphabet (as `ClusterPass` is made
  today) and stores it. The page sends this for "Automatic" when not linked.
- Linked pair: "Automatic" is `auth=cluster` as today (random `ClusterPass` made by the primary, sent in the
  encrypted snapshot).
- Not linked: "Automatic" is `auth=password` with a server-made password. Both scripts come from the same page and
  the same stored password, so they always match.
- "Type my own" stays under Show details for people who need it.
- Defaults change only for new setups made through the new flow; `Defaults()` itself is unchanged.

### 9.3 Candidate suggestions

`POST /api/cluster/vip/suggest` (admin, CSRF, shares the preflight rate limit of 6/min/session).

- Input: none (uses this server's resolved interface and prefix) or `near=<member address>`.
- Candidate pool: the /24 that contains this server's address (also when the prefix is shorter, such as /16, so the
  probe stays small), excluding network and broadcast, member addresses, this host's addresses, the default gateway
  (`/proc/net/route`), and every address present in `/proc/net/arp` with flags `0x2`.
- Order: `.10` to `.29`, then `.240` to `.250` (common static zones on consumer routers), then `.2` to `.9`. Each
  candidate is probed with the existing `vipInUse` (ARP read plus TCP 22/80/443, 500 ms) and the planned
  unprivileged ICMP probe when `net.ipv4.ping_group_range` allows it. At most 12 probes, 4 in parallel, so the call
  ends within about 2 s. It returns the first 3 that nothing answered.
- Output: `{network: {cidr, first, last}, gateway, candidates: [{address, reason}]}`. `reason` is an i18n key.
- Known limit: absence of an answer proves nothing (switched-off devices, ICMP and TCP blocked).

### 9.4 Status that the page can poll, for both servers

- `GET /api/cluster/vip/status` gains `nodes: [{label, address, self, state, held, keepalived, installed,
  installedFingerprint, settingsMatch, reachable, lastSeen, version, iface, probeOk, dynamicAddr, platform}]`,
  one entry per member. `state` is the node state of section 10. Cache drops from 5 s to 2 s; the page polls every
  3 s while the section is visible (`document.visibilityState`), every 1 s during "Test it".
- **Peer facts come from the peer's health endpoint**, so they work with and without linking and are live (the
  follower heartbeat runs only every sync interval, 60 s by default). The health JSON gets an optional `vip` block,
  added only when the floating IP is enabled AND the request's TCP source is a member address or loopback:
  `{"vip": {"held": true, "keepalived": "yes", "settings": "3f9a1c2e", "installed": "3f9a1c2e", "iface": "ens18",
  "probe": "http://127.0.0.1:8081/.dunree/health", "probeOk": true, "dynamicAddr": false, "platform": "qemu",
  "service": "dunree.service", "generatedBy": "192.0.2.11"}}`. No password, no secret. Older Dunree ignores the
  block (plain `json.Unmarshal`). The probe is the existing `vipReach`/peer GET with a 2 s timeout, cached 2 s.
- `installed` comes from the marker file `/etc/keepalived/dunree-installed` (8.2 step 11), read with a size limit
  of 1 KiB and parsed as fixed `key=value` lines. Unreadable or missing means "not installed by this script".
- The existing follower heartbeat field `vip` stays as a fallback for `held` and `keepalived`.
- `service`: read-only detection of how Dunree runs, for the exact stop command in "Test it": the systemd unit name
  from `/proc/self/cgroup` (a `*.service` path segment, validated `^[A-Za-z0-9@._-]+\.service$`), or `docker` when
  `/.dockerenv` exists, else empty.

### 9.5 Installer script endpoint

`GET /api/cluster/vip/script?member=self|<index>&download=0|1` (admin, viewer denied, `Cache-Control: no-store`,
audited as `cluster.vip.generate`).

- Returns `{title: {label, address, role}, script, keepalivedConf, commands: {install, verify, sysctl, firewall},
  fingerprint, healthUrl, guessed: [fieldKeys], warnings: [...], blockers: [{field, node, labelKey, message}]}`.
  With `download=1` it returns the inner script as `text/x-shellscript`, attachment `dunree-floating-ip-<label>.sh`.
- Built by a new pure function `vip.Script(s, l, env, member, peerFacts)` next to `Generate`, which it calls for the
  config. `Generate` and `GET /api/cluster/vip/generate` stay for compatibility and for "Show details".
- `blockers` carry the validator's `FieldError.Field` plus the member index, so the page can show "proxy2: ..." and
  focus the field (section 11).

### 9.6 Extra read-only checks (no new privileges)

| Check | How | Where it shows |
|---|---|---|
| Address is DHCP-assigned | Unprivileged netlink `RTM_GETADDR`: an IPv4 address without `IFA_F_PERMANENT` is dynamic; fallback: a lease file exists for the interface under `/run/systemd/netif/leases/` or `/var/lib/NetworkManager/` | `fixed-addr` row, per server (peer via health JSON) |
| Platform | `/sys/class/dmi/id/sys_vendor`, `product_name`, `chassis_asset_tag` (world readable): QEMU/Proxmox, VMware, Microsoft Hyper-V, Amazon EC2, Google, Hetzner, Azure asset tag | `platform` row |
| Host firewall present | ufw: `/etc/ufw/ufw.conf` `ENABLED=yes` (existing); firewalld: `/proc/*/comm` equals `firewalld` (read only) | Shown under "Why?" of the split brain state; the script handles both |
| VRRP blocked, after install | Both servers report `held: true` within 2 polls (health JSON) | Failure state "Both servers answer" (section 11) |
| Nobody answers, after install | Both report keepalived running, neither holds the IP, for more than `fall * interval + 5` s | Failure state "Nobody answers" |
| Flapping | `held` changes more than 4 times in 2 minutes on one server | Failure state "Keeps switching" |
| Settings out of date on a server | `installed` fingerprint differs from the current settings fingerprint | Card state "Old settings: run the script again" |

Raw VRRP (protocol 112) and multicast reachability can not be tested without raw sockets; the page does not
pretend to. The peer check is re-worded: "proxy2 is reachable (this does not prove the floating IP messages get
through; Dunree checks that after install)."

### 9.7 What does not change

Validators, render guard, `Generate` output, the sync of the `ha` root, viewer and CSRF rules, the audit events,
and the status reader's "never runs a command" rule.

---

## 10. Live progress

### 10.1 Server card states

Computed server side (`nodes[].state`), so the smoke can feed fixtures. First match wins.

| State | Condition | Card shows |
|---|---|---|
| `unknown` | Peer health JSON not reachable and no heartbeat in 2 sync intervals | Grey: "Can't see proxy2 from here. Its script checks itself when you run it." |
| `old-version` | Peer version below minimum | Amber: "Update Dunree on proxy2 first." |
| `waiting` | keepalived not installed, or no marker file | Grey spinner icon: "Waiting for this server. Copy the script and run it on proxy2." |
| `outdated` | Marker fingerprint differs from the current settings | Amber: "proxy2 runs older settings. Copy the script again and run it on proxy2." |
| `stopped` | Installed, keepalived not running | Red: "keepalived is not running on proxy2." Fix: the exact start command `sudo systemctl start keepalived` (copy) |
| `holding` | Running, holds the floating IP | Green: "Answers on the floating IP" |
| `standby` | Running, does not hold it, another server holds it | Green-neutral: "Standing by, ready to take over" |
| `fault` | Running, does not hold it, nobody holds it | Red: "keepalived is running, but proxy2's health check fails, so it does not take the floating IP." Fix: copy `sudo -u keepalived_script curl -fsS <probe>` |

### 10.2 The "Next step" banner

One sentence, one button. First match wins:

1. Before-you-start has a red row: that row's sentence and fix.
2. Step 1 not confirmed (no `main`): "Choose which server should normally answer."
3. No floating IP saved: "Pick a spare address for the floating IP."
4. DHCP tick missing: "Check that 192.0.2.10 is outside your router's DHCP range."
5. A card is `waiting` or `outdated`: "Copy the script for proxy1 and run it on proxy1." (the "You are here" server
   first, then the main server, then the rest)
6. A card is `stopped` or `fault`: its sentence.
7. A failure state of section 11 is active: its sentence.
8. Test not done: "It works. Now test it: stop Dunree on proxy1 and watch proxy2 take over." Button: Start the test.
9. Firewall step not ticked: "Point your firewall at 192.0.2.10."
10. Everything done: green, **"It works. Visitors reach 192.0.2.10, and proxy2 takes over if proxy1 fails."**

"It works" (item 8 onwards) requires: every card `holding` or `standby`, exactly one `holding`, and the
`holding` one is the main server (or the backup with preempt off, which the sentence then says).

The banner state and the ticked checkboxes for steps 4 and 5 are per viewer, kept in `localStorage` (wrapped in
try/catch; the page works without it). Everything else comes from the server.

---

## 11. Failure states: one sentence, one fix, optional "Why?"

| Situation (detected by) | Sentence | Fix | Why? |
|---|---|---|---|
| Both servers hold the IP (9.6) | "Both servers answer on 192.0.2.10. Something between them blocks the messages they send each other." | "Allow protocol 112 (VRRP) between 192.0.2.11 and 192.0.2.12 in the Proxmox or host firewall, then wait a minute." | VRRP adverts are IP protocol 112. Host firewalls (ufw, firewalld, nftables), the Proxmox VM/datacenter firewall, VLAN ACLs or switches that drop multicast stop them, so each side thinks the other is gone. |
| Nobody holds it (9.6) | "Neither server answers on 192.0.2.10 because both health checks fail." | Copy the health command for the "You are here" server. | keepalived gives up the IP when its `vrrp_script` fails. |
| Keeps switching (9.6) | "The floating IP keeps moving between your servers." | "Another device may use the same ID. Change 'Virtual router ID' under Show details and run both scripts again." | VRID collision, or a flapping health check. |
| Health: allow-list excludes 127.0.0.1 | "Dunree's health check refuses this server itself." | One click: "Allow 127.0.0.1" (existing health card API) | |
| Health: endpoint switched off | "Dunree's health check is switched off." | One click: "Switch it on" | |
| Health: TLS listener rejects unknown names, no health port | "Dunree needs a separate health port for this." | Copy the systemd drop-in that adds `-health_port=127.0.0.1:8081` (fixed text plus `systemctl daemon-reload` and restart), shown with the detected unit name | |
| Proxy stopped (503) | "Dunree's proxy is stopped on proxy1." | "Start it on the Status card." | |
| Interface mismatch reported by the script | (printed by the script, 8.2 step 3) | | |
| VIP same as a server | "That is proxy2's own address. Pick a spare one." | Focus field | |
| VIP outside the network | "203.0.113.10 is not in your network (192.0.2.0 to 192.0.2.255)." | Focus field | |
| Prefix differs from the interface | "This server's network is 192.0.2.0/16; you chose /24. Use /16 unless you know why." | One click: "Use /16" | |
| `members[1].priority` duplicate (manual numbers) | "proxy2: needs a different number from proxy1." | Focus field under Show details | |
| `health.timeout` out of range | "Health check time limit: 2 to 60 seconds." | Focus field | |
| Not a member (DHCP address changed) | "This server's address changed to 192.0.2.57. It is not one of the two servers any more." | "Use the new address" (updates the member and asks to run both scripts again) | |
| Port forward not moved (phase 2, 12.2) | "Visitors from the internet still reach 192.0.2.11 directly." | "Change your router's port forward to 192.0.2.10." | |

Every `FieldError.Field` gets a mapping entry (`field -> label key`) so no raw path like `members[1].priority` reaches
the page. A test enumerates every field the validators can return and fails on a missing mapping.

---

## 12. Steps 4 and 5

### 12.1 Step 4: Test it

1. Before starting, the page checks where it is served from (`location.hostname` against the member addresses).
   If the page runs on the main server, it says: "You are about to stop Dunree on proxy1, which runs this page.
   Open this page on proxy2 (link) or through the floating IP (link), then start the test there." Both links keep
   the current path and port. Linked servers share the session (cluster secret), so the user stays logged in;
   otherwise proxy2 asks for its own login, which the page says.
2. **Start the test**: the page shows the exact command for the main server from its `service` fact:
   `sudo systemctl stop dunree` (or the detected unit, or `docker stop <your Dunree container>` with a sentence),
   with one copy button, and "Run this on proxy1 now."
3. A live timeline, polled every second, one line per event with the time since start:
   "0 s proxy1 answers on the floating IP" - "4 s proxy1 does not answer its health check" -
   "7 s proxy2 took over the floating IP". Fetch errors during the move are shown as "Waiting while the floating IP
   moves..." and are not errors.
4. When the backup holds the IP: big green "It worked: proxy2 took over after 7 seconds." Then: "Start Dunree
   again on proxy1: `sudo systemctl start dunree`." With preempt on: "proxy1 takes the floating IP back about 1
   minute after it is healthy." The timeline keeps watching and adds that line too.
5. If nothing moved after `fall * interval + 20` s: "proxy2 did not take over." plus the matching failure state of
   section 11. "Stop the test" is always available.

### 12.2 Step 5: Point your firewall at 192.0.2.10

- Info icon (`info circle`), not a shield. Title: "Point your firewall at 192.0.2.10".
- Text: "In your router or firewall, change the port forward for ports 80 and 443 so it goes to 192.0.2.10 instead
  of 192.0.2.11. UniFi: Settings > Security > Port Forwarding. Example: public 203.0.113.5:443 -> 192.0.2.10:443."
- Checkbox "I've changed the port forward".
- Shown once, here only.
- Phase 2 (separate item, its own test): read-only detection. When the floating IP is enabled, the proxy counts,
  in memory, requests from non-private client addresses by local destination address
  (`http.LocalAddrContextKey`), last 10 minutes. If public visitors keep arriving at a server address, step 5
  shows the "still reach 192.0.2.11 directly" state; once they arrive at the VIP it ticks itself. Cost: one map
  increment per request, only when enabled.

---

## 13. Tests (every item automated)

| Area | Test |
|---|---|
| Main field | `validate_test.go`: `main` must be a member; derived priorities 150/100/99; manual mode untouched; old file without `main` loads unchanged and re-saves byte-identical when nothing changed. |
| Compat | Snapshot with `main` refused by the old strict parser (documented limit), `oldFollowers` minimum version bumped; health JSON with `vip` parses on the old struct. |
| Password | `generatePassword=1` makes an 8-char password once and never again; two scripts from one page carry the same `auth_pass`; regression test for the audit finding: two standalone first-time saves on two pages now show "already set up on proxy1" on the second (handler test with a fake peer health JSON). |
| Script render | Golden scripts for main/backup, ufw on/off, sysctl on/off, `-k` on/off, IPv6; `sh -n` on every golden (skipped with a message if `sh` is missing); unquoted-`$D_` scanner; every whitelist refuses `'`, `$`, backtick, `\`, newline, space; delimiter lines refused; `FuzzVIPScript` feeding random member labels/interfaces/URLs through the validators into `Script` and asserting the guard holds. |
| Script behaviour | Run the inner script with `sh` in a temp dir with PATH stubs (`id`, `ip`, `keepalived`, `systemctl`, `apt-get`, `dnf`, `runuser`, `ufw`, `firewall-cmd`, `cmp`) and the root paths rewritten by a test-only renderer option (`ScriptEnv.Root`, empty in production and not reachable from the API). Cases: not root, wrong server, wrong interface, package install per OS family, unsupported OS, health fail, `keepalived -t` fail (output hidden, no `auth_pass` value on stdout/stderr), first install, second run idempotent (no backup, no restart), changed settings (one backup, restart), ufw insert and replace, ufw reload fail restores backup, start timeout. Every case asserts the password never appears in the output. |
| Suggest | Fake lister, ARP file and dialer: excludes members, gateway, ARP entries, answered addresses; at most 12 probes; /16 host only probes its /24. |
| Status | `nodes[]` state table of 10.1 from fixtures; marker file parser (size limit, unknown keys ignored); health JSON `vip` block only for member/loopback sources; cgroup unit parser; DMI platform mapping; netlink dynamic flag via fake. |
| Failure detection | Both held, nobody held, flapping, outdated, each from a poll sequence. |
| Field mapping | Every validator field has a label key (enumerated). |
| UI smoke | `tools/ui-smoke/cluster_vip_smoke.py` new scenarios with fixture status: before-you-start all states and the link flow; step 1 card selection by keyboard; suggestions; DHCP tick; two node cards with the right title per member and the "Run this on X" name equal to the member in the script header (audit finding); each card state; next-step banner for each rule of 10.2; test timeline from a fixture sequence; failure states; firewall step appears exactly once; no shield icon in the section; copy button height equals its heading row height (+-2 px); 390 px and 1920 px; light and dark; no nested scroll (existing assertion). Ports below 32768. |
| i18n | `tools/i18n/extract.py` and `--check` pass. |

---

## 14. Known limits

- Floating IP suggestions and the "address in use" check are best effort. No answer does not prove an address is
  free. Dunree cannot read the router's DHCP range; the user's tick is the only check.
- VRRP (protocol 112) cannot be tested before install without raw sockets. Blocking is detected only after
  install, when both servers hold the IP, and only when Dunree can reach the peer's health endpoint.
- Peer facts depend on reaching the peer's Dunree health endpoint from this server. If it is blocked, the other
  card is generated with guessed values; the script then refuses to run on a mismatch instead of breaking.
- The source-address restriction on the health JSON `vip` block is not authentication (addresses can be spoofed on
  the LAN). The block holds no secret; it reveals interface name, health port and floating IP state.
- The installer supports apt and dnf systems with systemd. Alpine, Arch, OpenRC and others get a plain refusal and
  the raw commands under Show details.
- The installer handles ufw and firewalld. nftables-only and other firewalls are named in the final message, not
  changed.
- The old keepalived.conf is backed up but not restored automatically when keepalived fails to start.
- A follower older than this release refuses settings that carry `main` (strict parser); update followers first.
- Cloud detection covers the vendors listed in 9.6 only.
- "Test it" needs the page to be served by a server that stays up; the page tells the user to switch, it cannot do
  it for them.
- More than two servers work but the simple path is designed and tested for two.
- Pasting in some web consoles mangles long text; the download link is the workaround.
- The VRRP password is still sent in clear on the LAN (keepalived PASS auth). It prevents accidental cross-talk; it
  is not security. Unchanged from `vip-plan.md`.

---

## 15. Build order

1. Backend: `main` + `dhcpChecked` fields, derived priorities, `generatePassword`, field-label mapping (tests).
2. Backend: `vip.Script` and `GET /api/cluster/vip/script` with the full safety test set.
3. Backend: health JSON `vip` block, marker file reader, `nodes[]` states, failure detection, extra read-only
   checks, `suggest`.
4. Page: new layout (sections 3 to 7, 10 to 12), old "Configuration for" select and tabs removed, overrides
   moved under Show details; smoke scenarios; i18n extract and check.
5. Docs: rewrite `docs/guides/floating-ip-keepalived.md` around the new steps (placeholders only); pointer in
   `vip-plan.md` section 8; `docs/ux/changes.md` entry; known limits into DEVELOPMENT.md.
6. Phase 2: port-forward detection (12.2).
