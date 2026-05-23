# Iptables WireGuard helpers

Three xtables targets in one kernel module, for running WireGuard
across hostile or asymmetric networks:

- **`WGOBFS`** — chacha-keyed payload obfuscation. DPI can't fingerprint
  the WG message shape. Cross-platform clients can use
  [rs-wgobfs](https://github.com/infinet/rs-wgobfs).
- **`WGANYCAST`** — WG-protocol-aware dynamic anycast pool learning.
  Allocates a per-session anchor conntrack on first observed RESP,
  encoding `(Sa, our_idx)` in the ORIGINAL tuple and `(Sa, peer_idx)`
  in REPLY.  LEARN refreshes-or-inserts each observed inbound source
  into a **4-entry inline pool stored in the anchor's helper
  extension `data[32]` area**; SPRAY picks one uniformly at random
  and rewrites outbound dst.  No static pool enumeration at the
  rule level — pool entries are learned from observed inbound WG
  traffic and self-reap via standard conntrack GC at WG
  `REJECT_AFTER_TIME + 20 s`.
- **`WGPTCP`** — UDP↔fake-TCP transmutation with stateful flow
  tracking via `nf_conn_acct` (the kernel's per-direction byte+packet
  counter extension).  Reproduces a textbook Linux TCP handshake +
  ESTABLISHED data stream so middleboxes that block or rate-limit UDP
  let the flow through.  Re-handshakes ride as PSH+ACK on the same
  conntrack entry — the middlebox sees one uninterrupted ESTABLISHED
  stream and never observes a SYN→ESTABLISHED transition.

All three ship in a single consolidated `xt_wg.ko` (plus three
userspace plugins). Backward-compat aliases (`xt_WGOBFS`,
`xt_WGANYCAST`, `xt_WGPTCP` and their `ipt_*` / `ip6t_*` variants)
resolve to `xt_wg.ko` via the kernel's modalias lookup, so existing
`/etc/modules-load.d/` entries and iptables auto-load keep working.

Build system: `autotools` + `src/Makefile.libxt.in`.


## Build & install

### Dependencies

- Alpine: `alpine-sdk iptables-dev linux-lts-dev`
- CentOS 7: `iptables-devel kernel-devel`
- Debian 10-13: `autoconf libtool libxtables-dev linux-headers pkg-config`
- openSUSE 15: `autoconf automake gcc kernel-default-devel libtool libxtables-devel make`

### Build

```shell
./autogen.sh
./configure
make
sudo make install
sudo depmod -a && sudo modprobe xt_wg
```

Produces `src/xt_wg.ko` (one kernel module, all three targets) and
`src/libxt_WG{OBFS,ANYCAST,PTCP}.so` (three userspace plugins).

openSUSE may refuse unsupported modules; allow with
`/etc/modprobe.d/10-unsupported-modules.conf` containing
`allow_unsupported_modules 1`.

### DKMS

```shell
./autogen.sh && ./configure
make tarball
sudo make dkms-install
```

### Debian / Ubuntu (`.deb`)

The `debian/` tree builds three `.deb` packages via debhelper.

```shell
sudo apt-get install autoconf automake libtool libxtables-dev pkgconf \
                     debhelper-compat dh-dkms devscripts fakeroot
dpkg-buildpackage -us -uc -b
```

Produces in the parent directory:

- `xt-wg-common_<v>_<arch>.deb` — userspace plugins
  (`libxt_WG{OBFS,ANYCAST,PTCP}.so`).
- `xt-wg-source_<v>_all.deb` — drops `/usr/src/xt-wg.tar.bz2` with an
  inner `debian/` for module-assistant. After install run
  `sudo m-a a-i xt-wg` to compile a kernel-version-specific
  `xt-wg-modules-$(uname -r).deb`.
- `xt-wg-dkms_<v>_all.deb` — kernel-module source for DKMS auto-rebuild.
  Installing the deb triggers a build for every installed kernel; new
  kernels rebuild automatically.

Install `xt-wg-common` plus exactly one of `xt-wg-dkms` or the m-a-built
modules deb — the two kernel-module mechanisms are equivalent.

Tested on Alpine 5.15, CentOS 7, Debian 10-13, openSUSE 15.5.


## WGOBFS

Sender and receiver share a key, used by `chacha6` to derive identical
pseudo-random keystream on both ends. The first 16 bytes of every WG
message are obfuscated, the zero `mac2` field is overwritten with
random bytes, the message is padded with random trailing bytes, the
Diffserv field is zeroed, and ~80% of keepalives are dropped.
`chacha6` is chosen for speed — the goal is unrecognizability, not
encryption.

### Usage

`--key <secret>` — shared between client and server. Truncated or
repeated to 32 characters; this is the `chacha6` key.

`--obfs` / `--unobfs` — operation mode.

Client, assuming server on port 6789:

```shell
iptables -t mangle -I INPUT  -p udp --sport 6789 -j WGOBFS --key SECRET --unobfs
iptables -t mangle -I OUTPUT -p udp --dport 6789 -j WGOBFS --key SECRET --obfs
```

Server is the mirror image (swap `--sport` / `--dport`).

### As a relay

Useful for Windows/Mac/mobile clients that can't load the kernel
module. The relay DNATs to the real WG server and obfuscates the
forwarded traffic:

```shell
iptables -t nat -A PREROUTING  -p udp -d RELAY_WAN_IP --dport 6789 -j DNAT --to-destination REAL_WG:6789
iptables -t nat -A POSTROUTING -p udp -d REAL_WG     --dport 6789 -j MASQUERADE
iptables -t mangle -A FORWARD -p udp -d REAL_WG --dport 6789 -j WGOBFS --key SECRET --obfs
iptables -t mangle -A FORWARD -p udp -s REAL_WG --sport 6789 -j WGOBFS --key SECRET --unobfs
```

### IPv6 and MSS clamp

Replace `iptables` with `ip6tables`; set WG MTU to 1280. Clamp TCP
MSS on tunnelled traffic:

```shell
iptables -t mangle -A FORWARD -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu
```

### Performance

Two Alpine VMs (1 CPU, 256M RAM), iperf3 over WG: 1.1 Gbps without
obfuscation, 950 Mbps with.

### OpenWrt

See [openwrt/package/README.md](/openwrt/package/README.md).


## WGANYCAST

WG-protocol-aware dynamic anycast pool learning + per-packet UDP
destination spray.  Pool is built at runtime from observed inbound
WG traffic, keyed by WG session indices.  An **optional per-rule
`--init-pool`** flag supplies a static cold-start fallback for
hosts that originate WG sessions and have no inbound traffic to
learn from on first packet.

v10 (current) adds the optional `--init-pool` to v9's design.  v9
itself replaced v3.x's synthetic-anchor design with **real WG flow
cts as masters** plus **synthetic-marker expectations** for
indexing.  No private rhashtable, no manual `nf_conntrack_alloc`,
no `dport=0` synthetic anchors polluting `/proc/net/nf_conntrack`.

### Mechanism

| Hook | Rule | Action |
|---|---|---|
| `raw` PREROUTING (any prio) | `-p udp --dport <listenPort> -j CT --helper WGANYCAST` | Attach the WGANYCAST conntrack helper to peer-initiated WG cts. |
| `raw` OUTPUT (any prio) | `-p udp --dport <listenPort> -j CT --helper WGANYCAST` | Attach to us-initiated WG cts.  **Both directions are mandatory** — CT --helper attaches the helper at ct CREATION via template copy, so the direction that creates the ct must match. |
| conntrack-helper, prio +300 | helper's `.help` callback (`wga_help`) | On RESP (in/out): claim ct as per-session master (set `IPS_FIXED_TIMEOUT_BIT` + 200 s timeout, **REFRESHED on every promotion AND every inbound DATA**), register two marker expectations under it (one keyed by `our_idx`, one by `peer_idx`).  On inbound DATA/COOKIE: look up master via `our_idx` marker, refresh master TTL + pool's (saddr, sport) entry. |
| `raw` OUTPUT, prio −300 | `-p udp --sport <listenPort> -j WGANYCAST` *or* `-d <peer> --dport <port> -j WGANYCAST --init-pool …` | Parse WG header for the idx visible in the outbound packet (sender_idx for INIT/RESP = our_idx; receiver_idx for DATA/COOKIE = peer_idx).  **Master found** → pick from master's learned pool, rewrite `iph->daddr` + `udph->dest` with incremental checksum updates.  Also seed master's pool with rule's `--init-pool` entries via `wga_seed_pool_if_absent` (no refresh of existing slots → preserves seed-then-decay).  **Master NOT found + `--init-pool` non-empty** → cold-start fallback: pick a random init entry and rewrite (`spray_init_rewrote++`).  **Master NOT found + no init pool** → `XT_CONTINUE` (`spray_no_master++`). |

### Marker expectations

Each master ct holds up to 8 markers (`expect_policy.max_expected
= 8`), with `dst.protonum = WGA_MARKER_PROTO (253)`.  Real WG
traffic is proto=UDP=17, so the kernel's expectation-matching
code (which compares `tuple.dst.protonum` exactly, with no mask)
never mistakes a real packet for one of our markers.

```c
src.l3num    = AF_INET
dst.u3.ip    = idx_as_be32       /* our_idx OR peer_idx — primary key
                                  * AND hash input (see below) */
dst.protonum = WGA_MARKER_PROTO  /* 253 — RFC 3692 experimental */
all other fields = 0             /* mask = 0xFFFFFFFF / 0xFFFF */
```

The idx lives in `dst.u3.ip` rather than `src.u3.ip` because
`nf_ct_expect_dst_hash` (the kernel's expectation hashtable hash
function) keys on `dst.u3.all` + `dst.protonum` + `dst.u.all` +
`src.l3num` — none of `src.u3` contributes.  Putting the per-
session idx in `dst.u3.ip` spreads markers across the 8192-bucket
expect hashtable; putting it in `src.u3.ip` would pile every
marker into ONE bucket and degrade `__nf_ct_expect_find` to O(N)
across all sessions.

`max_expected = 8` is sized to span WG's transient session
overlap.  During re-key both old and new sessions transmit DATA
for up to `REJECT_AFTER_TIME = 180 s`; the OLD session's
`peer_idx` is still on outbound DATA until the old key expires,
so the OLD marker must remain registered alongside the NEW one.
At 8 slots, up to 4 sessions' markers coexist per master — well
above the 2 sessions WG actually allows concurrently.  The
kernel does NOT auto-evict expectations on overflow (returns
`-EMFILE`), so undersizing `max_expected` directly caps the
outbound rewrite rate.

### Pool storage — inline in `help->data[32]`

The per-master pool is stored **inline** in the helper extension's
fixed 32-byte `data[]` area (`struct nf_conn_help.data`, exposed
via `nfct_help_data()`).  Pool layout (8 bytes per entry × 4
entries = 32 bytes, fills `help->data[32]` exactly):

```c
struct wga_pool_entry {
    __be32 ip;             /* 4 — 0 marks free slot */
    __be16 port;           /* 2 */
    __u16  last_seen_q8;   /* 2 — (jiffies >> 3) wrapped to 16 b */
};
```

LRU compare uses wrap-aware unsigned arithmetic: the 16-bit
`last_seen_q8 = (jiffies >> 3)` wraps every ~524 s at HZ=1000.
The unambiguous-compare half-window is 262 s — comfortably larger
than the 200 s master ct lifetime cap, so any two slots can be
ordered correctly within a master's life.  Serialised by
`master->lock` (the `spinlock_t` already in `struct nf_conn`).

### Lifecycle

| Object | Created | Reaped by |
|---|---|---|
| Master ct (real WG flow) | First RESP through `wga_help` after the ct gains the helper extension | `IPS_FIXED_TIMEOUT_BIT` + 200 s TTL, REFRESHED on every promotion + every inbound DATA.  Active sessions stay alive indefinitely; idle sessions expire 200 s after last packet. |
| Markers (`nf_conntrack_expect`) | At RESP, two per session (`our_idx` + `peer_idx`) | Destroyed by `nf_ct_remove_expectations(master)` when master ct is destroyed.  `expect_policy.timeout = 86400` is a far ceiling — master ct's 200 s TTL governs. |
| Inline pool (4 × 8 B in `help->data[32]`) | Initialised zero by `nf_ct_helper_ext_add`; populated by `wga_help` on inbound DATA | Freed automatically as part of the help extension when the master ct is destroyed. |
| Per-door cts (anycast doors) | Standard conntrack hook on each new inbound/outbound tuple | UDP unreplied 30 s / stream 120 s.  Independent of master; `ct->master` is never set. |

No module-private kmalloc, no module-managed GC, no `.destroy`
callback on the helper.

### Helper attach quirks

- **No more sysctl auto-attach.**  Modern kernels (post-CVE-2017-7184)
  removed `net.netfilter.nf_conntrack_helper` entirely.  The
  `helper.tuple.dst.u.udp.port = htons(51821)` field no longer
  causes any auto-attach; explicit CT --helper rules are the only
  mechanism.

- **`nf_ct_expect_init` NULL handling.**  The kernel's
  `nf_ct_expect_init(exp, class, family, saddr, daddr, proto, src,
  dst)` checks **only `saddr`** for NULL — the other three pointer
  args (`daddr`, `src` port, `dst` port) are dereferenced
  unconditionally via `memcpy(..., daddr, len)` and `*src` /
  `*dst`.  Passing NULL for any of them → instant kernel NULL-ptr
  panic.  `wga_register_marker` works around this by passing
  pointers to zero-valued stack locals.

- **`IPS_FIXED_TIMEOUT_BIT` write pattern.**  v9's first cut
  guarded the TTL write with `test_and_set_bit(...)`, so the TTL
  was set on the *first* promotion and never refreshed.  Re-keys
  on the same ct fired promotion again but the TTL stayed at
  `first_promotion + 200 s` — the ct died despite RESPs still
  coming.  Current code uses `set_bit(...)` + unconditional
  `WRITE_ONCE(ct->timeout, ...)` so every promotion AND every
  inbound DATA pool refresh extends the TTL.

### Multi-peer on one WG interface

Markers are keyed by `our_idx` / `peer_idx` (32-bit WG session
indices, unique per active session on a device).  Two peers
sharing the same listenPort get distinct masters; spray for one
session never reaches another session's pool.  No per-peer rule
configuration needed.

### Example: WG over two Cloudflare Spectrum anycasts

Gateway maps both anycast IPs' UDP/59263 → backend's WG :51821.
WG's `listenPort = 51821` on both ends.

**Receiver side** (the WG backend; pool grows naturally from
inbound traffic):

```shell
# Attach helper to inbound WG cts (peer-initiated sessions).
iptables -t raw -A PREROUTING -p udp --dport 51821 \
  -j CT --helper WGANYCAST

# Attach helper to outbound WG cts (us-initiated sessions).
iptables -t raw -A OUTPUT     -p udp --dport 51821 \
  -j CT --helper WGANYCAST

# Spray outbound across learned doors (catch-all, no init pool).
iptables -t raw -A OUTPUT     -p udp --sport 51821 -j WGANYCAST
```

**Initiator side** (CN hub originating WG to the backend; needs
cold-start init pool because nothing inbound has been observed
yet):

```shell
# Same two helper-attach rules as above.
iptables -t raw -A PREROUTING -p udp --dport 51821 \
  -j CT --helper WGANYCAST
iptables -t raw -A OUTPUT     -p udp --dport 51821 \
  -j CT --helper WGANYCAST

# Per-peer SPRAY rule with cold-start init pool of CF Spectrum
# anycast IPs paired with the app's edgePort.  No catch-all —
# the per-peer rule's -d filter is mutually exclusive.
iptables -t raw -A OUTPUT     \
  -d 193.134.211.67 -p udp --dport 51821 \
  -j WGANYCAST \
  --init-pool 138.252.162.176:59263,161.248.136.186:59263
```

Until the first inbound RESP arrives, outbound WG packets get
rewritten to a random init-pool entry (`spray_init_rewrote++`).
Once the helper sees a RESP and promotes a master, the SPRAY path
seeds the init entries into master's pool via
`wga_seed_pool_if_absent` (no refresh of existing slots, so the
seed-then-decay property holds), and steady-state spray is from
master's pool (`spray_rewrote++`).  Real-observed doors that
match init entries (saddr == init.ip, sport == edgePort —
typical for CF Spectrum) get LRU-promoted on subsequent inbound
RX; unmatched init entries age out as the pool fills with real
doors.

Port-translation by the gateway (e.g. anycast:59263 →
backend:51821 in CF Spectrum) is learned implicitly on the
receiver side because `wga_help` captures the observed source
`(ip, port)` into the inline pool on every inbound DATA.  On the
initiator side, the rule's `--init-pool` carries the same
`(anycast_ip, edgePort)` tuples explicitly so the cold-start
path knows where to spray before any inbound traffic exists.

### Diagnostics

```shell
# Helper-attachment state.  USE netlink (conntrack-tools), not
# /proc/net/nf_conntrack — /proc hides the helper= field in some
# kernel configs.
nix-shell -p conntrack-tools --run \
  "conntrack -L --proto udp -o extended | grep '51821'"
#   ipv4 2 udp 17 175 src=... [ASSURED] mark=0 helper=WGANYCAST use=1

# Markers (one or more per active master, dst.protonum=253).
sudo cat /proc/net/nf_conntrack_expect
#   86399 proto=253 src=168.25.179.227 dst=0.0.0.0 PERMANENT
#   ...

# Live counters.  Health signature on a working host:
#   spray_rewrote / spray_total      → ~0.9       (most outbound rewritten)
#   spray_no_master / spray_total    → < 0.1      (cold-start + short transients)
#   spray_init_rewrote / spray_total → < 0.01     (init-pool fallback rare after handshake)
#   spray_init_seed / spray_total    → varies     (every spray_rewrote on init-pool rules)
#   pool_match_refresh / inbound DATA→ 0.7-0.9    (steady-state pool hot)
#   master_promote_lost              → near 0     (race losses rare)
#   marker_register_fail             → 0          (max_expected sized right)
cat /proc/net/wganycast_stats
```

If `spray_no_master` is high (> 0.5 of `spray_total`), check in
order:

1. **Helper coverage** — `conntrack -L -o extended | grep 51821
   | grep -c helper=WGANYCAST` should match the count of primary
   WG cts (dport=51821 OR sport=51821).  Helper-less primary cts
   indicate a missing CT --helper rule in one direction; you need
   BOTH PREROUTING and OUTPUT covered.
2. **Marker accumulation** — `wc -l /proc/net/nf_conntrack_expect`
   should reach `2 × active_peers` quickly, and grow under re-key
   load.  Stuck low → master cts are dying (TTL not refreshing).
3. **`marker_register_fail` climbing** — `max_expected` too low
   for current session churn.  Bump in `wga_exp_policy`.

### Notes

- **Anti-poisoning**: `wga_help` only processes packets passing
  WG type byte + size validation.  Attacker would need to forge
  the receiver-side `our_idx` (32-bit value chosen by WG kernel at
  handshake) AND match an in-pool slot — bounded by the 4-entry
  LRU cap, legitimate anycast IPs displace attackers on next
  genuine inbound.
- **`iptables -j DNAT --random` is not equivalent**: `-j DNAT`
  runs in `nat` and registers the mapping in conntrack, so every
  packet of the same 5-tuple inherits the *first* random pick.
  WGANYCAST picks per-packet, with per-session pool isolation.
- **Pre-v3 `--dest` / `--canonical` and v3.x `--learn` /
  `--spray` are gone**.  v10's only flag is the optional
  `--init-pool <ip>[:<port>][,<ip>[:<port>]]...` (also accepted
  in repeat-flag form as `--init-dest <ip>[:<port>]`, max 4
  entries combined).  Omitting the flag preserves receiver-side
  behaviour (pool grows from inbound RX only).
- **IPv4 only.**  Same constraint as WGPTCP; IPv6 support would
  need parallel paths in the marker tuple builders.


## WGPTCP

WG-aware UDP↔fake-TCP transmutation. Per-flow state is read from
kernel-managed conntrack accounting (`nf_conn_acct`, the per-netns
extension behind `sysctl net.netfilter.nf_conntrack_acct=1`). The
encoder writes nothing to the conntrack entry — no `ct->mark` claim,
no `ct->labels` claim — and reads byte/packet counters in both
directions for byte-accurate seq AND ack_seq math.

Wire-shape decision is **conntrack-state-driven** (not
WG-type-driven):

| State                                                | Shape     | Options                                              | Growth |
|------------------------------------------------------|-----------|------------------------------------------------------|-------:|
| `own_packets == 1` + `IP_CT_NEW`                     | `SYN`     | MSS + SACK_Perm + TS + WSCALE=7 + TFO_Cookie (28 B)  | +40 B  |
| `own_packets == 1` + `IP_CT_ESTABLISHED_REPLY`       | `SYN+ACK` | same                                                 | +40 B  |
| `own_packets >  1` + WG INIT + `!SEEN_REPLY`         | `SYN`     | same (stuck-flow recovery)                           | +40 B  |
| `own_packets >  1`                                   | `PSH+ACK` | TS only (12 B)                                       | +24 B  |

`own_packets = acct->counter[own_dir].packets` (auto-incremented by
conntrack at -200 before encoder runs at -150). Both own_cum and
peer_cum come from `acct->counter[dir].bytes - packets * 28`
(stripping IP+UDP overhead). No module-side writes to any conntrack
field.

The TCP option set on `SYN`/`SYN+ACK` matches what stock Linux's
`tcp_select_initial_window` emits, so the initial fingerprint passes
`p0f`-style classifiers as "Linux".

Re-handshakes on a working flow (WG `REJECT_AFTER_TIME = 180 s`,
re-key every 120 s) ride as PSH+ACK with cumulative seq on the SAME
conntrack entry — the middlebox sees one uninterrupted ESTABLISHED
stream and never observes a SYN→ESTABLISHED transition. This is the
v2 fix for the v1.5 failure mode (Cloudflare-Spectrum-style strict
middleboxes dropping the re-handshake's fresh SYN as out-of-window).

**Stuck-flow recovery:** if `own_packets > 1` (we've sent at least
one prior outbound) but `IPS_SEEN_REPLY` is still unset — i.e., no
return packet has ever come back — the middlebox on the return path
probably dropped our handshake without opening flow state.  The
encoder re-fires a fresh SYN on every WG type=1 INIT.  WG itself
drives the cadence (`REKEY_TIMEOUT = 5 s`, capped at
`REKEY_ATTEMPT_TIME = 90 s`), so worst case is ~18 SYN retransmits
before WG gives up.  Once any reply lands and `IPS_SEEN_REPLY` flips,
the encoder drops back to PSH+ACK.  Accounting counters keep
incrementing through the refire so cum_bytes math is correct for
the post-recovery stream.

The recovery condition fires only on the **originator** side. On the
responder, `IPS_SEEN_REPLY` flips to true the moment the first
outbound is emitted (outbound IS the reply direction from conntrack's
POV), so the same signal isn't usable there. Fine in practice — once
the originator's recovery SYN gets through, the responder's existing
PSH+ACK retransmits land naturally.

**Byte-accurate ack_seq (v2.2):** the encoder reads peer's cumulative
bytes from `acct->counter[peer_dir].bytes` (auto-incremented by
conntrack on every inbound) and uses it directly in ack_seq math.
ack_seq advances byte-by-byte as more inbound data is observed —
strict middleboxes that demand monotonic ack progression now see
exactly that, not v2.0/2.1's stationary duplicate-ACK pattern. Works
correctly for the cookie scenario too (peer_init = 64 B is read from
accounting, not inferred from ctinfo direction).

### Sequence derivation

`tcph->seq` and `tcph->ack_seq` are derived from `iph->{saddr,daddr}`
via SipHash-2-4 with `--key`, plus per-direction cumulative byte
counters from `nf_conn_acct`:

```
SYN.seq         = H(K, saddr, "out ")
SYN+ACK.seq     = H(K, saddr, "out ")
SYN+ACK.ack_seq = H(K, daddr, "out ") + 1 + peer_cum
PSH+ACK.seq     = H(K, saddr, "out ") + 1 + own_cum_before
PSH+ACK.ack_seq = H(K, daddr, "out ") + 1 + peer_cum
```

Where:
```
own_dir         = ctinfo == IP_CT_ESTABLISHED_REPLY ? REPLY : ORIGINAL
peer_dir        = !own_dir
own_cum_incl    = acct->counter[own_dir].bytes  - own_packets  * 28
peer_cum        = acct->counter[peer_dir].bytes - peer_packets * 28
own_cum_before  = own_cum_incl - current_payload_len
```

`28` is the per-packet IP (20 B) + UDP (8 B) header overhead.
Subtracting it gives WG-payload-only cumulative bytes, matching the
scale the seq math expects. Counters are auto-incremented by the
conntrack hook at priority -200, before the encoder runs at -150;
own_packets includes the current outbound, so first-outbound
detection collapses to `own_packets == 1`.

### TFO cookie marker

`SYN`/`SYN+ACK` carry a 4-byte TFO cookie used by the decoder to
distinguish our fake-TCP from real TCP traffic. With `--key`,
cookie = `H(K, tcph->seq, "ckie")[0..4)`; without, a fixed sentinel
`0xC07F0001`. Deriving from `tcph->seq` (rather than IP addresses)
makes the cookie **NAT-immune** — TCP sequence numbers aren't
rewritten by any conventional NAT (1:1 NAT, Cloudflare Spectrum DNAT,
provider SNAT pools).

### Hook placement — load-bearing

The decoder MUST run in **`raw` PREROUTING** (priority -300), not
`mangle` (-150). Kernel hook priorities at PREROUTING:

| Priority | Hook |
|---|---|
| -300 | `raw` |
| -200 | conntrack |
| -150 | `mangle` |

If the decoder runs after conntrack, conntrack creates a TCP-flow
entry and the kernel TCP stack RSTs the SYN. By running at -300, the
rewrite predates conntrack — the packet becomes UDP, conntrack creates
a UDP entry, the kernel TCP stack never sees a TCP packet. **No
companion `-j DROP` rule is needed.**

### Usage

```shell
iptables -t mangle -A OUTPUT -p udp -d PEER --dport 51821 \
  -j WGPTCP --encode --key 0123456789abcdef0123456789abcdef
iptables -t raw    -A PREROUTING -p tcp -s PEER --sport 51821 \
  -j WGPTCP --decode --key 0123456789abcdef0123456789abcdef
```

Server is the mirror image. WG is symmetric — either side may emit
type-1 (initiation), so install both encode and decode on each side.

#### Flags

- **`--encode` / `--decode`** (mutually exclusive, required) —
  operation mode.
- **`--key <32 hex chars>`** (optional) — 16-byte siphash key. When
  omitted, falls back to the fixed sentinel cookie + unkeyed
  defaults; works but is more easily mis-classified if a real TFO
  client connects to the same port.
- **`--obfs`** (optional) — also apply WGOBFS-style payload mangling
  (chacha-XOR head 16 B, random padding, keepalive drop, mac2 zero)
  inside the fake-TCP segment. Hides the WG message signature from
  deep DPI that unwraps the TCP. Requires `--key`; chacha key is
  derived as `key || key` (32 B). Both ends must agree.

### MTU

v2 sustained overhead is +24 B/packet (PSH+ACK with TS option). With
underlay MTU 1500 and WG transport overhead 60 B, recommended WG
interface MTU is **1416** (or 1408 with safety margin). Initial SYN
(+40 B) fits since handshake messages cap at 148 B before wrapping.

With `--obfs`: random padding adds 0..32 B; budget another -32 in MTU.

### State storage

WGPTCP v2.2 reads per-direction byte/packet counters from
`nf_conn_acct` (the kernel's built-in conntrack accounting extension).
The encoder writes nothing to the conntrack entry — no `ct->mark`
claim, no `ct->labels` claim. Hosts are free to use `-j CONNMARK`,
`-m mark`, or fwmark-based routing independently of wg-ptcp.

The only kernel-side claim is the sysctl
`net.netfilter.nf_conntrack_acct = 1`, which is per-netns. The NixOS
module auto-sets this; the kernel module also force-enables it at
init time. If both are bypassed, the encoder falls back to
`XT_CONTINUE` (UDP escapes unencoded) for any conntrack without the
acct extension, logged via `pr_warn_ratelimited`.

### Probe resistance

Real TCP SYNs to the fake-TCP port without our cookie marker fail the
check and the decoder returns `XT_CONTINUE`, so the kernel RSTs —
distinguishable from a real idle TCP service. To make the port look
idle, also bind a tiny accept-and-close TCP listener on the same port
(e.g. systemd-socket-activated `socat - SYSTEM:'true'`). Real fake-TCP
packets still rewrite at `raw` PREROUTING before reaching the kernel
TCP stack, so the listener never sees them.

### IPv4 only

v1 limitation, carried forward. IPv6 is straightforward — same wire
shape, different IP header struct + `csum_ipv6_magic`.


## Authors

- **WGOBFS** — Chen Wei \<weichen302@gmail.com\>
- **WGANYCAST, WGPTCP, consolidated `xt_wg.ko`** —
  Bingchen Gong \<gongbingchen@gmail.com\>


## License

GPL v2
