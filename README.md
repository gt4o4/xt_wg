# Iptables WireGuard helpers

Three xtables targets in one kernel module, for running WireGuard
across hostile or asymmetric networks:

- **`WGOBFS`** — chacha-keyed payload obfuscation. DPI can't fingerprint
  the WG message shape. Cross-platform clients can use
  [rs-wgobfs](https://github.com/infinet/rs-wgobfs).
- **`WGANYCAST`** — WG-protocol-aware dynamic anycast pool learning.
  Allocates a per-session anchor conntrack on first observed RESP,
  encoding `(Sa, our_idx)` in the ORIGINAL tuple and `(Sa, peer_idx)`
  in REPLY.  LEARN registers permanent `nf_conntrack_expect` entries
  under the anchor for each observed inbound source; SPRAY picks one
  uniformly at random and rewrites outbound dst.  No static pool
  enumeration at the rule level — pool entries are learned from
  observed inbound WG traffic and self-reap via standard conntrack
  GC at WG `REJECT_AFTER_TIME + 20 s`.
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
destination spray.  Two modes, no rule-level arguments — the pool is
built at runtime from observed inbound WG traffic.

### Modes

- **`--learn`** — install in `raw` PREROUTING (priority -300, BEFORE
  conntrack at -200).  Parses the WG type byte and extracts session
  indices (`sender_index` / `receiver_index`) from the WG payload.
  On type=2 RESP, allocates a per-session anchor conntrack (synthetic
  5-tuple encoding `(Sa, our_idx)` in ORIGINAL, `(Sa, peer_idx)` in
  REPLY, `dst.port = 0` so the tuple never collides with a real flow).
  On every observed inbound, registers or refreshes a permanent
  `nf_conntrack_expect` under the anchor for the packet's
  `(anycast_src, anycast_sport)`.  Pool is capped at 8 entries with
  LRU eviction.
- **`--spray`** — install in `raw` OUTPUT (priority -300, BEFORE
  conntrack at -200).  Looks up the anchor by WG `receiver_index`
  (= `peer_idx` for outbound DATA/COOKIE).  Iterates the anchor's
  expectations, picks one uniformly at random, rewrites `iph->daddr`
  + `udph->dest` with incremental checksum updates.  Empty pool →
  `XT_CONTINUE` (packet goes to WG's configured `peer.endpoint`
  as-is — handles cold-start handshakes).

Mutually exclusive in a single rule.  Typical deployment: one LEARN
rule plus one SPRAY rule per WG listenPort.

### Anchor lifecycle

| Object | Created | Reaped by |
|---|---|---|
| Anchor `nf_conn` | LEARN/SPRAY at first observed RESP | conntrack GC at 200 s (WG `REJECT_AFTER_TIME + 20 s`).  `IPS_FIXED_TIMEOUT_BIT` blocks refresh; `nf_ct_remove_expectations()` clears the pool automatically. |
| Permanent expectation | LEARN on inbound observation | Anchor reap (bulk-removed via `nf_ct_remove_expectations`), or pool-capacity LRU evicts oldest via `nf_ct_unexpect_related`. |
| Real child ct (anycast flow) | conntrack hook on each new inbound/outbound tuple, via expectation match | UDP unreplied 30 s / stream 120 s. |

No module-private storage, no module-managed GC, no per-packet
refresh dance.  A no-op `nf_conntrack_helper` (matching never-used
UDP port 0) is registered to satisfy the kernel's helper-required
check in `__nf_ct_expect_check` — it has no `.help()` work and never
auto-attaches to real flows.

### Multi-peer on one WG interface

Anchors are keyed by WG `our_idx` (32-bit session index, unique per
active session on a device).  Two peers sharing the same listenPort
get distinct anchors; LEARN/SPRAY for one session never affects the
other.  No per-peer rule configuration needed.

### Re-key handling via WG's overlap window

WG re-keys every ~120 s (`REKEY_AFTER_TIME`).  `REJECT_AFTER_TIME =
180 s` gives a ~60 s window where both old and new session indices
are live: the new anchor's pool refills from observed traffic before
the old anchor expires at 200 s.  No special handling required.

### Example: WG over two Cloudflare Spectrum anycasts

Gateway maps both anycast IPs' UDP/59263 → backend's WG :51821.
WG's `listenPort = 51821` on both ends.

```shell
# Observe inbound, learn the anycast doors.  Self-installs the
# per-session anchor + permanent expectations.
iptables -t raw -A PREROUTING -p udp --dport 51821 -j WGANYCAST --learn

# Spray outbound across the learned doors.  Cold-start handshake
# (no anchor yet) falls through to WG's configured peer.endpoint.
iptables -t raw -A OUTPUT     -p udp --sport 51821 -j WGANYCAST --spray
```

That's the entire ruleset — both directions of the flow are handled
by the conntrack hashtable.  Port-translation by the gateway (e.g.
anycast:59263 → backend:51821 in CF Spectrum) is learned implicitly
because the expectation captures the observed source `(ip, port)`.

### Diagnostics

Anchors and pool entries are visible through standard conntrack
introspection — no module-specific procfs file.

```shell
# Per-session anchors: `dport=0` is the synthetic-tuple signature.
# `src=<Sa.ip>` is our local WG endpoint, `dst=<idx_as_ip>` decodes to
# the session index (little-endian).  `[ASSURED]` flag is set.
grep 'dport=0.*\[ASSURED\]' /proc/net/nf_conntrack

# Permanent expectations under those anchors = current pool entries.
# Each line is one anycast door learned for one session.
cat /proc/net/nf_conntrack_expect

# Children — real WG flows linked to an anchor via expectation match.
# These are the actual UDP flows; one per (session, anycast door).
grep -F 'EXPECTED' /proc/net/nf_conntrack | grep "dport=$listenPort"

# The no-op helper bookkeeping.
cat /proc/net/nf_conntrack_helpers | grep WGANYCAST
```

Reading the `dst=<idx_as_ip>` field: convert four octets back to a
32-bit value to get the session index.  Useful for correlating with
`wg show <iface> peers` output (the `latest-handshake` peer also
exposes its session index via `wg show <iface> all` on newer
`wireguard-tools`).

If the SPRAY pool stays empty after multiple peer connections,
check:

1. **LEARN rule is in `raw` PREROUTING and BEFORE conntrack** —
   priority must be ≤ −300.  Verify with
   `iptables -t raw -L PREROUTING -n -v --line-numbers`.
2. **WG packets actually arrive** — `tcpdump -i <wan> udp port <listenPort>`
   on the host should show inbound RESP/DATA from anycast doors.
3. **No iptables `-j DROP` upstream of the LEARN rule** — even
   stoppage in `mangle` PREROUTING is too late if it precedes the
   `raw` table's `-j DROP`, but `raw` itself is first.
4. **Anchor exists but expectations don't refresh** — check that
   `nf_conntrack_acct` is enabled (`sysctl net.netfilter.nf_conntrack_acct`)
   and that no `-j NOTRACK` rule is shadowing the WG flow.

### Notes

- **Synthetic-tuple collision-free**: anchor tuples have
  `dst.port = 0` (RFC-reserved, no real UDP flow uses it), so the
  hashtable lookup by anchor tuple is guaranteed not to match real
  packets.  Anchors appear in `/proc/net/nf_conntrack` with
  `src=Sa.ip dst=<idx_as_ip> sport=Sa.port dport=0 [ASSURED]` — odd
  shape but functionally inert.
- **Anti-poisoning**: LEARN only processes packets passing WG type
  byte + size validation.  Attacker would need to forge the
  receiver-side `our_idx` (32-bit value chosen by WG kernel at
  handshake) AND match an in-pool slot — bounded by the 8-entry LRU
  cap, legitimate anycast IPs displace attackers on next genuine
  inbound.
- **`iptables -j DNAT --random` is not equivalent**: `-j DNAT` runs
  in `nat` and registers the mapping in conntrack, so every packet
  of the same 5-tuple inherits the *first* random pick.  WGANYCAST
  picks per-packet, with per-session pool isolation.
- **Pre-v3 `--dest` / `--canonical` are gone**.  The static pool
  enumeration and source-canonicalisation are replaced by dynamic
  learning + the synthetic-tuple-anchor mechanism.
- **IPv4 only.**  Same constraint as WGPTCP; IPv6 support would
  need parallel paths in the anchor / expectation tuple builders.


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
