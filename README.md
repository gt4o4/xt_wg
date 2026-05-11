# Iptables WireGuard helpers

Three xtables targets in one kernel module, for running WireGuard
across hostile or asymmetric networks:

- **`WGOBFS`** — chacha-keyed payload obfuscation. DPI can't fingerprint
  the WG message shape. Cross-platform clients can use
  [rs-wgobfs](https://github.com/infinet/rs-wgobfs).
- **`WGANYCAST`** — stateless per-packet UDP destination spray plus
  matching source canonicalisation. Lets a single WG flow ride two or
  more anycast endpoints without conntrack/DNAT.
- **`WGPTCP`** — UDP↔fake-TCP transmutation with stateful flow tracking
  via `ct->mark`. Reproduces a textbook Linux TCP handshake +
  ESTABLISHED data stream so middleboxes that block or rate-limit UDP
  let the flow through. Re-handshakes ride as PSH+ACK on the same
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

Stateless per-packet UDP destination/source rewriter. Fans a single
UDP flow across multiple anycast endpoints without conntrack/DNAT.
Written for spraying WG across two anycast IPs that DNAT to the same
backend, but applies to any UDP service.

### Modes

- **`--dest IP[:PORT]`** (SPRAY) — for each outbound packet, picks one
  destination uniformly at random and rewrites destination IP/port.
  Use in `mangle` OUTPUT/POSTROUTING (priority -150, AFTER conntrack
  at -200 — conntrack records the canonical dst, one stable entry
  regardless of which pool member the spray picked). Up to 8
  destinations per rule.
- **`--canonical IP[:PORT]`** — rewrites an inbound packet's source
  IP/port to a single canonical address. Use in `raw` PREROUTING
  (priority -300, BEFORE conntrack at -200 — the inbound entry's
  reply tuple matches the OUTPUT entry, giving one symmetric
  conntrack entry per flow instead of two orphans). Makes replies
  from any pool member look like one peer endpoint, so WG roaming
  stays pinned.

Mutually exclusive in a single rule. Typical deployment: one SPRAY
on OUTPUT mangle plus one CANONICAL per pool member on raw PREROUTING.

### Example: WG over two Cloudflare Spectrum anycasts

Gateway maps both anycast IPs' UDP/59263 → backend's WG :51821:

```shell
# Egress: spray each WG packet
iptables -t mangle -A OUTPUT -p udp -d 193.134.211.67 --dport 51821 \
  -j WGANYCAST --dest 161.248.136.186:59263 --dest 138.252.162.176:59263

# Ingress: canonicalise both replies back to the original peer
iptables -t raw -A PREROUTING -p udp -s 161.248.136.186 --sport 59263 \
  -j WGANYCAST --canonical 193.134.211.67:51821
iptables -t raw -A PREROUTING -p udp -s 138.252.162.176 --sport 59263 \
  -j WGANYCAST --canonical 193.134.211.67:51821
```

If the gateway DNAT preserves port, omit `:59263` from all entries.

### Notes

- **Conflicts with conntrack-DNAT** for the same `(dest, port)` — the
  first packet's NAT mapping pins all subsequent ones. Drop the
  DNAT entry and flush stale conntrack
  (`conntrack -D -p udp --dport <wg-port> --orig-dst <peer>`)
  before adding WGANYCAST rules.
- **`iptables -j DNAT --random` is not equivalent**: `-j DNAT` runs
  in `nat` and registers the mapping in conntrack, so every packet
  of the same 5-tuple inherits the *first* random pick. WGANYCAST
  is per-packet stateless.


## WGPTCP

WG-aware UDP↔fake-TCP transmutation. Per-flow state lives in
`ct->mark` of the underlying UDP conntrack entry —
`nf_ct_is_confirmed(ct)` + `ct->mark` together drive shape selection
without any module-local table.

Wire-shape decision is **conntrack-state-driven** (not
WG-type-driven):

| State                                       | Shape     | Options                                              | Growth |
|---------------------------------------------|-----------|------------------------------------------------------|-------:|
| `ct->mark == 0` + `IP_CT_NEW`               | `SYN`     | MSS + SACK_Perm + TS + WSCALE=7 + TFO_Cookie (28 B)  | +40 B  |
| `ct->mark == 0` + `IP_CT_ESTABLISHED_REPLY` | `SYN+ACK` | same                                                 | +40 B  |
| `ct->mark >= 1`                             | `PSH+ACK` | TS only (12 B)                                       | +24 B  |

The TCP option set on `SYN`/`SYN+ACK` matches what stock Linux's
`tcp_select_initial_window` emits, so the initial fingerprint passes
`p0f`-style classifiers as "Linux".

Re-handshakes (WG `REJECT_AFTER_TIME = 180 s`, re-key every 120 s)
ride as PSH+ACK with cumulative seq on the SAME conntrack entry — the
middlebox sees one uninterrupted ESTABLISHED stream and never observes
a SYN→ESTABLISHED transition. This is the v2 fix for the v1.5 failure
mode (Cloudflare-Spectrum-style strict middleboxes dropping the
re-handshake's fresh SYN as out-of-window).

### Sequence derivation

`tcph->seq` and `tcph->ack_seq` are derived from `iph->{saddr,daddr}`
via SipHash-2-4 with `--key`, plus the cumulative byte counter in
`ct->mark`:

```
SYN.seq         = H(K, saddr, "out ")
SYN+ACK.seq     = H(K, saddr, "out ")
SYN+ACK.ack_seq = H(K, daddr, "ack ")
PSH+ACK.seq     = H(K, saddr, "out ") + 1 + 148 + ct->mark
PSH+ACK.ack_seq = H(K, daddr, "ack ")
```

After each PSH+ACK, the encoder writes back `ct->mark += payload_len`,
so subsequent packets carry monotonically advancing seq. The stationary
`ack_seq` looks like a perpetual "duplicate ACK" to loose conntrack
trackers, which accept it.

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

### State storage caveat

WGPTCP claims the full 32-bit `ct->mark` field for per-flow state. The
host must not use connmark for anything else (`-j CONNMARK`, `-m
mark`, fwmark-based routing) — those would collide. Switch to
`ct->labels` if connmark coexistence is ever required.

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
