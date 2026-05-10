# Iptables WireGuard helpers

Three related xtables targets in one kernel module package, useful for
running WireGuard across hostile or asymmetric networks:

- **`WGOBFS`** — obfuscates the WG packet payload so DPI can't fingerprint
  it (described in [§ WGOBFS](#wgobfs) below). Cross-platform clients can
  use [rs-wgobfs](https://github.com/infinet/rs-wgobfs) to talk to a
  WGOBFS-protected server.
- **`WGANYCAST`** — stateless per-packet UDP destination spray, plus
  matching source canonicalisation for the reply path. Lets a single WG
  flow ride two or more anycast destinations without involving conntrack
  / DNAT (described in [§ WGANYCAST](#wganycast) below).
- **`WGPTCP`** — stateless WG-protocol-aware UDP↔fake-TCP transmutation:
  reads the WG message-type byte and dispatches each packet to the
  matching TCP shape (handshake initiation → SYN+TFO, response/cookie
  → SYN+ACK+TFO, transport data → PSH+ACK). Reproduces a textbook TCP
  3-way handshake on the wire so stateful firewalls / NAT helpers
  register a clean ESTABLISHED transition. Useful when middleboxes
  block or rate-limit UDP. Per-packet overhead +20 B for handshake
  packets, +12 B for transport. Decoder runs in `raw` PREROUTING so
  the kernel TCP stack never sees the fake-TCP packets — no companion
  `-j DROP` rule is needed. Described in [§ WGPTCP](#wgptcp) below.

All three targets ship in **one consolidated** `xt_wg.ko` kernel module
(plus three userspace plugins, one per target). Backward-compat aliases
mean `modprobe xt_WGOBFS` / `xt_WGANYCAST` / `xt_WGPTCP` all still
resolve to `xt_wg.ko` via the kernel's modalias lookup, so existing
`/etc/modules-load.d/` entries and iptables auto-load (which uses
`request_module("ipt_<NAME>")`) keep working unchanged. The shared `.ko`
also lets WGPTCP reuse WGOBFS's chacha-keyed payload mangling via the
`--obfs` flag (see [§ WGPTCP](#wgptcp)) without duplicating code.

The build system is `autotools` + the `src/Makefile.libxt.in` userspace
plugin template.


## Build & install (both targets)

### Build dependencies

- Alpine: `alpine-sdk iptables-dev linux-lts-dev` or `linux-virt-dev`
- CentOS 7: `iptables-devel kernel-devel`
- Debian 10 to 13: `autoconf libtool libxtables-dev linux-headers pkg-config`
- openSUSE 15: `autoconf automake gcc kernel-default-devel libtool libxtables-devel make`

### Build

```shell
./autogen.sh
./configure
make
```

Produces:

- `src/xt_wg.ko` — single kernel module, registers all three targets
  (WGOBFS, WGANYCAST, WGPTCP) from one `module_init`. Backward-compat
  via per-target `MODULE_ALIAS` (`xt_WGOBFS`, `ipt_WGOBFS`,
  `ip6t_WGOBFS`, `xt_WGANYCAST`, `ipt_WGANYCAST`, `xt_WGPTCP`,
  `ipt_WGPTCP`).
- `src/libxt_WGOBFS.so`, `src/libxt_WGANYCAST.so`, `src/libxt_WGPTCP.so`
  — three separate userspace iptables plugins, one per target name.

### Install

```shell
sudo make install
```

Then `sudo depmod -a && sudo modprobe xt_wg` to load all three targets.
(`modprobe xt_WGOBFS` / `xt_WGANYCAST` / `xt_WGPTCP` all also work via
the per-target aliases.) Add to `/etc/modules-load.d/` (or distro
equivalent) for boot-time loading.

By default, openSUSE does not allow unsupported kernel modules. To
override, create or modify `/etc/modprobe.d/10-unsupported-modules.conf`
and add:

```
allow_unsupported_modules 1
```

### DKMS

To use DKMS, first generate a source tarball, then install it as
superuser:

```shell
./autogen.sh
./configure
make tarball
sudo make dkms-install
```

Tested working on Alpine linux kernel 5.15, CentOS 7, Debian 10 to 13
and openSUSE 15.5.


## WGOBFS

### How it works

The sender and receiver share a secret key, which is used by `chacha6` to hash
the same input into identical pseudo-random numbers. These pseudo-random
numbers are used in obfuscation.

- The first 16 bytes of WG message is obfuscated.
- The mac2 field is also obfuscated, if it is all zeros.
- Padding WG message with random long random bytes.
- Drop keepalive message with 80% probability.
- Change the Diffserv field to zero.

`Chacha6` is chosen for its speed, as the goal is not encryption.


### Usage

This extension takes two parameters.

`--key` for a shared secret between client and server. If a key is a long
string, it will be cut at 32 characters; if a key is short, then it will be
repeated until reaches 32 characters. This 32 characters long string is the key
used by `chacha6` hash.

`--obfs` or `--unobfs` to indicate the operation mode.

**Before** bring up wg, on client, insert two iptables rules:

```shell
iptables -t mangle -I INPUT -p udp -m udp --sport 6789 -j WGOBFS --key mysecretkey --unobfs
iptables -t mangle -I OUTPUT -p udp -m udp --dport 6789 -j WGOBFS --key mysecretkey --obfs
```

The above rules assuming remote server is listening on port 6789. On server, do
the opposite:

```shell
iptables -t mangle -I INPUT -p udp -m udp --dport 6789 -j WGOBFS --key mysecretkey --unobfs
iptables -t mangle -I OUTPUT -p udp -m udp --sport 6789 -j WGOBFS --key mysecretkey --obfs
```

### As a relay

Since this is a Linux kernel module, users on Windows, Mac, or mobile devices
will not be able to use it directly. However, a possible workaround is to use it
through a relay.

For setting it up on a relay server (assuming default policy for FORWARD chain is
ACCEPT):


```shell
iptables -t nat -A PREROUTING -p udp -d RELAY_WAN_IP --dport 6789 -j DNAT --to-destination real_wg_server_ip:6789
iptables -t nat -A POSTROUTING -p udp -d real_wg_server_ip --dport 6789 -j MASQUERADE

iptables -t mangle -A FORWARD -p udp -d real_wg_server_ip --dport 6789 -j WGOBFS --key mysecretkey --obfs
iptables -t mangle -A FORWARD -p udp -s real_wg_server_ip --sport 6789 -j WGOBFS --key mysecretkey --unobfs

```

Windows, Mac or mobile clients then use the IP and port of the relay as WG
server endpoint. The setup for the remote WG server is the same as in previous
section.


### IPv6

For IPv6, replace `iptables` with `ip6tables` in rules. It is also necessary to
reduce the MTU of wireguard interface, for example, set the MTU to 1280.


### TCP MSS fix

It is necessary to clamp TCP MSS on TCP traffic over tunnel. Symptoms of TCP
MSS problems including HTTP not working on some websites, ssh works but scp
doesn’t work.

```shell
iptables -t mangle -A FORWARD -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu
```


### Performance

Test in two Alpine linux VMs on same host. Each VM has 1 CPU and 256M RAM.
Iperf3 over wg reports 1.1Gbits/sec without obfuscation, 950Mbits/sec with
obfuscation.


### OpenWrt

See [openwrt/package/README.md](/openwrt/package/README.md)


## WGANYCAST

Stateless per-packet UDP destination/source rewriter — fans a single
application's UDP flow across multiple anycast endpoints without conntrack
or DNAT involvement. Originally written for spraying a WireGuard tunnel
across two anycast IPs that both DNAT to the same backend (single WG
peer, two paths), but applicable to any UDP service.

### Two modes

- **`SPRAY`** (`--dest`) — for each outbound packet matched by the rule,
  picks one entry uniformly at random from the destination pool and
  rewrites the packet's destination IP (and optionally port). Use in
  `OUTPUT` or `POSTROUTING` `mangle`.
- **`CANONICAL`** (`--canonical`) — rewrites an inbound packet's source
  IP (and optionally port) to a single canonical address. Use in
  `PREROUTING` `mangle` to make replies from any pool member look like
  they came from one peer endpoint, so WireGuard's roaming stays pinned.

The two flags are mutually exclusive in a single rule. A typical
WireGuard deployment installs one `SPRAY` rule on `OUTPUT` plus one
`CANONICAL` rule per pool member on `PREROUTING`.

### Address syntax

Each `--dest` and `--canonical` argument is `IP` or `IP:PORT`:

- Bare `IP` — preserves the packet's existing UDP destination/source port.
- `IP:PORT` — rewrites the port too (with incremental UDP-checksum
  update). Useful when the gateway DNAT also translates port (e.g.
  Cloudflare Spectrum-style mappings).

Up to 8 destinations per `--dest` rule.

### Stateless on purpose

WGANYCAST does not interact with conntrack. It modifies the packet at
`mangle` priority and returns `XT_CONTINUE`. Conntrack runs after
(`OUTPUT`) or before (`PREROUTING`) mangle and tracks the modified
tuple, but no NAT mapping is registered — so each packet's destination
is decided fresh by the random pick, no per-flow stickiness. (If you
want per-flow stickiness, use a hash-based `iptables -j DNAT` instead.)

### Example: WireGuard over two Cloudflare Spectrum anycasts

Gateway maps both anycast IPs' UDP/59263 → backend's WG :51821:

```shell
# Egress: spray each WG packet to one of two anycast IPs (port :59263)
iptables -t mangle -A OUTPUT -p udp -d 193.134.211.67 --dport 51821 \
  -j WGANYCAST \
  --dest 161.248.136.186:59263 \
  --dest 138.252.162.176:59263

# Ingress: canonicalise replies from either anycast back to the original
# peer:port so WireGuard sees one stable endpoint
iptables -t mangle -A PREROUTING -p udp -s 161.248.136.186 --sport 59263 \
  -j WGANYCAST --canonical 193.134.211.67:51821
iptables -t mangle -A PREROUTING -p udp -s 138.252.162.176 --sport 59263 \
  -j WGANYCAST --canonical 193.134.211.67:51821
```

If the gateway DNAT preserves port (no translation), drop `:59263` from
all entries:

```shell
iptables -t mangle -A OUTPUT -p udp -d 193.134.211.67 --dport 51821 \
  -j WGANYCAST --dest 161.248.136.186 --dest 138.252.162.176
iptables -t mangle -A PREROUTING -p udp -s 161.248.136.186 --sport 51821 \
  -j WGANYCAST --canonical 193.134.211.67
iptables -t mangle -A PREROUTING -p udp -s 138.252.162.176 --sport 51821 \
  -j WGANYCAST --canonical 193.134.211.67
```

### Operational notes

- **Co-existing with conntrack-DNAT for the same flow**: the two are
  mutually exclusive — if a `nat` table DNAT rule for the same `(dest,
  port)` is already in place, conntrack registers the flow's
  destination from the first packet and subsequent packets inherit
  that mapping (overriding `WGANYCAST`'s rewrite). Drop the
  conntrack-DNAT entry for the WG flow before adding the `WGANYCAST`
  rules, and flush the stale conntrack entry (`conntrack -D -p udp
  --dport <wg-port> --orig-dst <peer-ip>`) so the next packet hits
  fresh.
- **Stale conntrack on first install**: even after removing the DNAT,
  any existing conntrack entry for `(local-ip:wg-port, peer-ip:wg-port)`
  with NAT translation persists until it ages out (~120 s) or is
  explicitly deleted. Flush it on first deploy or WG breaks until
  timeout.
- **Module loading**: `xt_WGANYCAST.ko` is built but not autoloaded. Add
  `xt_WGANYCAST` to `/etc/modules-load.d/` (or NixOS
  `boot.kernelModules`) for boot-time load.
- **CAP_NET_ADMIN required** to install `mangle` rules; same as any
  other iptables manipulation.

### Why not just use `iptables -j DNAT --random`?

`-j DNAT` runs in the `nat` table and registers the mapping in
conntrack — every packet of the same 5-tuple inherits the *first*
random pick. WGANYCAST runs in `mangle` and is stateless: every packet
is an independent random draw, so a single WG flow really fans out
per-packet.


## WGPTCP

WG-protocol-aware stateless UDP↔fake-TCP transmutation. Useful when
the network between you and the WG peer drops or rate-limits UDP, but
lets TCP through. Unlike [udp2raw](https://github.com/wangyu-/udp2raw),
there is no userspace daemon, no handshake state machine, no per-flow
table — every packet is independently rewritten in the netfilter hook,
with TCP fields derived statelessly from the WG message contents and
a shared `--key`.

### How it works

The encoder reads the WG message-type byte at the start of the UDP
payload and dispatches each WG message type to a different TCP shape
so the wire reproduces a textbook 3-way handshake + ESTABLISHED data
exchange:

| WG type | Size | TCP flags | TCP doff | Net growth |
|---|---:|---|---:|---:|
| 1 (initiation) | 148 B | `SYN`     | 7 (with TFO opt) | +20 B |
| 2 (response)   |  92 B | `SYN+ACK` | 7 (with TFO opt) | +20 B |
| 3 (cookie)     |  64 B | `SYN+ACK` | 7 (with TFO opt) | +20 B |
| 4 (transport)  |   ≥16 B | `PSH+ACK` | 5 (no opts) | +12 B |

`seq` / `ack_seq` are derived from the `sender_index` /
`receiver_index` fields in the WG payload via SipHash-2-4 with a
fixed 4-byte role tag — both ends compute the same values
independently:

```
SYN.seq         = H(K, init.sender_index,   "init")
SYN+ACK.seq     = H(K, resp.sender_index,   "resp")
SYN+ACK.ack_seq = H(K, init.sender_index,   "init") + 1 + 148
                                                      ^^^^^^
                       (SYN consumes 1) + (TFO data carried in SYN)

cookie.seq      = H(K, recv_idx,            "cook")
cookie.ack_seq  = H(K, recv_idx,            "init") + 1 + 148

PSH+ACK.seq     = H(K, recv_idx,            "tx  ") + counter_lo32
PSH+ACK.ack_seq = H(K, recv_idx,            "rx  ")
```

The SYN+ACK's `ack_seq` matches the SYN's `seq + 1 + 148` exactly,
so stateful firewalls observe a valid handshake and register the
flow as ESTABLISHED before the first PSH+ACK arrives.

**Encode steps** (per packet):

- Read first byte of UDP payload → WG type. Reject non-WG (`XT_CONTINUE`).
- Read `sender_index` / `receiver_index` from the matching WG struct
  in `wg.h`.
- Compute seq / ack_seq via the table above (or `random()` in unkeyed
  mode using a fixed default key for determinism).
- Strip the 8-byte UDP header, push the appropriate TCP header (20 or
  28 bytes), copy the original payload as TCP data.
- For SYN-bearing packets: append `NOP NOP TFO_COOKIE(kind=34, len=6,
  4-byte cookie)`. The 4-byte cookie is the marker used by the
  decoder: either a fixed sentinel `0xC07F0001` (default, no `--key`),
  or `siphash24(key, tcph->seq ‖ "ckie")[0..4)` (when `--key` is
  given). Hashing `tcph->seq` rather than the iph addresses makes
  the cookie **NAT-immune**: TCP sequence numbers are not rewritten
  by any conventional NAT (1:1 NAT, Cloudflare Spectrum DNAT,
  provider SNAT pools, etc. all preserve `seq`), so encoder and
  decoder agree on the marker even across NAT'd paths. The seq
  itself encodes a SipHash of the WG `sender_index` /
  `receiver_index` (which lives in the encrypted WG payload) — so
  the entire chain stays inside the WG message and never touches
  IP-layer fields that NAT might mangle.
- Rewrite IP `protocol` from 17 (UDP) to 6 (TCP). Full IP + TCP
  checksum recompute (not incremental, since L4 protocol shape
  changed).

**Decode steps:**

- Match `iph->protocol == TCP`, dispatch on TCP flags:
  - `SYN` (any ACK): require TFO cookie option matching the configured
    marker. If absent or mismatched: `XT_CONTINUE` (lets kernel TCP
    stack RST real probes).
  - `PSH+ACK` / bare `ACK`: no TFO cookie expected; rely on rule-level
    peer-IP/port filtering as the marker.
  - `RST` / `FIN` / other: `XT_CONTINUE` (leave for kernel TCP stack).
- For matched packets: read the TCP header length from `tcph->doff`,
  strip the TCP header, write a fresh UDP header (sport/dport copied
  from TCP), shrink the skb by `tcp_hdr_len - 8`, rewrite `iph->protocol
  = UDP`, recompute checksums.

### Hook placement — load-bearing detail

The decoder MUST be installed in **`raw` PREROUTING**, not `mangle`.
Linux netfilter hook priorities at PREROUTING are:

| Priority | Hook |
|---|---|
| `NF_IP_PRI_RAW = -300` | `raw` table |
| `NF_IP_PRI_CONNTRACK = -200` | conntrack |
| `NF_IP_PRI_MANGLE = -150` | `mangle` table |

If the decoder runs in `mangle` (-150), conntrack (-200) has already
created a TCP-flow entry; the kernel TCP stack would emit RST for a
SYN to a non-listening port. By running in `raw` (-300), the rewrite
predates conntrack — the packet becomes UDP, conntrack creates a UDP
entry, the kernel TCP stack never sees a TCP packet. **No companion
`iptables -t raw -j DROP` rule is needed** (this is what udp2raw's
userspace model has to install because its raw socket sees packets
after the kernel might already RST).

### Usage

This extension takes three parameters.

`--encode` or `--decode` to indicate the operation mode.

`--key <32 hex chars>` (optional) — 16 raw bytes of secret key used to
derive the per-direction TFO cookie via SipHash-2-4 over (source IP ‖
dest IP). Both ends must agree. When omitted, a fixed sentinel cookie
is used; this works but is more easily mis-classified if a real TFO
client happens to connect to the same port.

`--obfs` (optional) — also apply WGOBFS-style payload obfuscation to
the WG message inside the fake-TCP segment: chacha-XOR the first 16
bytes, append random padding (length encoded in the last byte), drop
~80 % of WG keepalives, and zero-restore the mac2 field on handshake
messages. Useful when a deep-DPI middlebox unwraps the TCP and
inspects the inner bytes — the WG message signature would otherwise
leak through. Requires `--key`; the chacha key is derived as
`key || key` (32 bytes from the 16-byte siphash key). Per-packet wire
growth becomes +24..+52 B for handshake, +16..+44 B for transport
(the random padding length varies). Both ends must agree.

On the **client** (encoder side):

```shell
# Encode outbound: WG datagrams to peer:port → fake TCP (shape chosen
# by the kernel module from the WG message-type byte)
iptables -t mangle -A OUTPUT -p udp -d <peer> --dport 51821 \
  -j WGPTCP --encode --key 0123456789abcdef0123456789abcdef

# Decode inbound: any TCP from peer:port → UDP, BEFORE conntrack.
# No `--syn` filter: the encoder produces SYN, SYN+ACK, AND PSH+ACK
# packets. The decoder dispatches on TCP flags internally and validates
# a TFO cookie marker for SYN-set packets; PSH+ACK transport packets
# rely on the rule's peer IP/port filter as their marker.
iptables -t raw -A PREROUTING -p tcp -s <peer> --sport 51821 \
  -j WGPTCP --decode --key 0123456789abcdef0123456789abcdef

# With WGOBFS-style payload mangling (must add --obfs on BOTH ends):
iptables -t mangle -A OUTPUT -p udp -d <peer> --dport 51821 \
  -j WGPTCP --encode --key 0123456789abcdef0123456789abcdef --obfs
iptables -t raw -A PREROUTING -p tcp -s <peer> --sport 51821 \
  -j WGPTCP --decode --key 0123456789abcdef0123456789abcdef --obfs
```

On the **server** (decoder side, mirror image): swap source/dest and
sport/dport in the same two rules. WG is symmetric — either side may
send type-1 (initiation) for a fresh handshake — so install both
encode and decode on each side regardless of who initiates.

### MTU

Without `--obfs`: handshake packets grow by +20 B; transport packets
grow by +12 B. With `--obfs`: handshake +24..+52 B, transport
+16..+44 B (random padding component). Worst case is +52 B.
WireGuard's default MTU 1420 fits in a 1500-byte underlay even at
worst case (1420 + 52 = 1472 ≤ 1500). On tighter underlays (1280,
IPv6-only links, PPPoE), lower the WG MTU accordingly:
`MTU ≤ <underlay-mtu> - 80` (without `--obfs`) or
`MTU ≤ <underlay-mtu> - 112` (with `--obfs`).

### Operational notes

- **Decoy TCP listener**. A pure `xt_WGPTCP` setup is fingerprintable
  via active probes: a real TCP SYN sent to the fake-TCP port without
  our cookie marker fails the cookie check, so the decoder returns
  `XT_CONTINUE` and the kernel sends RST — distinguishable from a
  real, idle TCP service. To make the port look like a normal idle
  TCP service, also bind a tiny accept-and-close TCP listener on the
  same port (e.g. systemd-socket-activated `socat - SYSTEM:'true'`).
  Real fake-TCP packets still rewrite at `raw` PREROUTING before
  reaching the kernel TCP stack, so the listener never sees them.

- **No per-flow state**. Even though the wire shape reproduces a
  3-way handshake, there's no kernel-side flow tracking — every
  packet's TCP fields are derived purely from its own contents +
  the shared `--key`. This survives:
  - stateless firewalls and TCP-flag DPI;
  - **stateful firewalls with default-loose mode** (most common; e.g.
    Linux netfilter conntrack with `nf_conntrack_tcp_loose=1`, the
    default), which validate the SYN/SYN+ACK pairing and then accept
    PSH+ACK seq within a generous receive window.
  Won't survive **strict** stateful firewalls that demand monotonic
  per-byte seq advancement across the handshake→data boundary
  (rare in practice). For that, either upgrade to a userspace tool
  with full handshake state (udp2raw `--seq-mode 3`), or extend this
  module with a `nf_conntrack_extend` per-flow seq counter (see the
  parent repo's plan for sketching).

- **Co-existing with `WGANYCAST` / conntrack-DNAT**: same gotcha as
  WGANYCAST — if a `nat`-table DNAT rule for the same `(dest, port)`
  is in place, conntrack pins the rewrite from the first packet.
  Drop the conntrack-DNAT entry first if you want WGPTCP to apply.
  In a typical anycast setup the layering goes WGPTCP first
  (UDP→TCP), then WGANYCAST `--dest` (per-packet anycast spray),
  with the inverse on receive.

- **Module loading**: `xt_WGPTCP.ko` is built but not autoloaded.
  Add `xt_WGPTCP` to `/etc/modules-load.d/` (or NixOS
  `boot.kernelModules`) for boot-time load.

- **IPv4 only** in v1 (matching WGANYCAST). IPv6 is straightforward
  to add — same wire shape, different IP header struct + checksum
  helper (`csum_ipv6_magic`).


## License

GPL v2
