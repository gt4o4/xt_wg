# Iptables WireGuard helpers

Two related xtables targets in one kernel module package, both useful for
running WireGuard across hostile or asymmetric networks:

- **`WGOBFS`** — obfuscates the WG packet payload so DPI can't fingerprint
  it (described in [§ WGOBFS](#wgobfs) below). Cross-platform clients can
  use [rs-wgobfs](https://github.com/infinet/rs-wgobfs) to talk to a
  WGOBFS-protected server.
- **`WGANYCAST`** — stateless per-packet UDP destination spray, plus
  matching source canonicalisation for the reply path. Lets a single WG
  flow ride two or more anycast destinations without involving conntrack
  / DNAT (described in [§ WGANYCAST](#wganycast) below).

Both targets ship in the same `xt_*.ko` kernel module set and share the
build system (`autotools` + the `src/Makefile.libxt.in` userspace plugin
template).


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

- `src/xt_WGOBFS.ko` and `src/xt_WGANYCAST.ko` (kernel modules)
- `src/libxt_WGOBFS.so` and `src/libxt_WGANYCAST.so` (userspace iptables plugins)

### Install

```shell
sudo make install
```

Then `sudo depmod -a && sudo modprobe xt_WGOBFS xt_WGANYCAST` to load the
modules. Add to `/etc/modules-load.d/` (or distro equivalent) for
boot-time loading.

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


## License

GPL v2
