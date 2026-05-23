# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Build & install

Autotools + a kernel `Kbuild` invoked from a generated Automake stub.

```shell
./autogen.sh         # autoreconf -fi
./configure          # auto-detects /lib/modules/$(uname -r)/build and xtlibdir from pkg-config
make                 # builds src/xt_wg.ko + src/libxt_WG{OBFS,ANYCAST,PTCP}.so
sudo make install    # installs module under /lib/modules/.../updates + plugins to xtlibdir
sudo depmod -a && sudo modprobe xt_wg
```

`./configure --without-kbuild` builds userspace plugins only (no kernel module). `./configure --with-kbuild=PATH` for cross-compile / out-of-tree kernels.

DKMS path: `make tarball && sudo make dkms-install`. Note `dkms.conf` still uses the legacy `PACKAGE_NAME=xt_wgobfs` (matches `configure.ac`'s `AC_INIT([xt_wgobfs], …)` and the autotools tarball name) while `BUILT_MODULE_NAME` is the current `xt_wg`. The Debian `-dkms` binary uses an independent `debian/xt-wg-dkms.dkms` with `PACKAGE_NAME="xt-wg"`, so the two registrations don't collide.

Debian / Ubuntu `.deb`: `dpkg-buildpackage -us -uc -b` from the repo root produces three binaries:

- `xt-wg-common` — userspace plugins (`libxt_WG{OBFS,ANYCAST,PTCP}.so`).
- `xt-wg-source` — m-a tarball; user runs `m-a a-i xt-wg`.
- `xt-wg-dkms` — DKMS-managed kernel module (auto-rebuilds for each installed kernel).

Build deps: `autoconf automake libtool libxtables-dev pkgconf debhelper-compat (=13) dh-sequence-dkms`. The outer `debian/rules` works around two upstream Makefile bugs that bite when `dh_auto_clean` runs after a `--without-kbuild` configure: `src/Makefile.libxt:install` lacks `install -d`, and `src/Makefile.am clean-local` invokes a kbuild clean unconditionally. Fix or replicate those workarounds if you rewrite the rules. See `debian/README.Debian` for the relationship between the three binaries.

OpenWrt: see `openwrt/package/Makefile` (a separate buildroot recipe, not invoked by the top-level build).

No test suite in-tree. Validation is by loading the module and inspecting `/proc/net/wganycast_stats` + `conntrack -L -o extended`.

## Architecture

**Single consolidated kernel module.** Despite three iptables targets (`WGOBFS`, `WGANYCAST`, `WGPTCP`), everything ships in one `xt_wg.ko`. Backward-compat `MODULE_ALIAS("xt_WGOBFS")` etc. in `xt_wg_main.c:96-102` keep `modprobe xt_WGOBFS` and old `/etc/modules-load.d/` working via kernel modalias lookup.

**Module layout** (`src/Kbuild`): `xt_wg-y = xt_wg_main.o xt_WGOBFS_main.o xt_WGANYCAST_main.o xt_WGPTCP_main.o chacha.o`.

- `xt_wg_main.c` — `module_init`/`module_exit` glue. Registers all three target arrays via `xt_register_targets` in dependency order (WGANYCAST needs its conntrack helper registered first). Force-enables `nf_conntrack_acct` per-netns at init for WGPTCP.
- `xt_wg_common.h` — shared declarations exposing each target's `xt_target[]` array (non-static so the central init can reach them) and shared WG-header constants (`WG_TYPE_*`, `WG_OFF_*_IDX_*`). Also exposes `wg_obfs_payload` / `wg_unobfs_payload` so WGPTCP's `--obfs` mode can reuse WGOBFS payload mangling.
- `wg.h` — WG protocol structs (handshake init/response/cookie). Includes pre-4.13 RNG-init shims; do not touch the kernel-version `#if` ladder without testing.
- `chacha.{c,h}` — chacha20 used by WGOBFS for keyed payload mangling.
- `src/libxt_*.c` — three userspace iptables plugins built via `Makefile.libxt.in` (not Kbuild). Each emits a `.so` loaded by `iptables`.

**Kernel compat.** `<linux/unaligned.h>` on ≥6.12; `<asm/unaligned.h>` before. The `LINUX_VERSION_CODE` guard is in `xt_WGANYCAST_main.c:76-80`. Mirror this pattern when adding new code that uses `get_unaligned_*`.

### WGANYCAST is the architecturally complex one

Per-WG-session anycast pool learning via the kernel's conntrack-helper + expectation machinery — **no module-private hashtable, no manual `nf_conntrack_alloc`**.

- The `WGANYCAST` *helper* (registered by `xt_wganycast_module_init`) is attached to WG cts via `iptables -t raw -j CT --helper WGANYCAST` rules in **both** PREROUTING and OUTPUT. Helper attaches at ct creation via template copy, so the direction that creates the ct must match.
- Helper's `.help` callback (`wga_help`) promotes the WG flow's ct to "master" on RESP and registers two `nf_conntrack_expect` markers under it — keyed by WG `our_idx` and `peer_idx` in `dst.u3.ip` (NOT `src.u3.ip` — see the long comment block; the kernel hashes expectations on `dst.u3` so per-session idx must live there for hashtable spread).
- Markers use `dst.protonum = WGA_MARKER_PROTO (253)` so they never match real packets (WG is UDP=17, exact-compared).
- Per-master pool is **inline in the helper extension's 32-byte `data[]` area** (`struct wga_pool_entry` × 4 = 32 B). LRU via 16-bit `last_seen_q8 = jiffies >> 3` with wrap-aware compare. Serialised by `master->lock` (the spinlock already in `nf_conn`).
- Master ct TTL is bounded by `IPS_FIXED_TIMEOUT_BIT + 200 s`, REFRESHED on every promotion and every inbound DATA. v9 used `test_and_set_bit` which only set TTL on the first promotion — the ct died on re-key. Current code uses `set_bit` + unconditional `WRITE_ONCE(ct->timeout, ...)`. Do not regress to `test_and_set_bit`.
- The `WGANYCAST` *target* (SPRAY side) lives in `raw` OUTPUT at priority −300, looks up the master via the marker expectation, picks a pool entry, rewrites `iph->daddr` + `udph->dest` with incremental checksum updates.
- v10 adds optional `--init-pool` for cold-start before any master exists.
- v10.1 adds per-door GC keyed by per-door ct's `IPS_SEEN_REPLY_BIT`.
- Observability: `/proc/net/wganycast_stats` (created in `xt_WGANYCAST_main.c:1331`). Health signature is documented in `README.md`.
- ABI: target revision is **1** with `struct xt_wganycast_info` (36 bytes). Bumping the struct requires bumping the revision and updating `libxt_WGANYCAST.c` together — kernel and userspace plugin must always upgrade in lockstep.
- IPv4 only. IPv6 would need parallel marker-tuple builders.

### WGPTCP — hook priority is load-bearing

The **decoder MUST run in `raw` PREROUTING (priority −300)**, before conntrack (−200). If the decoder runs after conntrack, conntrack creates a TCP-flow entry and the kernel RSTs the SYN. Documented in `xt_WGPTCP.h:21-23` and `README.md`. No companion `-j DROP` is needed because the rewrite predates conntrack.

State is read from **`nf_conn_acct`** (per-direction byte+packet counters) — the encoder writes nothing to the conntrack entry. No `ct->mark`, no `ct->labels`. Hosts can use `-j CONNMARK` etc. independently. The only kernel-side claim is `net.netfilter.nf_conntrack_acct=1`, force-enabled by `xt_wg_main.c:42-45`.

Seq/ack_seq are derived from `siphash24(--key, iph->saddr, "out ")` plus the per-direction cumulative byte counter from `nf_conn_acct` (minus `packets × 28` to strip IP+UDP overhead). The `28` is load-bearing — it makes the cumulative count WG-payload-only, matching the scale the seq math expects.

Wire shape is **conntrack-state-driven**, not WG-type-driven (see the 4-row table in `README.md`). The `own_packets > 1 + WG INIT + !SEEN_REPLY` row is the stuck-flow recovery path — fires only on the originator side because on the responder `IPS_SEEN_REPLY` flips immediately.

TFO cookie is derived from `tcph->seq` (not IP addresses) so it's NAT-immune — survives Cloudflare Spectrum DNAT, 1:1 NAT, provider SNAT pools.

IPv4 only.

### WGOBFS

Simpler: chacha6-keyed payload mangling of the WG message head + random padding. Symmetric `--obfs` / `--unobfs`. The kernel implementation is in `xt_WGOBFS_main.c`; the helpers `wg_obfs_payload` / `wg_unobfs_payload` are exported so WGPTCP `--obfs` mode can reuse them.

IPv4 + IPv6 (only target with v6 support).

## Coding conventions in this repo

- Kernel C, GPL v2 (SPDX header on every file). Match the existing kernel style (tabs, `pr_warn_ratelimited`, `READ_ONCE`/`WRITE_ONCE` for cross-CPU shared data).
- Long architectural comment blocks at the top of each `xt_WG*_main.c` document load-bearing design decisions and prior bugs. Read them before changing the file — they are the design doc.
- Stats are `atomic_t` counters surfaced via `/proc/net/<name>_stats`. Add new counters in the same pattern when introducing new code paths worth observing.
- Userspace plugins are minimal — argument parsing, validation, `save`/`print`. Keep them in sync with the kernel struct in `xt_WGxxx.h` and bump the xtables target revision together when changing the on-wire ABI.
