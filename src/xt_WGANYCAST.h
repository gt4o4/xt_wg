/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Author: Bingchen Gong <gongbingchen@gmail.com>
 *
 * xt_WGANYCAST v10 — shared header (kernel + userspace)
 *
 * Single iptables target.  Install in `raw` OUTPUT to rewrite an
 * outbound WG packet's `iph->daddr` (and `udph->dest`) to a random
 * entry chosen as follows:
 *
 *   1. If a per-session master conntrack exists (the WG flow has
 *      already produced at least one RESP that promoted it), pick
 *      from master's inline 4-entry pool — populated dynamically
 *      from observed inbound traffic by the WGANYCAST conntrack
 *      helper (`wga_help`).  Steady-state behaviour, identical to
 *      v9.
 *
 *   2. If NO master ct exists yet (cold start) AND the rule
 *      carries a non-empty `--init-pool`, pick from the rule's
 *      static init pool.  This bootstraps initiator-side hosts
 *      (CN hubs) whose outbound WG packets would otherwise hit
 *      `spray_no_master` and dribble out to a GFW-blocked real IP.
 *
 *   3. Otherwise (no master, no init pool), continue unchanged —
 *      v9 behaviour preserved for receiver-side hosts whose pool
 *      naturally grows from inbound traffic.
 *
 *   iptables -t raw -A OUTPUT -d 193.134.211.67 -p udp --dport 51821 \
 *            -j WGANYCAST --init-pool 138.252.162.176:59263,161.248.136.186:59263
 *
 *   iptables -t raw -A OUTPUT -p udp --sport 51821 -j WGANYCAST
 *
 * Init-pool entries are ALSO seeded into master's inline pool on
 * every outbound packet after master is promoted, via the normal
 * `wga_learn_door` LRU path — idempotent, so calling it on every
 * packet is safe and self-converges.  Real observed doors evict
 * init entries over time (init entries' `last_seen_q8` only
 * advances on TX cadence ≈ 25 s WG keepalives; real entries
 * advance on inbound DATA cadence which is typically faster), so
 * the pool decays from "seeded" to "fully learned" naturally.
 *
 * The inbound LEARN side is *no longer* an iptables target — it's
 * done implicitly via a `nf_conntrack_helper` (also named
 * "WGANYCAST") whose `.help` callback runs at conntrack-helper
 * priority +300 for every WG ct.  Attach the helper via the
 * standard `CT` target:
 *
 *   iptables -t raw -A PREROUTING -p udp --dport 51821 \
 *            -j CT --helper WGANYCAST
 *   iptables -t raw -A OUTPUT     -p udp --dport 51821 \
 *            -j CT --helper WGANYCAST
 *
 * Pool storage (unchanged from v9) is a 4-entry array inlined
 * into the helper extension's 32-byte `data[]` area on the per-
 * session **master** real WG-flow conntrack.  Each session has one
 * master (the first ct that processes a WG RESP) plus two
 * synthetic-marker expectations under it:
 *
 *   - marker_1.dst.u3.ip = our_idx,  dst.protonum = WGA_MARKER_PROTO
 *   - marker_2.dst.u3.ip = peer_idx, dst.protonum = WGA_MARKER_PROTO
 *
 * (idx goes in `dst.u3.ip` rather than `src.u3.ip` because the
 *  kernel's expectation hashtable lookup keys on `dst.u3` + dst.port
 *  + dst.protonum + src.l3num.  Putting per-session idx in dst spreads
 *  markers across the 8192-bucket hashtable instead of piling every
 *  marker into one bucket.)
 *
 * Both markers are PERMANENT and serve only as a `our_idx → master`
 * resp. `peer_idx → master` index (looked up via
 * `__nf_ct_expect_find`).  The kernel never matches them against
 * real packets because `dst.protonum != IPPROTO_UDP` (real WG
 * always proto=UDP, exact-compared).  Markers and pool die with
 * master via `nf_ct_remove_expectations(master)` at the master's
 * 200-second `IPS_FIXED_TIMEOUT_BIT` expiry; next inbound packet
 * promotes a new master.
 *
 * No per-flow expectations.  No module-private hashtable.  No
 * synthetic `nf_conn` allocation.  Per-door cts are independent
 * regular conntracks; the marker mechanism is the only cross-ct
 * linkage.
 *
 * ABI (target revision 1):
 *   `struct xt_wganycast_info` is a fixed-size 36-byte payload
 *   (after XT_ALIGN).  v9 used `targetsize = 0` and revision 0;
 *   v10 bumps to revision 1 with the new payload.  Atomic switch
 *   — old userspace iptables binary cannot install v10 rules and
 *   vice versa, but each host upgrades the kernel module and the
 *   `libxt_WGANYCAST.so` plugin together via `nixos-rebuild
 *   switch`, so they always match.  Empty payload (`ninit == 0`)
 *   reproduces v9 behaviour for receiver-side hosts.
 */
#ifndef _XT_WGANYCAST_H
#define _XT_WGANYCAST_H

#include <linux/types.h>

/* Per-master pool capacity — bounded LRU.  Stored inline in the
 * helper extension's 32-byte `data[]` area: 4 × 8-byte entries.
 * CF Spectrum's per-(client, anycast_IP) NAT stability means 2-3
 * distinct doors per session is the realistic max; 4 is sufficient
 * headroom.
 */
#define XT_WGANYCAST_POOL_MAX	4u

/* Per-rule init-pool capacity — matches the inline pool slot count
 * so a full init pool can fully seed an empty master pool in one
 * pass.  Userspace `libxt_WGANYCAST.c` parses up to this many
 * `ip[:port]` tuples from `--init-pool` / `--init-dest` options.
 */
#define XT_WGANYCAST_INIT_MAX	4u

/* Sentinel protonum for the synthetic marker expectations.  Real
 * WG flows are always IPPROTO_UDP (17).  Per
 * `__nf_ct_tuple_dst_cmp`, protonum is exact-compared with no mask
 * — so picking any value ≠ 17 guarantees zero false-match against
 * real traffic.  253 is the RFC 3692 "experimental/testing" value;
 * never appears in routine netfilter-processed traffic.
 */
#define WGA_MARKER_PROTO	253u

/* One init-pool entry — 8 bytes packed (matches `wga_pool_entry`
 * layout in the kernel inline pool so the seed-loop can memcpy-
 * style stamp entries cheaply, though the kernel re-derives
 * `last_seen_q8` from jiffies rather than copying it).
 *
 * `port == 0` (network order) means "preserve the packet's
 * existing udph->dest" — used when the gateway DNATs both IP and
 * port and the canonical port == anycast port (rare; most fleet
 * mappings have a distinct edgePort).
 */
struct xt_wganycast_init_entry {
	__be32 ip;
	__be16 port;
	__u16  _pad;
};

/* Per-rule target payload.  Lives in iptables rule blob, copied
 * once at rule install time, read on every packet hit.  Size is
 * 4 + 4 × 8 = 36 bytes; XT_ALIGN may pad to 40 on some archs.
 */
struct xt_wganycast_info {
	__u8 ninit;            /* 0..XT_WGANYCAST_INIT_MAX */
	__u8 _pad[3];
	struct xt_wganycast_init_entry init[XT_WGANYCAST_INIT_MAX];
};

#endif
