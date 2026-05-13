/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Author: Bingchen Gong <gongbingchen@gmail.com>
 *
 * xt_WGANYCAST v9 — shared header (kernel + userspace)
 *
 * Single argument-less iptables target.  Install at `raw` OUTPUT —
 * SPRAY direction; rewrites the outbound WG packet's `iph->daddr`
 * (and `udph->dest`) to a random entry from a per-session pool
 * learned from observed inbound traffic.
 *
 *   iptables -t raw -A OUTPUT -p udp --sport 51821 -j WGANYCAST
 *
 * The inbound LEARN side is *no longer* an iptables target — it's
 * done implicitly via a `nf_conntrack_helper` (also named
 * "WGANYCAST") whose `.help` callback runs at conntrack-helper
 * priority +300 for every WG ct.  Attach the helper to inbound WG
 * cts via the standard `CT` target:
 *
 *   iptables -t raw -A PREROUTING -p udp --dport 51821 \
 *            -j CT --helper WGANYCAST
 *
 * Pool storage (unchanged from v3.2) is a 4-entry array inlined
 * into the helper extension's 32-byte `data[]` area on the per-
 * session **master** real WG-flow conntrack.  Each session has one
 * master (the first ct that processes a WG RESP) plus two
 * "synthetic marker" expectations under it:
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

/* Sentinel protonum for the synthetic marker expectations.  Real
 * WG flows are always IPPROTO_UDP (17).  Per
 * `__nf_ct_tuple_dst_cmp`, protonum is exact-compared with no mask
 * — so picking any value ≠ 17 guarantees zero false-match against
 * real traffic.  253 is the RFC 3692 "experimental/testing" value;
 * never appears in routine netfilter-processed traffic.
 */
#define WGA_MARKER_PROTO	253u

#endif
