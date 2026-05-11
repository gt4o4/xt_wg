/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Author: Bingchen Gong <gongbingchen@gmail.com>
 *
 * xt_WGANYCAST v3 — shared header (kernel + userspace)
 *
 * Two modes for WG-protocol-aware dynamic anycast learning:
 *
 *   LEARN — installed in `raw` PREROUTING (priority -300, before
 *           conntrack at -200).  Validates the WG message type byte
 *           and extracts session indices from the WG payload.  On
 *           type=2 RESP: allocates a per-session anchor conntrack
 *           (synthetic 5-tuple encoding (Sa, our_idx) in ORIGINAL,
 *           (Sa, peer_idx) in REPLY).  On every observed inbound,
 *           registers/refreshes a permanent expectation under the
 *           anchor for the packet's (anycast_src, anycast_sport)
 *           tuple.  Conntrack's expect-match path will link future
 *           anycast inbounds as children of the anchor.
 *
 *   SPRAY — installed in `raw` OUTPUT (priority -300, before
 *           conntrack at -200).  Validates the WG type byte and
 *           extracts the receiver_index from the WG payload.  Looks
 *           up the anchor via the REPLY direction (peer_idx).
 *           Iterates `nfct_help(anchor)->expectations`, picks one
 *           uniformly at random, rewrites the packet's
 *           `iph->daddr` (and `udph->dest` if the expectation's
 *           port differs).  Empty pool → XT_CONTINUE (packet goes
 *           to WG's configured peer.endpoint as-is).
 *
 * The pool storage is the conntrack hashtable itself: anchors are
 * regular `nf_conn` allocated via `nf_conntrack_alloc()` with
 * IPS_CONFIRMED_BIT + IPS_FIXED_TIMEOUT_BIT + a fixed 200-second
 * timeout (= WG REJECT_AFTER_TIME + 20 s buffer).  No separate
 * module-private hashtable, no module-managed GC, no per-packet
 * refresh.  Anchors self-reap via standard conntrack GC at the
 * end of each WG session lifetime.
 *
 * The targets take no arguments at the iptables-rule level.
 * Everything is derived from packet contents at handler time:
 *
 *   - Sa (local endpoint) = `iph->daddr`+`udph->dest` on ingress,
 *                           `iph->saddr`+`udph->source` on egress.
 *   - our_idx / peer_idx  = parsed from WG header per message type.
 *
 * Multi-peer-per-WG-interface is handled natively: distinct WG
 * sessions have distinct `our_idx` values, mapping to distinct
 * anchors keyed by `(Sa, our_idx)`.
 */
#ifndef _XT_WGANYCAST_H
#define _XT_WGANYCAST_H

#include <linux/types.h>

#define XT_WGANYCAST_MODE_LEARN	0
#define XT_WGANYCAST_MODE_SPRAY	1

/* Per-anchor pool capacity — bounded LRU.  Matches the pre-v3
 * static `--dest` enumeration limit for continuity.
 */
#define XT_WGANYCAST_POOL_MAX	8u

struct xt_wganycast_info {
	__u8 mode;	/* XT_WGANYCAST_MODE_* */
	__u8 _pad[3];
};

#endif
