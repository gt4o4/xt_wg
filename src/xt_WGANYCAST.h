/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Author: Bingchen Gong <gongbingchen@gmail.com>
 *
 * xt_WGANYCAST v3.2 — shared header (kernel + userspace)
 *
 * Two modes for WG-protocol-aware dynamic anycast learning:
 *
 *   LEARN — installed in `raw` PREROUTING (priority -300, before
 *           conntrack at -200).  Validates the WG message type byte
 *           and extracts session indices from the WG payload.  On
 *           type=2 RESP: allocates a per-session anchor conntrack
 *           (synthetic 5-tuple encoding (Sa, our_idx) in ORIGINAL,
 *           (Sa, peer_idx) in REPLY).  On every observed inbound,
 *           refreshes-or-inserts the packet's (anycast_src,
 *           anycast_sport) tuple in the anchor's inline pool array.
 *
 *   SPRAY — installed in `raw` OUTPUT (priority -300, before
 *           conntrack at -200).  Validates the WG type byte and
 *           extracts the receiver_index from the WG payload.  Looks
 *           up the anchor via the REPLY direction (peer_idx).
 *           Picks one pool entry uniformly at random and rewrites
 *           the packet's `iph->daddr` (and `udph->dest` if the
 *           entry's port differs).  Empty pool → XT_CONTINUE
 *           (packet goes to WG's configured peer.endpoint as-is).
 *
 * Pool storage: a 4-entry array inlined into the helper extension's
 * 32-byte private `data[]` area on each anchor `nf_conn`.  No
 * `nf_conntrack_expect` use — eliminates the global tuple-uniqueness
 * clash that bit v3.1 on every WG re-key.  Lives for the anchor's
 * 200-second timeout and is freed automatically when the anchor's
 * conntrack is destroyed.
 *
 * Anchors are regular `nf_conn` allocated via `nf_conntrack_alloc()`
 * with IPS_CONFIRMED_BIT + IPS_FIXED_TIMEOUT_BIT + a fixed 200-second
 * timeout (= WG REJECT_AFTER_TIME + 20 s buffer).  No module-private
 * hashtable, no module-managed GC, no per-packet refresh of timing.
 * Anchors self-reap via standard conntrack GC at the end of each WG
 * session lifetime.
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

/* Per-anchor pool capacity — bounded LRU.  v3.2 stores the pool
 * inline in the helper extension's 32-byte `data[]` area, which
 * caps us at 4 × 8-byte entries.  CF Spectrum's per-(client,
 * anycast_IP) NAT stability means 2-3 distinct doors per session
 * is the realistic max; 4 is sufficient headroom.
 */
#define XT_WGANYCAST_POOL_MAX	4u

struct xt_wganycast_info {
	__u8 mode;	/* XT_WGANYCAST_MODE_* */
	__u8 _pad[3];
};

#endif
