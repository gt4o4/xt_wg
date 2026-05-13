// SPDX-License-Identifier: GPL-2.0-only
/*
 * Author: Bingchen Gong <gongbingchen@gmail.com>
 *
 * xt_WGANYCAST v10.1 — marker-only expectation, no synthetic conntracks,
 * with optional per-rule `--init-pool` cold-start seeding and per-door
 * conntrack-based dead-door eviction (no module-private storage).
 *
 *   - Per-session **master** is the first WG ct that processes a
 *     RESP message.  Pool storage lives inline in the master's
 *     `nfct_help_data(master)` (the kernel's 32-byte
 *     `nf_conn_help.data[]` area).
 *
 *   - Two synthetic marker `nf_conntrack_expect` per master, both
 *     with `dst.protonum = WGA_MARKER_PROTO (253)` and
 *     `NF_CT_EXPECT_PERMANENT`.  Marker 1 keyed by `our_idx` in
 *     `dst.u3.ip`; marker 2 keyed by `peer_idx`.  `dst.u3.ip` is
 *     the kernel's `nf_ct_expect_dst_hash` input, so per-session
 *     markers fan out across the 8192-bucket expect hashtable
 *     (would be one-bucket pile-up if we keyed via `src.u3.ip`).
 *     They never match real packets — real WG is proto=UDP,
 *     marker is proto=253, and protonum is exact-compared with no
 *     mask in `__nf_ct_tuple_dst_cmp`.
 *
 *   - Helper is attached to WG cts via `iptables -t raw -j CT
 *     --helper WGANYCAST` in PREROUTING (also via auto-attach if
 *     sysctl `net.netfilter.nf_conntrack_helper=1`, helper.tuple
 *     matches `dst.port=51821, proto=UDP`).  The helper's `.help`
 *     callback runs at conntrack-helper priority +300 — does
 *     master promotion + pool refresh on inbound packets.
 *
 *   - SPRAY xt target (raw OUTPUT, -300) parses WG header for the
 *     session idx in the outbound packet and looks up the marker
 *     to find master → snapshots pool → rewrites iph->daddr +
 *     udph->dest with the chosen anycast door.
 *
 *     v10.0: when master exists, init entries unconditionally seeded
 *     into master's inline pool on every packet via
 *     `wga_seed_pool_if_absent` (insert-only, no refresh).
 *
 *     v10.1: pipeline is now
 *       (a) pre-spray GC via `wga_run_pool_gc` — drops slots whose
 *           per-door conntrack has expired,
 *       (b) gated seeding via `wga_should_seed` — only on outbound
 *           handshake / keepalive / fresh-master,
 *       (c) DATA spray uses `wga_pick_for_data_and_rewrite` which
 *           filters slots by `wga_query_door`: an entry is eligible
 *           only if its per-door ct has `IPS_SEEN_REPLY_BIT` set OR
 *           was matched in reply direction (RX-confirmed).  Handshake
 *           spray uses the original full-pool random pick (probes are
 *           supposed to try unknowns).
 *
 *     If no master exists AND the rule has a non-empty `--init-pool`,
 *     spray from the static init pool, biased toward entries whose
 *     per-door ct is WGA_DOOR_ALIVE (so re-key INITs prefer the same
 *     anycast as the prior session, keeping the new INIT on the same
 *     conntrack and the same master).
 *
 *     `last_seen_q8 == 0` is now the "untried init seed" sentinel.
 *     `wga_seed_pool_if_absent` writes 0; spray paths promote the
 *     slot to `last_seen_q8 = wga_now_q8()` once they decide to use
 *     it (so subsequent DATA-spray must verify via per-door ct).
 *
 * Master ct lifetime: bounded above by 200 s via
 * `IPS_FIXED_TIMEOUT_BIT`.  Markers + pool die with master via
 * `nf_ct_remove_expectations(master)` in the conntrack destroy
 * path.  Next inbound RESP after master expiry promotes a new
 * master.
 */

#include <linux/version.h>
#include <linux/module.h>
#include <linux/random.h>
#include <linux/skbuff.h>
#include <linux/spinlock.h>
#if LINUX_VERSION_CODE < KERNEL_VERSION(6, 12, 0)
#include <asm/unaligned.h>
#else
#include <linux/unaligned.h>
#endif
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/netfilter/x_tables.h>
#include <linux/netfilter_ipv4/ip_tables.h>
#include <net/checksum.h>
#include <net/ip.h>
#include <net/udp.h>
#include <net/route.h>
#include <net/net_namespace.h>
#include <net/netfilter/nf_conntrack.h>
#include <net/netfilter/nf_conntrack_core.h>
#include <net/netfilter/nf_conntrack_helper.h>
#include <net/netfilter/nf_conntrack_expect.h>
#include <net/netfilter/nf_conntrack_zones.h>
#include "xt_WGANYCAST.h"
#include "xt_wg_common.h"
#include "wg.h"

/* ------------------------------------------------------------------
 *   Observability counters — /proc/net/wganycast_stats
 * ------------------------------------------------------------------ */
static atomic_t wga_stat_help_total           = ATOMIC_INIT(0);
static atomic_t wga_stat_help_parse_fail      = ATOMIC_INIT(0);
static atomic_t wga_stat_help_inbound_init    = ATOMIC_INIT(0);
static atomic_t wga_stat_help_inbound_resp    = ATOMIC_INIT(0);
static atomic_t wga_stat_help_inbound_data    = ATOMIC_INIT(0);
static atomic_t wga_stat_help_inbound_cookie  = ATOMIC_INIT(0);
static atomic_t wga_stat_help_outbound        = ATOMIC_INIT(0);
static atomic_t wga_stat_help_no_master       = ATOMIC_INIT(0);
static atomic_t wga_stat_master_promoted      = ATOMIC_INIT(0);
static atomic_t wga_stat_master_promote_lost  = ATOMIC_INIT(0);
static atomic_t wga_stat_marker_register_fail = ATOMIC_INIT(0);
static atomic_t wga_stat_pool_match_refresh   = ATOMIC_INIT(0);
static atomic_t wga_stat_pool_insert_append   = ATOMIC_INIT(0);
static atomic_t wga_stat_pool_insert_evict    = ATOMIC_INIT(0);
static atomic_t wga_stat_spray_total          = ATOMIC_INIT(0);
static atomic_t wga_stat_spray_parse_fail     = ATOMIC_INIT(0);
static atomic_t wga_stat_spray_skip_type      = ATOMIC_INIT(0);
static atomic_t wga_stat_spray_no_master      = ATOMIC_INIT(0);
static atomic_t wga_stat_spray_rewrote        = ATOMIC_INIT(0);
static atomic_t wga_stat_spray_no_rewrite     = ATOMIC_INIT(0);
static atomic_t wga_stat_spray_init_rewrote   = ATOMIC_INIT(0);
static atomic_t wga_stat_spray_init_seed      = ATOMIC_INIT(0);
static atomic_t wga_stat_pool_gc_removed      = ATOMIC_INIT(0);
static atomic_t wga_stat_spray_data_filtered  = ATOMIC_INIT(0);
static atomic_t wga_stat_spray_data_fallback  = ATOMIC_INIT(0);
static atomic_t wga_stat_pool_seed_promoted   = ATOMIC_INIT(0);
static atomic_t wga_stat_init_bias_alive      = ATOMIC_INIT(0);
static atomic_t wga_stat_init_bias_fallback   = ATOMIC_INIT(0);

static int wga_stats_show(struct seq_file *s, void *v)
{
	seq_printf(s, "help_total            %d\n", atomic_read(&wga_stat_help_total));
	seq_printf(s, "help_parse_fail       %d\n", atomic_read(&wga_stat_help_parse_fail));
	seq_printf(s, "help_inbound_init     %d\n", atomic_read(&wga_stat_help_inbound_init));
	seq_printf(s, "help_inbound_resp     %d\n", atomic_read(&wga_stat_help_inbound_resp));
	seq_printf(s, "help_inbound_data     %d\n", atomic_read(&wga_stat_help_inbound_data));
	seq_printf(s, "help_inbound_cookie   %d\n", atomic_read(&wga_stat_help_inbound_cookie));
	seq_printf(s, "help_outbound         %d\n", atomic_read(&wga_stat_help_outbound));
	seq_printf(s, "help_no_master        %d\n", atomic_read(&wga_stat_help_no_master));
	seq_printf(s, "master_promoted       %d\n", atomic_read(&wga_stat_master_promoted));
	seq_printf(s, "master_promote_lost   %d\n", atomic_read(&wga_stat_master_promote_lost));
	seq_printf(s, "marker_register_fail  %d\n", atomic_read(&wga_stat_marker_register_fail));
	seq_printf(s, "pool_match_refresh    %d\n", atomic_read(&wga_stat_pool_match_refresh));
	seq_printf(s, "pool_insert_append    %d\n", atomic_read(&wga_stat_pool_insert_append));
	seq_printf(s, "pool_insert_evict     %d\n", atomic_read(&wga_stat_pool_insert_evict));
	seq_printf(s, "spray_total           %d\n", atomic_read(&wga_stat_spray_total));
	seq_printf(s, "spray_parse_fail      %d\n", atomic_read(&wga_stat_spray_parse_fail));
	seq_printf(s, "spray_skip_type       %d\n", atomic_read(&wga_stat_spray_skip_type));
	seq_printf(s, "spray_no_master       %d\n", atomic_read(&wga_stat_spray_no_master));
	seq_printf(s, "spray_rewrote         %d\n", atomic_read(&wga_stat_spray_rewrote));
	seq_printf(s, "spray_no_rewrite      %d\n", atomic_read(&wga_stat_spray_no_rewrite));
	seq_printf(s, "spray_init_rewrote    %d\n", atomic_read(&wga_stat_spray_init_rewrote));
	seq_printf(s, "spray_init_seed       %d\n", atomic_read(&wga_stat_spray_init_seed));
	seq_printf(s, "pool_gc_removed       %d\n", atomic_read(&wga_stat_pool_gc_removed));
	seq_printf(s, "spray_data_filtered   %d\n", atomic_read(&wga_stat_spray_data_filtered));
	seq_printf(s, "spray_data_fallback   %d\n", atomic_read(&wga_stat_spray_data_fallback));
	seq_printf(s, "pool_seed_promoted    %d\n", atomic_read(&wga_stat_pool_seed_promoted));
	seq_printf(s, "init_bias_alive       %d\n", atomic_read(&wga_stat_init_bias_alive));
	seq_printf(s, "init_bias_fallback    %d\n", atomic_read(&wga_stat_init_bias_fallback));
	return 0;
}

static int wga_stats_open(struct inode *inode, struct file *file)
{
	return single_open(file, wga_stats_show, NULL);
}

static const struct proc_ops wga_stats_pops = {
	.proc_open    = wga_stats_open,
	.proc_read    = seq_read,
	.proc_lseek   = seq_lseek,
	.proc_release = single_release,
};

static struct proc_dir_entry *wga_stats_proc;

/* Master ct lifetime — matches WG REJECT_AFTER_TIME + 20 s buffer.
 * The fixed timeout combined with IPS_FIXED_TIMEOUT_BIT prevents
 * any refresh path from extending it.  Without per-flow expectations
 * keeping master alive via child refcounts (v8 design), master ALWAYS
 * dies on its 200 s mark — matches v3.2's anchor lifetime exactly.
 */
#define WGA_MASTER_TTL_SEC	200u

/* --------------------------------------------------------------------
 *   Inline pool — lives in nf_conn_help->data[32] on master ct
 *
 *   Each entry is 8 bytes packed; 4 entries fill the 32-byte area
 *   exactly.  An empty slot is marked by ip == 0 (no need for an
 *   explicit count field).  Per-entry last_seen is a 16-bit truncated
 *   tick value derived from `jiffies >> WGA_TIME_SHIFT` — the shift
 *   stretches the wrap window to ~524 s at HZ=1000, giving a 262 s
 *   half-window for unambiguous LRU compare that comfortably exceeds
 *   the 200 s master lifetime.
 * -------------------------------------------------------------------- */

#define WGA_POOL_SIZE      4u
#define WGA_TIME_SHIFT     3  /* (jiffies >> 3): 1 unit ≈ 8 ms @HZ=1000 */

struct wga_pool_entry {
	__be32  ip;                /* 4 — 0 means free slot           */
	__be16  port;              /* 2                                */
	__u16   last_seen_q8;      /* 2 — (jiffies >> 3) wrapped 16b  */
};

struct wga_pool_inline {
	struct wga_pool_entry slot[WGA_POOL_SIZE];
};

/* 4 × 8 = 32 bytes — fills help->data[32] exactly.  Use
 * static_assert (C11, file-scope) rather than NF_CT_HELPER_BUILD_BUG_ON
 * which expands to BUILD_BUG_ON / do-while-0 requiring function scope. */
static_assert(sizeof(struct wga_pool_inline) <= 32,
	      "wga_pool_inline must fit in nf_conn_help->data[32]");
static_assert(sizeof(struct wga_pool_entry) == 8,
	      "wga_pool_entry expected to be exactly 8 bytes (4+2+2)");
static_assert(WGA_POOL_SIZE == XT_WGANYCAST_POOL_MAX,
	      "pool size must match userspace-visible XT_WGANYCAST_POOL_MAX");

static inline __u16 wga_now_q8(void)
{
	return (__u16)(jiffies >> WGA_TIME_SHIFT);
}

static inline struct wga_pool_inline *wga_pool_of(struct nf_conn *master)
{
	return (struct wga_pool_inline *)nfct_help_data(master);
}

/* --------------------------------------------------------------------
 *   Helper definition
 *
 *   `helper.tuple.dst.u.udp.port = htons(51821)` enables auto-attach
 *   if `net.netfilter.nf_conntrack_helper=1`.  For sysctl=0 (kernel
 *   default), the NixOS module emits `-j CT --helper WGANYCAST` in
 *   raw PREROUTING which explicitly attaches the helper via xt_CT
 *   template regardless of sysctl.
 *
 *   `helper.data_len = sizeof(struct wga_pool_inline)` reserves the
 *   32-byte data[] area on every helped ct's `nf_conn_help`.  Pool
 *   only lives on master; other helped cts of the same session have
 *   the area but it stays zeroed.
 *
 *   `expect_policy.max_expected = 2` allows the two markers we
 *   register per master (one keyed by our_idx, one by peer_idx).
 *   `expect_policy.timeout = 86400` is a far-future ceiling — master
 *   FIXED_TIMEOUT (200 s) always fires first, removing markers via
 *   `nf_ct_remove_expectations` long before this timer would.
 *
 *   No `.destroy` callback — kernel walks `master_help->expectations`
 *   and destroys our markers automatically when master ct is
 *   destroyed.
 * -------------------------------------------------------------------- */

static int wga_help(struct sk_buff *skb, unsigned int protoff,
		    struct nf_conn *ct, enum ip_conntrack_info ctinfo);

/* WG can have 2 active sessions concurrently during re-key transition
 * (the new session takes over after handshake completes, but the old
 * session keeps sending DATA until REJECT_AFTER_TIME = 180 s).  Our
 * outbound spray sees DATA from BOTH sessions during that window —
 * old peer_idx + new peer_idx.  max_expected = 2 markers per master
 * evicts the old peer_idx as soon as the new RESP registers new
 * markers, so outbound DATA on the OLD session hits spray_no_master.
 *
 * Set max_expected = 8 so we can hold markers for up to ~4 sessions
 * concurrently per master.  In steady state (one re-key cycle every
 * 120 s, REJECT_AFTER_TIME = 180 s), only 2 sessions overlap, so 4
 * markers are in active use; the extra 4 slots cover transient bursts
 * (handshake retries, peer NAT churn).  Marker timeout (86400 s) and
 * master ct TTL (200 s, refreshed) bound the total lifetime; old
 * markers die when the master ct dies. */
static const struct nf_conntrack_expect_policy wga_exp_policy = {
	.max_expected = 8,
	.timeout      = 86400,
	.name         = "default",
};

static struct nf_conntrack_helper wga_helper __read_mostly = {
	.name = "WGANYCAST",
	.tuple = {
		.src.l3num      = AF_INET,
		.dst.protonum   = IPPROTO_UDP,
		.dst.u.udp.port = __constant_htons(51821),
	},
	.expect_class_max = 0,
	.expect_policy    = &wga_exp_policy,
	.help             = wga_help,
	.data_len         = sizeof(struct wga_pool_inline),
};

/* --------------------------------------------------------------------
 *   WG packet parsing — unchanged from v3.2
 * -------------------------------------------------------------------- */

struct wga_pkt_info {
	u8	wg_type;
	__le32	sender_idx;	/* valid for INIT, RESP */
	__le32	receiver_idx;	/* valid for RESP, COOKIE, DATA */
	__u16	wg_payload_len;	/* WG payload size (after UDP hdr).
				 * Used to detect WG keepalives (32 B
				 * DATA = 4 type + 4 receiver_idx + 8
				 * counter + 16 AEAD tag, no plaintext). */
};

/* WG keepalive: DATA message with empty plaintext.
 *   wire layout = 4B header + 4B receiver_idx + 8B counter
 *               + 0B encrypted plaintext + 16B AEAD tag
 *   total      = 32 B
 * Real DATA carrying any payload is larger; handshakes are larger;
 * therefore exact == 32 reliably identifies keepalives. */
#define WGA_KEEPALIVE_WG_PAYLOAD_LEN	32u

static bool wga_parse_packet(struct sk_buff *skb,
			     struct wga_pkt_info *info,
			     struct iphdr **iph_out,
			     struct udphdr **udph_out)
{
	struct iphdr *iph;
	struct udphdr *udph;
	const u8 *payload;
	unsigned int ihl, payload_len;
	u8 wg_type;

	if (skb_ensure_writable(skb, skb_network_offset(skb) +
				     sizeof(*iph) + sizeof(*udph)))
		return false;

	iph = ip_hdr(skb);
	if (iph->protocol != IPPROTO_UDP)
		return false;

	ihl = iph->ihl * 4;
	if (ntohs(iph->tot_len) < ihl + sizeof(*udph))
		return false;

	udph = (struct udphdr *)((u8 *)iph + ihl);
	payload_len = ntohs(udph->len);
	if (payload_len < sizeof(*udph))
		return false;
	payload_len -= sizeof(*udph);
	payload = (const u8 *)udph + sizeof(*udph);

	if (payload_len < 4)
		return false;

	wg_type = payload[0];
	switch (wg_type) {
	case WG_TYPE_INIT:
		if (payload_len != sizeof(struct wg_message_handshake_initiation))
			return false;
		info->sender_idx   = get_unaligned((__le32 *)(payload + WG_OFF_SENDER_IDX_INIT));
		info->receiver_idx = 0;
		break;
	case WG_TYPE_RESP:
		if (payload_len != sizeof(struct wg_message_handshake_response))
			return false;
		info->sender_idx   = get_unaligned((__le32 *)(payload + WG_OFF_SENDER_IDX_RESP));
		info->receiver_idx = get_unaligned((__le32 *)(payload + WG_OFF_RECEIVER_IDX_RESP));
		break;
	case WG_TYPE_COOKIE:
		if (payload_len != sizeof(struct wg_message_handshake_cookie))
			return false;
		info->sender_idx   = 0;
		info->receiver_idx = get_unaligned((__le32 *)(payload + WG_OFF_RECEIVER_IDX_COOKIE));
		break;
	case WG_TYPE_DATA:
		/* Transport-data header is 16 B, plus ≥ 16 B AEAD tag. */
		if (payload_len < 16)
			return false;
		info->sender_idx   = 0;
		info->receiver_idx = get_unaligned((__le32 *)(payload + WG_OFF_RECEIVER_IDX_DATA));
		break;
	default:
		return false;
	}

	info->wg_type        = wg_type;
	info->wg_payload_len = (__u16)payload_len;
	*iph_out  = iph;
	*udph_out = udph;
	return true;
}

/* --------------------------------------------------------------------
 *   Marker expectation — synthetic tuple keyed by session idx
 *
 *   Tuple shape:
 *     src.l3num    = AF_INET
 *     dst.u3.ip    = idx          (mask 0xFFFFFFFF — exact match,
 *                                  AND the hash key — see below)
 *     dst.protonum = WGA_MARKER_PROTO (253)   (exact, no mask)
 *     all other fields = 0        (mask = 0xFF/0xFFFF — exact-zero)
 *
 *   The kernel's expectation hash (`nf_ct_expect_dst_hash`) keys on
 *   `dst.u3.all` + `dst.protonum` + `dst.u.all` + `src.l3num`.  By
 *   placing `idx` in `dst.u3.ip` instead of `src.u3.ip` (where it
 *   sat through v9.0–v9.3), each marker spreads across the 8192-
 *   bucket hash table — eliminating the same-bucket pile-up that
 *   would otherwise force O(N) lookups across all sessions.
 *
 *   Real packets cannot match because they all have proto=UDP, and
 *   protonum is exact-compared with no mask in `__nf_ct_tuple_dst_cmp`.
 * -------------------------------------------------------------------- */

static void wga_marker_tuple(struct nf_conntrack_tuple *t, __le32 idx)
{
	memset(t, 0, sizeof(*t));
	t->src.l3num    = AF_INET;
	t->dst.u3.ip    = (__force __be32)idx;
	t->dst.protonum = WGA_MARKER_PROTO;
}

static int wga_register_marker(struct nf_conn *master, __le32 idx)
{
	struct nf_conntrack_expect *exp;
	union nf_inet_addr daddr_idx;
	/* Kernel 7.0.3's nf_ct_expect_init dereferences daddr/src/dst
	 * UNCONDITIONALLY (only saddr has a NULL check).  Passing NULL
	 * for any of these → instant null-ptr panic.  Pass zero-valued
	 * pointers so the deref reads from valid stack locations.  saddr
	 * stays NULL → mask.src.u3 = 0 (true wildcard), which doesn't
	 * matter for matching but keeps the tuple semantically clean. */
	__be16 port_zero = 0;
	int rc;

	exp = nf_ct_expect_alloc(master);
	if (!exp)
		return -ENOMEM;

	daddr_idx.ip = (__force __be32)idx;
	nf_ct_expect_init(exp, NF_CT_EXPECT_CLASS_DEFAULT, AF_INET,
			  NULL,              /* src.ip wildcard (mask 0)      */
			  &daddr_idx,        /* dst.ip = idx, mask 0xFFFFFFFF
			                      * — primary key + hash input    */
			  WGA_MARKER_PROTO,  /* sentinel — never real         */
			  &port_zero,        /* src.port = 0, mask 0xFFFF     */
			  &port_zero);       /* dst.port = 0, mask 0xFFFF
			                      * — also contributes to hash    */
	exp->flags  = NF_CT_EXPECT_PERMANENT;
	exp->helper = NULL;  /* marker never matches a real packet */

	rc = nf_ct_expect_related(exp, 0);
	nf_ct_expect_put(exp);
	return rc;  /* 0 = registered, -EBUSY = race lost, -ENOMEM */
}

/* Caller MUST hold rcu_read_lock.  Returned master is valid only
 * within the RCU read section (or until caller takes
 * `nf_conntrack_get` on it). */
static struct nf_conn *wga_find_master_rcu(struct net *net, __le32 idx)
{
	struct nf_conntrack_tuple t;
	struct nf_conntrack_expect *exp;

	wga_marker_tuple(&t, idx);
	exp = __nf_ct_expect_find(net, &nf_ct_zone_dflt, &t);
	return exp ? exp->master : NULL;
}

/* --------------------------------------------------------------------
 *   Pool maintenance — inline array in master->help->data[]
 *
 *   wga_learn_door: refresh existing entry, append into free slot, or
 *   evict the LRU (smallest last_seen, wrap-aware unsigned compare).
 *   Serialised via master `nf_conn`'s own spinlock.
 * -------------------------------------------------------------------- */

static void wga_learn_door(struct nf_conn *master,
			   __be32 anycast_ip, __be16 anycast_port)
{
	struct wga_pool_inline *p = wga_pool_of(master);
	int i, free_idx = -1, oldest_idx = -1;
	__u16 now_q8 = wga_now_q8();
	__u16 oldest_age = 0;

	if (!p)
		return;

	spin_lock_bh(&master->lock);

	for (i = 0; i < WGA_POOL_SIZE; i++) {
		struct wga_pool_entry *e = &p->slot[i];
		__u16 age;

		if (e->ip == 0) {
			if (free_idx < 0)
				free_idx = i;
			continue;
		}
		if (e->ip == anycast_ip && e->port == anycast_port) {
			e->last_seen_q8 = now_q8;
			atomic_inc(&wga_stat_pool_match_refresh);
			spin_unlock_bh(&master->lock);
			return;
		}
		/* Wrap-aware "age = now - last_seen": bigger age = older. */
		age = (__u16)(now_q8 - e->last_seen_q8);
		if (oldest_idx < 0 || age > oldest_age) {
			oldest_idx = i;
			oldest_age = age;
		}
	}

	if (free_idx >= 0) {
		p->slot[free_idx].ip            = anycast_ip;
		p->slot[free_idx].port          = anycast_port;
		p->slot[free_idx].last_seen_q8  = now_q8;
		atomic_inc(&wga_stat_pool_insert_append);
	} else {
		/* All slots occupied; evict LRU. */
		p->slot[oldest_idx].ip           = anycast_ip;
		p->slot[oldest_idx].port         = anycast_port;
		p->slot[oldest_idx].last_seen_q8 = now_q8;
		atomic_inc(&wga_stat_pool_insert_evict);
	}

	spin_unlock_bh(&master->lock);
}

/* --------------------------------------------------------------------
 *   Seed-only pool insert — fills an empty slot if (ip, port) isn't
 *   present, else does nothing.
 *
 *   Unlike `wga_learn_door`, this does NOT refresh `last_seen_q8` on
 *   match and does NOT evict on full pool.  Newly-inserted slots are
 *   stamped with `last_seen_q8 = 0` — the "untried init seed" sentinel
 *   in v10.1's state machine.  Spray paths interpret `last_seen_q8 == 0`
 *   as "this is an init seed; the kernel hasn't observed any per-door
 *   conntrack activity on it yet — DATA-spray treats it as eligible
 *   on first attempt, then bumps to a non-zero stamp afterwards so
 *   subsequent DATA picks must verify via per-door ct + IPS_SEEN_REPLY_BIT".
 *
 *   The seed inserts only into FREE slots; full pools silently drop
 *   seed attempts.  Real-observed doors (via `wga_help → wga_learn_door`)
 *   own LRU eviction; init seeds never displace observed entries.  If a
 *   real RX confirms the same (ip, port) as an existing init seed,
 *   `wga_learn_door` refreshes it (sets `last_seen_q8` to current time),
 *   promoting it from "init seed" to "RX-confirmed door".
 * -------------------------------------------------------------------- */

static void wga_seed_pool_if_absent(struct nf_conn *master,
				    __be32 anycast_ip, __be16 anycast_port)
{
	struct wga_pool_inline *p = wga_pool_of(master);
	int i, free_idx = -1;

	if (!p)
		return;

	spin_lock_bh(&master->lock);

	for (i = 0; i < WGA_POOL_SIZE; i++) {
		struct wga_pool_entry *e = &p->slot[i];

		if (e->ip == 0) {
			if (free_idx < 0)
				free_idx = i;
			continue;
		}
		if (e->ip == anycast_ip && e->port == anycast_port) {
			/* Already present — do NOT refresh. */
			spin_unlock_bh(&master->lock);
			return;
		}
	}

	if (free_idx >= 0) {
		p->slot[free_idx].ip            = anycast_ip;
		p->slot[free_idx].port          = anycast_port;
		/* v10.1 sentinel: untried init seed.  Spray paths read 0
		 * as "kernel-ct unverified yet; eligible by default and
		 * promote-on-spray". */
		p->slot[free_idx].last_seen_q8  = 0;
		atomic_inc(&wga_stat_pool_insert_append);
	}
	/* Pool full and entry not present — silently drop the seed.
	 * Real-observed doors take precedence; LRU eviction stays the
	 * exclusive privilege of `wga_learn_door`. */

	spin_unlock_bh(&master->lock);
}

/* --------------------------------------------------------------------
 *   Per-door conntrack queries — kernel-managed liveness signal
 *
 *   The kernel automatically creates a `nf_conn` for each unique
 *   outbound 5-tuple `(our_saddr:our_sport, anycast_ip:edgePort, UDP)`
 *   as we spray.  Reply traffic flips `IPS_SEEN_REPLY_BIT` on that ct.
 *   We never write to these cts; we only read their state to drive
 *   spray-eligibility decisions.  This is the entire mechanism for
 *   v10.1's "dead door eviction" — no module-private liveness cache
 *   needed.
 * -------------------------------------------------------------------- */

static void wga_build_door_tuple(struct nf_conntrack_tuple *t,
				 __be32 saddr, __be16 sport,
				 __be32 daddr, __be16 dport)
{
	memset(t, 0, sizeof(*t));
	t->src.l3num      = AF_INET;
	t->src.u3.ip      = saddr;
	t->src.u.udp.port = sport;
	t->dst.u3.ip      = daddr;
	t->dst.u.udp.port = dport;
	t->dst.protonum   = IPPROTO_UDP;
}

/* Tri-state liveness query.  Returns WGA_DOOR_*:
 *   ALIVE   — ct exists AND (IPS_SEEN_REPLY_BIT set OR matched via
 *             reply direction, i.e. inbound-initiated flow).
 *   DEAD    — ct exists in original direction, no reply seen yet.
 *   UNKNOWN — no ct found (never tried, or ct already expired).
 *
 * Caller decides how to treat UNKNOWN.  DATA-spray treats it as
 * eligible (give the door a chance); pre-spray GC treats it as
 * stale-when-slot-was-tried (gate by `last_seen_q8 > 0`).
 */
enum wga_door_state {
	WGA_DOOR_UNKNOWN = 0,
	WGA_DOOR_DEAD    = 1,
	WGA_DOOR_ALIVE   = 2,
};

static enum wga_door_state
wga_query_door(struct net *net,
	       __be32 saddr, __be16 sport,
	       __be32 daddr, __be16 dport)
{
	struct nf_conntrack_tuple t;
	struct nf_conntrack_tuple_hash *h;
	struct nf_conn *ct;
	enum wga_door_state state;

	wga_build_door_tuple(&t, saddr, sport, daddr, dport);
	h = nf_conntrack_find_get(net, &nf_ct_zone_dflt, &t);
	if (!h)
		return WGA_DOOR_UNKNOWN;

	ct = nf_ct_tuplehash_to_ctrack(h);
	if (test_bit(IPS_SEEN_REPLY_BIT, &ct->status))
		state = WGA_DOOR_ALIVE;
	else if (NF_CT_DIRECTION(h) == IP_CT_DIR_REPLY)
		state = WGA_DOOR_ALIVE;	/* inbound-initiated — RX-confirmed */
	else
		state = WGA_DOOR_DEAD;
	nf_ct_put(ct);
	return state;
}

/* --------------------------------------------------------------------
 *   Rewrite outbound packet daddr (+ dport when non-zero)
 *
 *   Primitive used by both the dynamic-pool and init-pool spray
 *   paths.  Idempotent for (old == new): returns true regardless
 *   of whether a rewrite was actually emitted, so callers can use
 *   the return to mean "spray decision was made", not "csum was
 *   touched".
 * -------------------------------------------------------------------- */

static void wga_rewrite_packet(struct sk_buff *skb,
			       struct iphdr *iph, struct udphdr *udph,
			       __be32 new_addr, __be16 new_port)
{
	__be32 old_addr = iph->daddr;
	__be16 old_port = udph->dest;

	if (new_addr != old_addr) {
		iph->daddr = new_addr;
		csum_replace4(&iph->check, old_addr, new_addr);
		if (udph->check)
			inet_proto_csum_replace4(&udph->check, skb,
						 old_addr, new_addr, true);
	}
	if (new_port && new_port != old_port) {
		udph->dest = new_port;
		if (udph->check)
			inet_proto_csum_replace2(&udph->check, skb,
						 old_port, new_port, false);
	}
}

/* --------------------------------------------------------------------
 *   Pick from master's pool + rewrite outbound packet
 *
 *   Snapshot the live entries under master's lock, then do the
 *   random pick + checksum rewrite unlocked.  Short critical section.
 * -------------------------------------------------------------------- */

static bool wga_pick_and_rewrite(struct sk_buff *skb,
				 struct iphdr *iph, struct udphdr *udph,
				 struct nf_conn *master)
{
	struct wga_pool_inline *p = wga_pool_of(master);
	struct wga_pool_entry candidates[WGA_POOL_SIZE];
	int i, n = 0;
	u32 pick;

	if (!p)
		return false;

	spin_lock_bh(&master->lock);
	for (i = 0; i < WGA_POOL_SIZE; i++) {
		if (p->slot[i].ip != 0)
			candidates[n++] = p->slot[i];
	}
	spin_unlock_bh(&master->lock);

	if (n == 0)
		return false;

	pick = get_random_u32_below((u32)n);
	wga_rewrite_packet(skb, iph, udph,
			   candidates[pick].ip, candidates[pick].port);
	return true;
}

/* --------------------------------------------------------------------
 *   Pick from rule-side init pool + rewrite outbound packet
 *
 *   Cold-start path: no master ct exists for this WG session yet.
 *   Used by:
 *     1) Initial INIT spray before any RESP has been observed.
 *     2) Re-key INIT spray (new sender_idx → no marker → master NULL)
 *        before the new RESP arrives.
 *
 *   v10.1 bias: query per-door cts of each `info->init[]` entry.
 *   Entries whose per-door ct is WGA_DOOR_ALIVE (kernel observed a
 *   reply on `(our:sport → entry.ip:entry.port)` recently) form the
 *   "alive subset" — pick uniformly from it.  Fall back to uniform
 *   pick across the full init pool only when no entry has alive
 *   ct evidence (true cold-start, or every CF anycast unreachable).
 *
 *   Why this matters: on re-key, biasing toward the same anycast IP
 *   as the prior session keeps the new INIT on the same per-door ct,
 *   which means same conntrack → same master → markers added under
 *   the SAME master.  Pool preserved across re-key, no migration
 *   needed.  When the bias hits an anycast different from the prior
 *   one (rare), the new master gets caught up via `wga_should_seed`'s
 *   fresh-master trigger on the first post-promotion outbound.
 *
 *   Stateless from our side: reads `info->init[]` (immutable rule
 *   blob), queries kernel ct hashtable, writes only to the packet.
 *   No master/help state.
 * -------------------------------------------------------------------- */

static bool wga_pick_init_and_rewrite(struct sk_buff *skb,
				      struct iphdr *iph, struct udphdr *udph,
				      const struct xt_wganycast_info *info,
				      struct net *net)
{
	u8 alive_idx[XT_WGANYCAST_INIT_MAX];
	u8 alive_n = 0;
	u8 i, chosen;
	u32 pick;

	if (!info || info->ninit == 0)
		return false;

	/* Pass 1: collect entries whose per-door ct is alive. */
	for (i = 0; i < info->ninit; i++) {
		if (wga_query_door(net, iph->saddr, udph->source,
				   info->init[i].ip, info->init[i].port)
		    == WGA_DOOR_ALIVE) {
			alive_idx[alive_n++] = i;
		}
	}

	if (alive_n > 0) {
		pick = get_random_u32_below((u32)alive_n);
		chosen = alive_idx[pick];
		atomic_inc(&wga_stat_init_bias_alive);
	} else {
		pick = get_random_u32_below((u32)info->ninit);
		chosen = (u8)pick;
		atomic_inc(&wga_stat_init_bias_fallback);
	}

	wga_rewrite_packet(skb, iph, udph,
			   info->init[chosen].ip, info->init[chosen].port);
	return true;
}

/* --------------------------------------------------------------------
 *   Seed master's inline pool from the rule's static init entries.
 *
 *   Called on every outbound packet that finds a master ct AND has
 *   a non-empty init pool on the rule.  Uses `wga_seed_pool_if_absent`
 *   (NOT `wga_learn_door`) so:
 *     - first call after master promotion fills empty slots with init
 *       entries that have a current `last_seen_q8`,
 *     - subsequent calls find init entries already present and exit
 *       early without touching `last_seen_q8`,
 *     - init entries thus age naturally over time; real-observed RX
 *       (via `wga_help` → `wga_learn_door`) can either refresh them
 *       (if real saddr/sport == init.ip/init.port — promotes to
 *       confirmed) or evict them via LRU (once 4 distinct real doors
 *       exist, oldest init entry loses).
 *
 *   Bounded loop (max 4 calls per packet) under master->lock per
 *   call.  Negligible cost.  After init entries occupy free slots,
 *   subsequent loops are O(ninit) lock-acquire + early-return.
 * -------------------------------------------------------------------- */

static void wga_seed_master_from_init(struct nf_conn *master,
				      const struct xt_wganycast_info *info)
{
	u8 i;

	if (!info || info->ninit == 0)
		return;

	for (i = 0; i < info->ninit; i++)
		wga_seed_pool_if_absent(master,
					info->init[i].ip,
					info->init[i].port);
	atomic_inc(&wga_stat_spray_init_seed);
}

/* --------------------------------------------------------------------
 *   v10.1 — pre-spray GC, seeding gates, DATA-filter spray
 *
 *   Pre-spray GC scans master's pool and removes slots whose per-door
 *   ct has expired (state = WGA_DOOR_UNKNOWN) but were previously tried
 *   (last_seen_q8 > 0).  Untried init seeds (last_seen_q8 == 0) are
 *   kept regardless — they haven't had a chance yet.
 *
 *   Seeding gates: handshake (INIT/RESP/COOKIE) and WG keepalives
 *   re-run `wga_seed_master_from_init`, plus a one-shot trigger on
 *   freshly-promoted masters (occupied < pool size, no init-seed
 *   sentinel present yet → re-seed).  This replaces v10.0's
 *   unconditional per-packet seed call.
 *
 *   DATA spray uses a per-door-ct eligibility filter.  Handshakes use
 *   the original full-pool random pick (they're meant to probe).
 * -------------------------------------------------------------------- */

/* Pre-spray pool GC.  Called per outbound packet immediately after
 * master is found.  Two-pass: snapshot under lock, query cts unlocked,
 * write back stale-slots-zeroed under lock (with reuse-detection so
 * we don't clobber concurrent wga_help inserts). */
static void wga_run_pool_gc(struct net *net, struct nf_conn *master,
			    struct iphdr *iph, struct udphdr *udph)
{
	struct wga_pool_inline *p = wga_pool_of(master);
	struct wga_pool_entry snapshot[WGA_POOL_SIZE];
	bool stale[WGA_POOL_SIZE] = { 0 };
	int i;
	bool any_stale = false;

	if (!p)
		return;

	spin_lock_bh(&master->lock);
	memcpy(snapshot, p->slot, sizeof(snapshot));
	spin_unlock_bh(&master->lock);

	for (i = 0; i < WGA_POOL_SIZE; i++) {
		enum wga_door_state s;

		if (snapshot[i].ip == 0)
			continue;
		if (snapshot[i].last_seen_q8 == 0)
			continue;	/* untried init seed — keep */

		s = wga_query_door(net, iph->saddr, udph->source,
				   snapshot[i].ip, snapshot[i].port);
		if (s == WGA_DOOR_UNKNOWN) {
			/* Slot was tried (last_seen > 0) but the kernel's
			 * per-door ct has since expired → stale. */
			stale[i] = true;
			any_stale = true;
		}
	}

	if (!any_stale)
		return;

	spin_lock_bh(&master->lock);
	for (i = 0; i < WGA_POOL_SIZE; i++) {
		if (!stale[i])
			continue;
		/* Reuse-detection: only zero if the slot is unchanged
		 * since snapshot.  `wga_help` may have refreshed it
		 * with a different (ip, port, last_seen) in between. */
		if (p->slot[i].ip == snapshot[i].ip &&
		    p->slot[i].port == snapshot[i].port &&
		    p->slot[i].last_seen_q8 == snapshot[i].last_seen_q8) {
			memset(&p->slot[i], 0, sizeof(p->slot[i]));
			atomic_inc(&wga_stat_pool_gc_removed);
		}
	}
	spin_unlock_bh(&master->lock);
}

/* Returns true if master's pool has at least one filled slot but no
 * untried init-seed sentinel.  Triggers a one-shot re-seed on the
 * first outbound packet after a fresh master is promoted (covers the
 * re-key-to-different-anycast case where the new master starts with
 * only slot[0] from the RESP and lacks init entries until next
 * handshake — which would be ≤120 s of reduced diversity). */
static bool wga_master_is_fresh(struct nf_conn *master)
{
	struct wga_pool_inline *p = wga_pool_of(master);
	int i, occupied = 0;
	bool has_seed = false, fresh;

	if (!p)
		return false;

	spin_lock_bh(&master->lock);
	for (i = 0; i < WGA_POOL_SIZE; i++) {
		if (p->slot[i].ip == 0)
			continue;
		occupied++;
		if (p->slot[i].last_seen_q8 == 0)
			has_seed = true;
	}
	fresh = (occupied > 0) && !has_seed && (occupied < WGA_POOL_SIZE);
	spin_unlock_bh(&master->lock);
	return fresh;
}

/* Seeding cadence gate.  See plan section 3. */
static bool wga_should_seed(struct nf_conn *master,
			    const struct wga_pkt_info *pi,
			    const struct xt_wganycast_info *info)
{
	if (!info || info->ninit == 0)
		return false;

	/* Trigger 1: outbound handshake (INIT / RESP / COOKIE). */
	if (pi->wg_type == WG_TYPE_INIT ||
	    pi->wg_type == WG_TYPE_RESP ||
	    pi->wg_type == WG_TYPE_COOKIE)
		return true;

	/* Trigger 2: WG keepalive (DATA with 32-byte total payload =
	 * header + tag, no plaintext). */
	if (pi->wg_type == WG_TYPE_DATA &&
	    pi->wg_payload_len == WGA_KEEPALIVE_WG_PAYLOAD_LEN)
		return true;

	/* Trigger 3: fresh master needs init-seed catch-up. */
	return wga_master_is_fresh(master);
}

/* DATA-spray pick + rewrite with per-door-ct eligibility filter.
 *
 *   Eligibility rule per slot:
 *     - `last_seen_q8 == 0` (untried init seed): always eligible.
 *       The kernel hasn't seen any TX/RX on this door yet; we'll
 *       give it a chance and bump `last_seen_q8` to `wga_now_q8()`
 *       after the spray decides to use it.
 *     - `last_seen_q8 > 0` (previously tried): query per-door ct.
 *       ALIVE → eligible.  DEAD or UNKNOWN → not eligible.
 *
 *   Empty filter → fall back to unfiltered snapshot.  Better to
 *   spray to a (possibly-stale) door than to drop the packet.
 *
 *   Post-spray bump: if the picked slot was an untried seed
 *   (snapshot's last_seen_q8 == 0), promote it under lock with
 *   reuse-detection so it transitions to "tried" for the next
 *   spray's DATA-filter pass.
 */
static bool wga_pick_for_data_and_rewrite(struct sk_buff *skb,
					  struct iphdr *iph,
					  struct udphdr *udph,
					  struct nf_conn *master,
					  struct net *net)
{
	struct wga_pool_inline *p = wga_pool_of(master);
	struct wga_pool_entry snapshot[WGA_POOL_SIZE];
	u8 eligible_idx[WGA_POOL_SIZE];
	u8 occupied_idx[WGA_POOL_SIZE];
	u8 eligible_n = 0, occupied_n = 0;
	u8 chosen_slot;
	struct wga_pool_entry chosen;
	bool was_seed;
	int i;
	u32 pick;

	if (!p)
		return false;

	spin_lock_bh(&master->lock);
	memcpy(snapshot, p->slot, sizeof(snapshot));
	spin_unlock_bh(&master->lock);

	for (i = 0; i < WGA_POOL_SIZE; i++) {
		if (snapshot[i].ip == 0)
			continue;
		occupied_idx[occupied_n++] = (u8)i;

		if (snapshot[i].last_seen_q8 == 0) {
			eligible_idx[eligible_n++] = (u8)i;
			continue;
		}
		if (wga_query_door(net, iph->saddr, udph->source,
				   snapshot[i].ip, snapshot[i].port)
		    == WGA_DOOR_ALIVE) {
			eligible_idx[eligible_n++] = (u8)i;
		} else {
			atomic_inc(&wga_stat_spray_data_filtered);
		}
	}

	if (occupied_n == 0)
		return false;

	if (eligible_n > 0) {
		pick = get_random_u32_below((u32)eligible_n);
		chosen_slot = eligible_idx[pick];
	} else {
		/* All slots are tried-and-dead; spray anyway and let
		 * the GC / handshake re-seed correct things.  Beats
		 * stranding the packet. */
		pick = get_random_u32_below((u32)occupied_n);
		chosen_slot = occupied_idx[pick];
		atomic_inc(&wga_stat_spray_data_fallback);
	}

	chosen = snapshot[chosen_slot];
	was_seed = (chosen.last_seen_q8 == 0);

	wga_rewrite_packet(skb, iph, udph, chosen.ip, chosen.port);

	/* Promote untried seed → tried (last_seen_q8 = now).  Re-acquire
	 * the lock and verify the slot hasn't been reused by wga_help in
	 * the meantime; only stamp if the (ip, port, last_seen_q8 == 0)
	 * triple still matches. */
	if (was_seed) {
		spin_lock_bh(&master->lock);
		if (p->slot[chosen_slot].ip == chosen.ip &&
		    p->slot[chosen_slot].port == chosen.port &&
		    p->slot[chosen_slot].last_seen_q8 == 0) {
			p->slot[chosen_slot].last_seen_q8 = wga_now_q8();
			atomic_inc(&wga_stat_pool_seed_promoted);
		}
		spin_unlock_bh(&master->lock);
	}
	return true;
}

/* --------------------------------------------------------------------
 *   wga_help — conntrack-helper callback, runs at priority +300 for
 *   every packet of every WG-helped ct (inbound and outbound).
 *
 *   On INBOUND RESP: register both markers, promote ct to master,
 *   initialize pool with this packet's (saddr, sport).
 *
 *   On OUTBOUND RESP: same — register both markers under ct.  No
 *   pool refresh (outbound saddr is our own IP, useless as pool
 *   entry).
 *
 *   On INBOUND DATA/COOKIE: look up our_idx marker → master.
 *   Refresh master's pool with this packet's (saddr, sport).
 *
 *   On OUTBOUND DATA/COOKIE: stats only.  SPRAY at raw OUTPUT
 *   already handled rewrite; nothing to do here.
 *
 *   On INIT (either direction): only one idx known.  Skip — wait
 *   for RESP to register both markers.
 * -------------------------------------------------------------------- */

static int wga_help(struct sk_buff *skb, unsigned int protoff,
		    struct nf_conn *ct, enum ip_conntrack_info ctinfo)
{
	struct wga_pkt_info pi;
	struct iphdr *iph;
	struct udphdr *udph;
	struct net *net = nf_ct_net(ct);
	struct nf_conn *master;
	bool is_inbound;

	atomic_inc(&wga_stat_help_total);

	if (!wga_parse_packet(skb, &pi, &iph, &udph)) {
		atomic_inc(&wga_stat_help_parse_fail);
		return NF_ACCEPT;
	}

	/* Direction: packet destined to a locally-assigned IP → inbound. */
	is_inbound = (inet_addr_type(net, iph->daddr) == RTN_LOCAL);

	if (pi.wg_type == WG_TYPE_RESP) {
		/* RESP carries both indexes.  Determine which sender-side
		 * value is "our_idx" vs "peer_idx" based on direction.
		 *
		 *   Inbound RESP  (peer responds to our INIT):
		 *     sender_idx   = peer's new id  (peer_idx)
		 *     receiver_idx = echo of our INIT's sender_idx (our_idx)
		 *
		 *   Outbound RESP (we respond to peer's INIT):
		 *     sender_idx   = our new id      (our_idx)
		 *     receiver_idx = echo of peer's INIT sender_idx (peer_idx)
		 */
		__le32 our_idx, peer_idx;
		int rc_our, rc_peer;

		if (is_inbound) {
			atomic_inc(&wga_stat_help_inbound_resp);
			peer_idx = pi.sender_idx;
			our_idx  = pi.receiver_idx;
		} else {
			atomic_inc(&wga_stat_help_outbound);
			our_idx  = pi.sender_idx;
			peer_idx = pi.receiver_idx;
		}

		/* Check for existing master first.  Keep RCU held across
		 * wga_learn_door so master's refcount-via-expectation
		 * stays valid for the entire use — releasing RCU before
		 * the deref would be a use-after-free if the marker was
		 * reclaimed between find and use.  wga_learn_door takes
		 * a spinlock but never sleeps, so it's safe under RCU. */
		rcu_read_lock();
		master = wga_find_master_rcu(net, our_idx);
		if (master) {
			/* Re-handshake on existing session: refresh pool. */
			if (is_inbound)
				wga_learn_door(master, iph->saddr, udph->source);
			rcu_read_unlock();
			return NF_ACCEPT;
		}
		rcu_read_unlock();

		/* No master yet — claim `ct` as master and register both
		 * markers under it. */
		rc_our  = wga_register_marker(ct, our_idx);
		rc_peer = wga_register_marker(ct, peer_idx);
		if (rc_our != 0 && rc_peer != 0) {
			/* Both failed; another CPU likely won the race.
			 * Find the winner and refresh its pool. */
			atomic_inc(&wga_stat_marker_register_fail);
			rcu_read_lock();
			master = wga_find_master_rcu(net, our_idx);
			if (master && is_inbound)
				wga_learn_door(master, iph->saddr, udph->source);
			if (master)
				atomic_inc(&wga_stat_master_promote_lost);
			rcu_read_unlock();
			return NF_ACCEPT;
		}

		/* We've claimed master role (at least one marker succeeded).
		 * Refresh TTL on EVERY promotion (including re-keys on the
		 * same ct) so the ct doesn't expire mid-session and leave
		 * spray without markers between expiry and next-ct + next-RESP.
		 * Without the refresh, the ct dies hard at master_promote_time
		 * + 200 s, killing all markers — even if RESPs keep coming. */
		set_bit(IPS_FIXED_TIMEOUT_BIT, &ct->status);
		WRITE_ONCE(ct->timeout, jiffies + WGA_MASTER_TTL_SEC * HZ);

		atomic_inc(&wga_stat_master_promoted);

		if (is_inbound)
			wga_learn_door(ct, iph->saddr, udph->source);
		return NF_ACCEPT;
	}

	/* Non-RESP: outbound is stats-only. */
	if (!is_inbound) {
		atomic_inc(&wga_stat_help_outbound);
		return NF_ACCEPT;
	}

	/* Inbound INIT: only peer_idx known (sender_idx); no marker
	 * registration without our_idx.  Wait for RESP. */
	if (pi.wg_type == WG_TYPE_INIT) {
		atomic_inc(&wga_stat_help_inbound_init);
		return NF_ACCEPT;
	}

	/* Inbound DATA/COOKIE: receiver_idx = our_idx.  Look up our_idx
	 * marker → master, refresh master's pool. */
	switch (pi.wg_type) {
	case WG_TYPE_DATA:    atomic_inc(&wga_stat_help_inbound_data);   break;
	case WG_TYPE_COOKIE:  atomic_inc(&wga_stat_help_inbound_cookie); break;
	}

	rcu_read_lock();
	master = wga_find_master_rcu(net, pi.receiver_idx);
	if (master) {
		wga_learn_door(master, iph->saddr, udph->source);
		/* Refresh master TTL on every inbound DATA so active
		 * sessions don't die at the 200 s cap.  WG keepalives
		 * arrive every 25 s, so the refresh is frequent.  This
		 * is the steady-state path that keeps master alive
		 * between re-key cycles. */
		WRITE_ONCE(master->timeout,
			   jiffies + WGA_MASTER_TTL_SEC * HZ);
	} else {
		atomic_inc(&wga_stat_help_no_master);
	}
	rcu_read_unlock();

	return NF_ACCEPT;
}

/* --------------------------------------------------------------------
 *   SPRAY xt target — raw OUTPUT, priority -300.
 *
 *   Pre-conntrack hook → skb has no ct yet.  Parse the WG header
 *   directly, derive the session idx visible in this outbound packet,
 *   look up the marker → master, snapshot pool, rewrite.
 *
 *   Idx semantics per outbound message type:
 *     INIT:   sender_idx   = our_idx   (we initiate)
 *     RESP:   sender_idx   = our_idx   (we respond)
 *     DATA:   receiver_idx = peer_idx  (peer is recipient)
 *     COOKIE: receiver_idx = peer_idx  (we echo peer's idx)
 *
 *   The two markers (our_idx-keyed and peer_idx-keyed) under each
 *   master mean either lookup type resolves to the same master.
 *
 *   v10: per-rule `info->init[]` static pool steers two paths:
 *     - master found + ninit > 0: seed master's pool with init
 *       entries (idempotent LRU insert), then pick from master.
 *     - master NOT found + ninit > 0: cold-start fallback —
 *       pick from init pool directly (no conntrack state touched).
 *     - master NOT found + ninit == 0: v9 behaviour, spray_no_master.
 * -------------------------------------------------------------------- */

static unsigned int wganycast_target_v4(struct sk_buff *skb,
					const struct xt_action_param *par)
{
	struct net *net = xt_net(par);
	const struct xt_wganycast_info *info = par->targinfo;
	struct wga_pkt_info pi;
	struct iphdr *iph;
	struct udphdr *udph;
	struct nf_conn *master;
	__le32 lookup_idx;

	atomic_inc(&wga_stat_spray_total);

	if (!wga_parse_packet(skb, &pi, &iph, &udph)) {
		atomic_inc(&wga_stat_spray_parse_fail);
		return XT_CONTINUE;
	}

	switch (pi.wg_type) {
	case WG_TYPE_INIT:
	case WG_TYPE_RESP:
		lookup_idx = pi.sender_idx;   /* our_idx */
		break;
	case WG_TYPE_DATA:
	case WG_TYPE_COOKIE:
		lookup_idx = pi.receiver_idx; /* peer_idx */
		break;
	default:
		atomic_inc(&wga_stat_spray_skip_type);
		return XT_CONTINUE;
	}

	rcu_read_lock();
	master = wga_find_master_rcu(net, lookup_idx);
	if (!master) {
		rcu_read_unlock();
		/* Cold start — no marker yet.  If the rule carries a
		 * static init pool, spray from it (biased toward known-
		 * alive doors via per-door cts); otherwise count
		 * spray_no_master and pass through. */
		if (wga_pick_init_and_rewrite(skb, iph, udph, info, net))
			atomic_inc(&wga_stat_spray_init_rewrote);
		else
			atomic_inc(&wga_stat_spray_no_master);
		return XT_CONTINUE;
	}

	/* Master exists.  v10.1 pipeline:
	 *   1. Pre-spray GC: drop pool slots whose per-door ct has
	 *      expired (the slot was tried — last_seen_q8 > 0 — but
	 *      no kernel ct exists anymore).
	 *   2. Gated seed: only on handshake / keepalive / fresh
	 *      master.  Avoids the v10.0 "init seed keeps getting
	 *      re-inserted post-eviction" thrashing.
	 *   3. Pick + rewrite, with DATA-spray applying a per-door-ct
	 *      eligibility filter to avoid dead doors.  Handshakes
	 *      (INIT / RESP / COOKIE) keep using the full-pool random
	 *      picker since they're meant to probe.
	 */
	wga_run_pool_gc(net, master, iph, udph);

	if (wga_should_seed(master, &pi, info))
		wga_seed_master_from_init(master, info);

	if (pi.wg_type == WG_TYPE_DATA) {
		if (wga_pick_for_data_and_rewrite(skb, iph, udph, master, net))
			atomic_inc(&wga_stat_spray_rewrote);
		else
			atomic_inc(&wga_stat_spray_no_rewrite);
	} else {
		if (wga_pick_and_rewrite(skb, iph, udph, master))
			atomic_inc(&wga_stat_spray_rewrote);
		else
			atomic_inc(&wga_stat_spray_no_rewrite);
	}
	rcu_read_unlock();

	return XT_CONTINUE;
}

/* Per-rule payload `struct xt_wganycast_info` carries optional
 * `--init-pool` entries.  targetsize > 0 is mandatory in revision
 * 1 — v9's argument-less revision 0 was retired.
 */
struct xt_target xt_wganycast_targets[] __read_mostly = {
	{
		.name		= "WGANYCAST",
		.revision	= 1,
		.family		= NFPROTO_IPV4,
		.target		= wganycast_target_v4,
		.targetsize	= sizeof(struct xt_wganycast_info),
		.me		= THIS_MODULE,
	},
};
const unsigned int xt_wganycast_targets_n = ARRAY_SIZE(xt_wganycast_targets);

int xt_wganycast_module_init(void)
{
	int rc;

	wga_helper.me = THIS_MODULE;
	rc = nf_conntrack_helper_register(&wga_helper);
	if (rc)
		return rc;

	wga_stats_proc = proc_create("wganycast_stats", 0444,
				     init_net.proc_net, &wga_stats_pops);
	if (!wga_stats_proc)
		pr_warn("xt_wg: failed to create /proc/net/wganycast_stats\n");
	return 0;
}

void xt_wganycast_module_exit(void)
{
	if (wga_stats_proc)
		proc_remove(wga_stats_proc);
	nf_conntrack_helper_unregister(&wga_helper);
}
