// SPDX-License-Identifier: GPL-2.0-only
/*
 * Author: Bingchen Gong <gongbingchen@gmail.com>
 *
 * xt_WGANYCAST v3.2 — dynamic anycast pool via inline per-anchor
 * storage in the helper extension's 32-byte data area.
 * See xt_WGANYCAST.h for protocol semantics.
 *
 * Use:
 *
 *   # raw PREROUTING — observe inbound WG packets, refresh-or-insert
 *   # the source (anycast_ip, sport) into the per-session anchor's
 *   # inline pool array
 *   iptables -t raw -A PREROUTING -p udp --dport 51821 -j WGANYCAST --learn
 *
 *   # raw OUTPUT — spray outbound WG packets across the pool array
 *   iptables -t raw -A OUTPUT -p udp --sport 51821 -j WGANYCAST --spray
 *
 * No per-rule pool configuration; per-session anchors are allocated
 * dynamically at RESP observation and self-reap via standard conntrack
 * GC after WG REJECT_AFTER_TIME (+ 20 s buffer).
 *
 * A no-op `nf_conntrack_helper` is registered globally — `data_len`
 * tells the helper extension allocator to expose its 32-byte
 * `nf_conn_help->data[]` area to us.  We do NOT use
 * nf_conntrack_expect at all; the pool array lives inline in that
 * 32-byte area.  The helper's tuple matches UDP port 0 (never used by
 * real flows), so the auto-attach path never fires.  We assign the
 * helper to our synthetic anchors manually after
 * `nf_ct_helper_ext_add` to mark them as ours (used during
 * helper_unregister at module exit).
 */

#include <linux/version.h>
#include <linux/module.h>
#include <linux/random.h>
#include <linux/skbuff.h>
#include <linux/spinlock.h>
#include <linux/unaligned.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/netfilter/x_tables.h>
#include <linux/netfilter_ipv4/ip_tables.h>
#include <net/checksum.h>
#include <net/ip.h>
#include <net/udp.h>
#include <net/net_namespace.h>
#include <net/netfilter/nf_conntrack.h>
#include <net/netfilter/nf_conntrack_core.h>
#include <net/netfilter/nf_conntrack_helper.h>
#include <net/netfilter/nf_conntrack_zones.h>
#include "xt_WGANYCAST.h"
#include "xt_wg_common.h"
#include "wg.h"

/* ------------------------------------------------------------------
 *   Observability counters — /proc/net/wganycast_stats
 * ------------------------------------------------------------------ */
static atomic_t wga_stat_learn_total          = ATOMIC_INIT(0);
static atomic_t wga_stat_learn_parse_fail     = ATOMIC_INIT(0);
static atomic_t wga_stat_learn_resp           = ATOMIC_INIT(0);
static atomic_t wga_stat_learn_data           = ATOMIC_INIT(0);
static atomic_t wga_stat_learn_cookie         = ATOMIC_INIT(0);
static atomic_t wga_stat_learn_init_skip      = ATOMIC_INIT(0);
static atomic_t wga_stat_anchor_missing       = ATOMIC_INIT(0);
static atomic_t wga_stat_anchor_created       = ATOMIC_INIT(0);
static atomic_t wga_stat_anchor_create_fail   = ATOMIC_INIT(0);
static atomic_t wga_stat_pool_match_refresh   = ATOMIC_INIT(0);
static atomic_t wga_stat_pool_insert_append   = ATOMIC_INIT(0);
static atomic_t wga_stat_pool_insert_evict    = ATOMIC_INIT(0);
static atomic_t wga_stat_spray_total          = ATOMIC_INIT(0);
static atomic_t wga_stat_spray_resp           = ATOMIC_INIT(0);
static atomic_t wga_stat_spray_data           = ATOMIC_INIT(0);
static atomic_t wga_stat_spray_anchor_missing = ATOMIC_INIT(0);
static atomic_t wga_stat_spray_rewrote        = ATOMIC_INIT(0);
static atomic_t wga_stat_spray_no_rewrite     = ATOMIC_INIT(0);

static int wga_stats_show(struct seq_file *s, void *v)
{
	seq_printf(s, "learn_total           %d\n", atomic_read(&wga_stat_learn_total));
	seq_printf(s, "learn_parse_fail      %d\n", atomic_read(&wga_stat_learn_parse_fail));
	seq_printf(s, "learn_resp            %d\n", atomic_read(&wga_stat_learn_resp));
	seq_printf(s, "learn_data            %d\n", atomic_read(&wga_stat_learn_data));
	seq_printf(s, "learn_cookie          %d\n", atomic_read(&wga_stat_learn_cookie));
	seq_printf(s, "learn_init_skip       %d\n", atomic_read(&wga_stat_learn_init_skip));
	seq_printf(s, "anchor_missing        %d\n", atomic_read(&wga_stat_anchor_missing));
	seq_printf(s, "anchor_created        %d\n", atomic_read(&wga_stat_anchor_created));
	seq_printf(s, "anchor_create_fail    %d\n", atomic_read(&wga_stat_anchor_create_fail));
	seq_printf(s, "pool_match_refresh    %d\n", atomic_read(&wga_stat_pool_match_refresh));
	seq_printf(s, "pool_insert_append    %d\n", atomic_read(&wga_stat_pool_insert_append));
	seq_printf(s, "pool_insert_evict     %d\n", atomic_read(&wga_stat_pool_insert_evict));
	seq_printf(s, "spray_total           %d\n", atomic_read(&wga_stat_spray_total));
	seq_printf(s, "spray_resp            %d\n", atomic_read(&wga_stat_spray_resp));
	seq_printf(s, "spray_data            %d\n", atomic_read(&wga_stat_spray_data));
	seq_printf(s, "spray_anchor_missing  %d\n", atomic_read(&wga_stat_spray_anchor_missing));
	seq_printf(s, "spray_rewrote         %d\n", atomic_read(&wga_stat_spray_rewrote));
	seq_printf(s, "spray_no_rewrite      %d\n", atomic_read(&wga_stat_spray_no_rewrite));
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

/* Anchor lifetime — matches WG REJECT_AFTER_TIME + 20 s buffer.
 * The fixed timeout combined with IPS_FIXED_TIMEOUT_BIT prevents
 * any refresh path from extending it.  Standard conntrack GC reaps
 * the anchor (and its inline pool, which lives inside the help
 * extension on the same nf_conn) once the timeout fires.
 */
#define WGA_ANCHOR_TIMEOUT_SEC	200u

/* --------------------------------------------------------------------
 *   Inline pool — lives in nf_conn_help->data[32]
 *
 *   Each entry is 8 bytes packed; 4 entries fill the 32-byte area
 *   exactly.  An empty slot is marked by ip == 0 (no need for an
 *   explicit count field).  Per-entry last_seen is a 16-bit truncated
 *   tick value derived from `jiffies >> WGA_TIME_SHIFT` — the shift
 *   stretches the wrap window to ~524 s at HZ=1000, giving a 262 s
 *   half-window for unambiguous LRU compare that comfortably exceeds
 *   the 200 s anchor lifetime.
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

static inline __u16 wga_now_q8(void)
{
	return (__u16)(jiffies >> WGA_TIME_SHIFT);
}

static inline struct wga_pool_inline *wga_pool_of(struct nf_conn *anchor)
{
	return (struct wga_pool_inline *)nfct_help_data(anchor);
}

/* --------------------------------------------------------------------
 *   No-op helper.
 *
 *   `.help` is non-NULL only because the helper API requires it;
 *   it never fires for real packets (synthetic dst.port=0 prevents
 *   auto-attach).  `.data_len` claims the full 32 bytes of
 *   `nf_conn_help->data[]` for our inline pool.  No .destroy
 *   callback — the pool is freed automatically as part of the help
 *   extension when the anchor `nf_conn` is destroyed.
 * -------------------------------------------------------------------- */

static int wganycast_help_noop(struct sk_buff *skb, unsigned int protoff,
			       struct nf_conn *ct,
			       enum ip_conntrack_info ctinfo)
{
	return NF_ACCEPT;
}

/* Even though we never call nf_ct_expect_related, the kernel's
 * nf_conntrack_helper_register() asserts at registration time that
 * a helper has a non-NULL expect_policy.  Provide a minimal stub
 * (max_expected = 0) so registration succeeds.  Never actually used
 * — we don't call into the expect API anywhere in v3.2. */
static const struct nf_conntrack_expect_policy wganycast_exp_policy = {
	.max_expected = 0,
	.timeout      = 0,
	.name         = "default",
};

static struct nf_conntrack_helper wganycast_helper __read_mostly = {
	.name = "WGANYCAST",
	.tuple = {
		.src.l3num      = AF_INET,
		.dst.protonum   = IPPROTO_UDP,
		.dst.u.udp.port = 0,	/* never-match port */
	},
	.expect_class_max = 0,
	.expect_policy    = &wganycast_exp_policy,
	.help             = wganycast_help_noop,
	.data_len         = sizeof(struct wga_pool_inline),
};

/* --------------------------------------------------------------------
 *   WG packet parsing
 * -------------------------------------------------------------------- */

struct wga_pkt_info {
	u8	wg_type;
	__le32	sender_idx;	/* valid for INIT, RESP */
	__le32	receiver_idx;	/* valid for RESP, COOKIE, DATA */
};

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

	info->wg_type = wg_type;
	*iph_out  = iph;
	*udph_out = udph;
	return true;
}

/* --------------------------------------------------------------------
 *   Synthetic-tuple helpers
 *
 * Anchor tuples encode session indices in dst.u3.ip:
 *   ORIGINAL.dst.u3.ip = our_idx_as_be32
 *   REPLY   .dst.u3.ip = peer_idx_as_be32
 * Both directions share src = (Sa_ip, Sa_port), proto = UDP, dst.port = 0.
 * -------------------------------------------------------------------- */

static void wga_build_tuple(struct nf_conntrack_tuple *t,
			    __be32 sa_ip, __be16 sa_port,
			    __le32 idx, u8 dir)
{
	memset(t, 0, sizeof(*t));
	t->src.l3num         = AF_INET;
	t->src.u3.ip         = sa_ip;
	t->src.u.udp.port    = sa_port;
	t->dst.u3.ip         = (__force __be32)idx;
	t->dst.u.udp.port    = 0;
	t->dst.protonum      = IPPROTO_UDP;
	t->dst.dir           = dir;
}

/* --------------------------------------------------------------------
 *   Anchor lifecycle
 * -------------------------------------------------------------------- */

static struct nf_conn *wga_lookup_anchor(struct net *net,
					 __be32 sa_ip, __be16 sa_port,
					 __le32 idx)
{
	struct nf_conntrack_tuple t;
	struct nf_conntrack_tuple_hash *h;

	wga_build_tuple(&t, sa_ip, sa_port, idx, IP_CT_DIR_ORIGINAL);
	h = nf_conntrack_find_get(net, &nf_ct_zone_dflt, &t);
	if (!h)
		return NULL;
	return nf_ct_tuplehash_to_ctrack(h);
}

static struct nf_conn *wga_create_anchor(struct net *net,
					 __be32 sa_ip, __be16 sa_port,
					 __le32 our_idx, __le32 peer_idx)
{
	struct nf_conntrack_tuple orig, repl;
	struct nf_conn *anchor;
	struct nf_conn_help *help;

	wga_build_tuple(&orig, sa_ip, sa_port, our_idx, IP_CT_DIR_ORIGINAL);
	wga_build_tuple(&repl, sa_ip, sa_port, peer_idx, IP_CT_DIR_REPLY);

	anchor = nf_conntrack_alloc(net, &nf_ct_zone_dflt, &orig, &repl,
				    GFP_ATOMIC);
	if (IS_ERR_OR_NULL(anchor)) {
		atomic_inc(&wga_stat_anchor_create_fail);
		return NULL;
	}

	/* Allocate the help extension to expose its zero-initialised
	 * 32-byte data[] area for our pool.  nf_ct_ext_add zeroes new
	 * extension memory, so every slot starts with ip == 0 (free). */
	help = nf_ct_helper_ext_add(anchor, GFP_ATOMIC);
	if (!help) {
		atomic_inc(&wga_stat_anchor_create_fail);
		nf_conntrack_free(anchor);
		return NULL;
	}

	/* Mark this anchor as ours.  Setting help->helper is what
	 * nf_conntrack_helper_unregister() walks for at module exit so
	 * the helper pointer is detached before the module is freed. */
	rcu_assign_pointer(help->helper, &wganycast_helper);

	set_bit(IPS_CONFIRMED_BIT,     &anchor->status);
	set_bit(IPS_FIXED_TIMEOUT_BIT, &anchor->status);
	WRITE_ONCE(anchor->timeout, jiffies + WGA_ANCHOR_TIMEOUT_SEC * HZ);

	if (nf_conntrack_hash_check_insert(anchor)) {
		/* Lost an allocate-race; the winning anchor is findable
		 * via wga_lookup_anchor in the caller. */
		atomic_inc(&wga_stat_anchor_create_fail);
		nf_conntrack_free(anchor);
		return NULL;
	}

	atomic_inc(&wga_stat_anchor_created);
	return anchor;
}

static struct nf_conn *wga_lookup_or_create_anchor(struct net *net,
						   __be32 sa_ip, __be16 sa_port,
						   __le32 our_idx, __le32 peer_idx)
{
	struct nf_conn *ct;

	ct = wga_lookup_anchor(net, sa_ip, sa_port, our_idx);
	if (ct)
		return ct;
	ct = wga_create_anchor(net, sa_ip, sa_port, our_idx, peer_idx);
	if (ct)
		return ct;
	return wga_lookup_anchor(net, sa_ip, sa_port, our_idx);
}

/* --------------------------------------------------------------------
 *   Pool maintenance — inline array in help->data[]
 *
 *   wga_learn_door: refresh existing entry, append into free slot, or
 *   evict the LRU (smallest last_seen, wrap-aware unsigned compare).
 *   Serialised via the anchor `nf_conn`'s own spinlock.
 * -------------------------------------------------------------------- */

static void wga_learn_door(struct nf_conn *anchor,
			   __be32 anycast_ip, __be16 anycast_port)
{
	struct wga_pool_inline *p = wga_pool_of(anchor);
	int i, free_idx = -1, oldest_idx = -1;
	__u16 now_q8 = wga_now_q8();
	__u16 oldest_age = 0;

	if (!p)
		return;

	spin_lock_bh(&anchor->lock);

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
			spin_unlock_bh(&anchor->lock);
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

	spin_unlock_bh(&anchor->lock);
}

/* --------------------------------------------------------------------
 *   Pick from pool + rewrite outbound packet
 *
 *   Snapshot the live entries under the anchor lock, then do the
 *   random pick + checksum rewrite unlocked.  Short critical section.
 * -------------------------------------------------------------------- */

static bool wga_pick_and_rewrite(struct sk_buff *skb,
				 struct iphdr *iph, struct udphdr *udph,
				 struct nf_conn *anchor)
{
	struct wga_pool_inline *p = wga_pool_of(anchor);
	struct wga_pool_entry candidates[WGA_POOL_SIZE];
	int i, n = 0;
	__be32 old_addr, new_addr;
	__be16 old_port, new_port;
	u32 pick;

	if (!p)
		return false;

	spin_lock_bh(&anchor->lock);
	for (i = 0; i < WGA_POOL_SIZE; i++) {
		if (p->slot[i].ip != 0)
			candidates[n++] = p->slot[i];
	}
	spin_unlock_bh(&anchor->lock);

	if (n == 0)
		return false;

	pick     = get_random_u32_below((u32)n);
	new_addr = candidates[pick].ip;
	new_port = candidates[pick].port;
	old_addr = iph->daddr;
	old_port = udph->dest;

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
	return true;
}

/* --------------------------------------------------------------------
 *   LEARN handler — raw PREROUTING, priority -300
 * -------------------------------------------------------------------- */

static unsigned int wganycast_learn_v4(struct sk_buff *skb, struct net *net)
{
	struct wga_pkt_info pi;
	struct iphdr *iph;
	struct udphdr *udph;
	struct nf_conn *anchor;
	__be32 sa_ip, anycast_ip;
	__be16 sa_port, anycast_port;
	__le32 our_idx, peer_idx;

	atomic_inc(&wga_stat_learn_total);

	if (!wga_parse_packet(skb, &pi, &iph, &udph)) {
		atomic_inc(&wga_stat_learn_parse_fail);
		return XT_CONTINUE;
	}

	sa_ip        = iph->daddr;
	sa_port      = udph->dest;
	anycast_ip   = iph->saddr;
	anycast_port = udph->source;

	switch (pi.wg_type) {
	case WG_TYPE_RESP:
		atomic_inc(&wga_stat_learn_resp);
		our_idx  = pi.receiver_idx;
		peer_idx = pi.sender_idx;
		anchor = wga_lookup_or_create_anchor(net, sa_ip, sa_port,
						     our_idx, peer_idx);
		break;
	case WG_TYPE_DATA:
		atomic_inc(&wga_stat_learn_data);
		our_idx = pi.receiver_idx;
		anchor = wga_lookup_anchor(net, sa_ip, sa_port, our_idx);
		break;
	case WG_TYPE_COOKIE:
		atomic_inc(&wga_stat_learn_cookie);
		our_idx = pi.receiver_idx;
		anchor = wga_lookup_anchor(net, sa_ip, sa_port, our_idx);
		break;
	default:
		if (pi.wg_type == WG_TYPE_INIT)
			atomic_inc(&wga_stat_learn_init_skip);
		return XT_CONTINUE;
	}

	if (!anchor) {
		atomic_inc(&wga_stat_anchor_missing);
		return XT_CONTINUE;
	}

	wga_learn_door(anchor, anycast_ip, anycast_port);
	nf_ct_put(anchor);
	return XT_CONTINUE;
}

/* --------------------------------------------------------------------
 *   SPRAY handler — raw OUTPUT, priority -300
 * -------------------------------------------------------------------- */

static unsigned int wganycast_spray_v4(struct sk_buff *skb, struct net *net)
{
	struct wga_pkt_info pi;
	struct iphdr *iph;
	struct udphdr *udph;
	struct nf_conn *anchor;
	__be32 sa_ip;
	__be16 sa_port;
	__le32 idx;
	bool did_rewrite;

	atomic_inc(&wga_stat_spray_total);

	if (!wga_parse_packet(skb, &pi, &iph, &udph))
		return XT_CONTINUE;

	sa_ip   = iph->saddr;
	sa_port = udph->source;

	switch (pi.wg_type) {
	case WG_TYPE_RESP:
		atomic_inc(&wga_stat_spray_resp);
		anchor = wga_lookup_or_create_anchor(net, sa_ip, sa_port,
						     pi.sender_idx, pi.receiver_idx);
		break;
	case WG_TYPE_DATA:
		atomic_inc(&wga_stat_spray_data);
		idx = pi.receiver_idx;
		anchor = wga_lookup_anchor(net, sa_ip, sa_port, idx);
		break;
	case WG_TYPE_COOKIE:
		idx = pi.receiver_idx;
		anchor = wga_lookup_anchor(net, sa_ip, sa_port, idx);
		break;
	default:
		return XT_CONTINUE;
	}

	if (!anchor) {
		atomic_inc(&wga_stat_spray_anchor_missing);
		return XT_CONTINUE;
	}

	did_rewrite = wga_pick_and_rewrite(skb, iph, udph, anchor);
	if (did_rewrite)
		atomic_inc(&wga_stat_spray_rewrote);
	else
		atomic_inc(&wga_stat_spray_no_rewrite);
	nf_ct_put(anchor);
	return XT_CONTINUE;
}

/* --------------------------------------------------------------------
 *   Target dispatcher
 * -------------------------------------------------------------------- */

static unsigned int wganycast_target(struct sk_buff *skb,
				     const struct xt_action_param *par)
{
	const struct xt_wganycast_info *info = par->targinfo;
	struct net *net = par->state->net;

	if (info->mode == XT_WGANYCAST_MODE_LEARN)
		return wganycast_learn_v4(skb, net);
	if (info->mode == XT_WGANYCAST_MODE_SPRAY)
		return wganycast_spray_v4(skb, net);
	return XT_CONTINUE;
}

static int wganycast_checkentry(const struct xt_tgchk_param *par)
{
	const struct xt_wganycast_info *info = par->targinfo;

	if (info->mode != XT_WGANYCAST_MODE_LEARN &&
	    info->mode != XT_WGANYCAST_MODE_SPRAY)
		return -EINVAL;
	return 0;
}

/* Target array exposed to xt_wg_main.c.  Helper registration is
 * driven by xt_wganycast_module_init / _exit, also called from
 * xt_wg_main.c.
 */
struct xt_target xt_wganycast_targets[] __read_mostly = {
	{
		.name		= "WGANYCAST",
		.revision	= 0,
		.family		= NFPROTO_IPV4,
		.target		= wganycast_target,
		.targetsize	= sizeof(struct xt_wganycast_info),
		.checkentry	= wganycast_checkentry,
		.me		= THIS_MODULE,
	},
};
const unsigned int xt_wganycast_targets_n = ARRAY_SIZE(xt_wganycast_targets);

int xt_wganycast_module_init(void)
{
	int rc;

	wganycast_helper.me = THIS_MODULE;
	rc = nf_conntrack_helper_register(&wganycast_helper);
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
	nf_conntrack_helper_unregister(&wganycast_helper);
}
