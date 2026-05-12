// SPDX-License-Identifier: GPL-2.0-only
/*
 * Author: Bingchen Gong <gongbingchen@gmail.com>
 *
 * xt_WGANYCAST v3 — dynamic anycast pool via conntrack-as-registry.
 * See xt_WGANYCAST.h for protocol semantics.
 *
 * Use:
 *
 *   # raw PREROUTING — observe inbound WG packets, register/refresh
 *   # permanent expectations under the per-session anchor conntrack
 *   iptables -t raw -A PREROUTING -p udp --dport 51821 -j WGANYCAST --learn
 *
 *   # raw OUTPUT — spray outbound WG packets across the learned pool
 *   iptables -t raw -A OUTPUT -p udp --sport 51821 -j WGANYCAST --spray
 *
 * No per-rule pool configuration; per-session anchors are allocated
 * dynamically at RESP observation and self-reap via standard conntrack
 * GC after WG REJECT_AFTER_TIME (+ 20 s buffer).
 *
 * A no-op `nf_conntrack_helper` is registered globally — the kernel's
 * expectation API requires `master_help->helper` to be non-NULL.  The
 * helper's tuple matches UDP port 0 (never used by real flows), so
 * the auto-attach path effectively never fires.  We assign the helper
 * to our synthetic anchors manually after `nf_ct_helper_ext_add`.
 */

#include <linux/version.h>
#include <linux/module.h>
#include <linux/random.h>
#include <linux/skbuff.h>
#include <linux/unaligned.h>
#include <linux/refcount.h>
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
#include <net/netfilter/nf_conntrack_expect.h>
#include <net/netfilter/nf_conntrack_helper.h>
#include <net/netfilter/nf_conntrack_zones.h>
#include "xt_WGANYCAST.h"
#include "xt_wg_common.h"
#include "wg.h"

/* ------------------------------------------------------------------
 *   DEBUG instrumentation — temporary, revert after diagnose.
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
static atomic_t wga_stat_exp_helper_null      = ATOMIC_INIT(0);
static atomic_t wga_stat_exp_refresh          = ATOMIC_INIT(0);
static atomic_t wga_stat_exp_alloc_fail       = ATOMIC_INIT(0);
static atomic_t wga_stat_exp_add_success      = ATOMIC_INIT(0);
static atomic_t wga_stat_exp_add_eexist       = ATOMIC_INIT(0);
static atomic_t wga_stat_exp_add_ebusy        = ATOMIC_INIT(0);
static atomic_t wga_stat_exp_add_other_err    = ATOMIC_INIT(0);
static atomic_t wga_stat_exp_evict            = ATOMIC_INIT(0);
static atomic_t wga_stat_pool_migrated_entries = ATOMIC_INIT(0);
static atomic_t wga_stat_pool_migrate_calls   = ATOMIC_INIT(0);
static atomic_t wga_stat_pool_migrate_skipped = ATOMIC_INIT(0);
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
	seq_printf(s, "exp_helper_null       %d\n", atomic_read(&wga_stat_exp_helper_null));
	seq_printf(s, "exp_refresh           %d\n", atomic_read(&wga_stat_exp_refresh));
	seq_printf(s, "exp_alloc_fail        %d\n", atomic_read(&wga_stat_exp_alloc_fail));
	seq_printf(s, "exp_add_success       %d\n", atomic_read(&wga_stat_exp_add_success));
	seq_printf(s, "exp_add_eexist        %d\n", atomic_read(&wga_stat_exp_add_eexist));
	seq_printf(s, "exp_add_ebusy         %d\n", atomic_read(&wga_stat_exp_add_ebusy));
	seq_printf(s, "exp_add_other_err     %d\n", atomic_read(&wga_stat_exp_add_other_err));
	seq_printf(s, "exp_evict             %d\n", atomic_read(&wga_stat_exp_evict));
	seq_printf(s, "pool_migrate_calls    %d\n", atomic_read(&wga_stat_pool_migrate_calls));
	seq_printf(s, "pool_migrate_skipped  %d\n", atomic_read(&wga_stat_pool_migrate_skipped));
	seq_printf(s, "pool_migrated_entries %d\n", atomic_read(&wga_stat_pool_migrated_entries));
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
 * the anchor (and its expectations, via nf_ct_remove_expectations)
 * once the timeout fires.
 */
#define WGA_ANCHOR_TIMEOUT_SEC	200u
#define WGA_EXPECT_TIMEOUT_SEC	WGA_ANCHOR_TIMEOUT_SEC

/* --------------------------------------------------------------------
 *   No-op helper — satisfies kernel's helper-required check in
 *   __nf_ct_expect_check.  No per-packet work; never auto-attaches
 *   to real flows (matches UDP port 0).
 * -------------------------------------------------------------------- */

static int wganycast_help_noop(struct sk_buff *skb, unsigned int protoff,
			       struct nf_conn *ct,
			       enum ip_conntrack_info ctinfo)
{
	return NF_ACCEPT;
}

static const struct nf_conntrack_expect_policy wganycast_exp_policy = {
	.max_expected	= XT_WGANYCAST_POOL_MAX,
	.timeout	= WGA_EXPECT_TIMEOUT_SEC,
	.name		= "default",
};

static struct nf_conntrack_helper wganycast_helper __read_mostly = {
	.name			= "WGANYCAST",
	.tuple = {
		.src.l3num	= AF_INET,
		.dst.protonum	= IPPROTO_UDP,
		.dst.u.udp.port	= 0,	/* never-match port */
	},
	.expect_class_max	= 0,	/* single default class */
	.expect_policy		= &wganycast_exp_policy,
	.help			= wganycast_help_noop,
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

	help = nf_ct_helper_ext_add(anchor, GFP_ATOMIC);
	if (!help) {
		atomic_inc(&wga_stat_anchor_create_fail);
		nf_conntrack_free(anchor);
		return NULL;
	}

	/* Attach the no-op helper so the kernel's __nf_ct_expect_check
	 * accepts expectations registered under this anchor.  We do NOT
	 * try_module_get(THIS_MODULE) here — modern kernels (≥5.16) no
	 * longer wire a destroy callback to the helper extension, so a
	 * matching module_put never fires and the refcount leaks.  Safety
	 * on module unload is instead guaranteed by
	 * nf_conntrack_helper_unregister() in xt_wganycast_module_exit:
	 * it walks all conntracks, detaches our helper pointer, and
	 * synchronize_rcu()s before returning so no CPU is still
	 * dereferencing the helper when the module is freed. */
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
 *   Pool inheritance on re-key clash
 *
 *   When a peer re-keys WG, our LEARN side creates a NEW anchor (new
 *   our_idx).  But CF Spectrum's UDP NAT mapping survives WG re-key
 *   (same client.NAT.IP:port → same CF backend port), so the new
 *   anchor's first add hits an `-EBUSY` clash with the *old* anchor
 *   that still holds the same (anycast_ip, anycast_port) tuple.
 *
 *   Rather than just losing the door, transfer the old anchor's whole
 *   pool to the new anchor in one move:
 *     - The conflicting tuple is now part of new's pool (the door we
 *       were trying to register).
 *     - Any other doors the peer was sending on are also inherited.
 *     - Old anchor is left with an empty pool; it expires harmlessly
 *       at its 200 s timeout.
 *
 *   Bounce protection: we only migrate FROM an older anchor TO a
 *   newer one (comparing absolute timeout, since IPS_FIXED_TIMEOUT_BIT
 *   keeps anchor->timeout stable).  Prevents ping-pong if both
 *   sessions are receiving traffic during the WG re-key overlap.
 * -------------------------------------------------------------------- */

static int wga_steal_pool(struct net *net,
			  const struct nf_conntrack_tuple *clash_tuple,
			  struct nf_conn *new_master)
{
	struct nf_conntrack_expect *conflict, *exp;
	struct nf_conn *old_master;
	struct nf_conn_help *old_help, *new_help;
	int moved = 0;

	atomic_inc(&wga_stat_pool_migrate_calls);

	conflict = nf_ct_expect_find_get(net, &nf_ct_zone_dflt, clash_tuple);
	if (!conflict)
		goto out_skip;
	if (conflict->master == new_master) {
		nf_ct_expect_put(conflict);
		goto out_skip;
	}
	old_master = conflict->master;
	if (!refcount_inc_not_zero(&old_master->ct_general.use)) {
		nf_ct_expect_put(conflict);
		goto out_skip;
	}

	spin_lock_bh(&nf_conntrack_expect_lock);

	/* Re-validate under lock — another CPU may have raced us. */
	if (conflict->master != old_master)
		goto out_unlock;

	old_help = nfct_help(old_master);
	new_help = nfct_help(new_master);
	if (!old_help || !new_help ||
	    rcu_access_pointer(old_help->helper) != &wganycast_helper)
		goto out_unlock;

	/* Migrate only toward the newer anchor (larger absolute timeout). */
	if (time_before(new_master->timeout, old_master->timeout))
		goto out_unlock;

	/* First pass: update each expectation's master pointer + refresh
	 * timer.  The lnodes still chain through old's list; we only
	 * touch fields the migration needs. */
	hlist_for_each_entry(exp, &old_help->expectations, lnode) {
		WRITE_ONCE(exp->master, new_master);
		mod_timer(&exp->timeout,
			  jiffies + WGA_EXPECT_TIMEOUT_SEC * HZ);
		moved++;
	}

	/* Bulk-move the list head when new is empty (the common case
	 * for a freshly-created anchor hitting -EBUSY on its first add).
	 * Otherwise splice per-entry to preserve new's existing entries. */
	if (hlist_empty(&new_help->expectations)) {
		hlist_move_list(&old_help->expectations,
				&new_help->expectations);
	} else {
		struct hlist_node *n;
		hlist_for_each_entry_safe(exp, n,
					  &old_help->expectations, lnode) {
			hlist_del_rcu(&exp->lnode);
			hlist_add_head_rcu(&exp->lnode,
					   &new_help->expectations);
		}
	}

	new_help->expecting[NF_CT_EXPECT_CLASS_DEFAULT] += moved;
	old_help->expecting[NF_CT_EXPECT_CLASS_DEFAULT] -= moved;

	atomic_add(moved, &wga_stat_pool_migrated_entries);

out_unlock:
	spin_unlock_bh(&nf_conntrack_expect_lock);
	nf_ct_put(old_master);
	nf_ct_expect_put(conflict);
	if (moved == 0)
		atomic_inc(&wga_stat_pool_migrate_skipped);
	return moved;

out_skip:
	atomic_inc(&wga_stat_pool_migrate_skipped);
	return 0;
}

/* --------------------------------------------------------------------
 *   Pool entry management — permanent expectations under the anchor
 * -------------------------------------------------------------------- */

static void wga_add_or_refresh_expectation(struct nf_conn *anchor,
					   __be32 anycast_ip, __be16 anycast_port,
					   __be32 sa_ip, __be16 sa_port)
{
	struct nf_conn_help *help = nfct_help(anchor);
	struct nf_conntrack_expect *exp, *match = NULL, *oldest = NULL;
	struct nf_conntrack_expect *evict = NULL;
	union nf_inet_addr src_addr = { .ip = anycast_ip };
	union nf_inet_addr dst_addr = { .ip = sa_ip };
	unsigned int count = 0;

	if (!help) {
		atomic_inc(&wga_stat_exp_helper_null);
		return;
	}

	spin_lock_bh(&nf_conntrack_expect_lock);
	hlist_for_each_entry(exp, &help->expectations, lnode) {
		count++;
		if (exp->tuple.src.u3.ip == anycast_ip &&
		    exp->tuple.src.u.udp.port == anycast_port)
			match = exp;
		if (!oldest ||
		    time_before(exp->timeout.expires, oldest->timeout.expires))
			oldest = exp;
	}

	if (match) {
		atomic_inc(&wga_stat_exp_refresh);
		mod_timer(&match->timeout,
			  jiffies + WGA_EXPECT_TIMEOUT_SEC * HZ);
		spin_unlock_bh(&nf_conntrack_expect_lock);
		return;
	}

	/* Need to insert a new entry.  If at capacity, hold a ref on
	 * the oldest now so we can safely call nf_ct_unexpect_related
	 * after dropping the lock. */
	if (count >= XT_WGANYCAST_POOL_MAX && oldest &&
	    refcount_inc_not_zero(&oldest->use)) {
		evict = oldest;
		atomic_inc(&wga_stat_exp_evict);
	}
	spin_unlock_bh(&nf_conntrack_expect_lock);

	if (evict)
		nf_ct_unexpect_related(evict);

	exp = nf_ct_expect_alloc(anchor);
	if (!exp) {
		atomic_inc(&wga_stat_exp_alloc_fail);
		return;
	}

	nf_ct_expect_init(exp, NF_CT_EXPECT_CLASS_DEFAULT, AF_INET,
			  &src_addr, &dst_addr,
			  IPPROTO_UDP, &anycast_port, &sa_port);
	exp->flags = NF_CT_EXPECT_PERMANENT;
	exp->helper = NULL;	/* children get no helper */
	exp->timeout.expires = jiffies + WGA_EXPECT_TIMEOUT_SEC * HZ;

	/* nf_ct_expect_related returns 0 on success or -EEXIST on
	 * dedup race.  -EBUSY means the global expect hashtable already
	 * has a clashing tuple under a different master (the pre-rekey
	 * predecessor anchor for this peer, almost always) — try to
	 * migrate that master's whole pool to us. */
	{
		int ret = nf_ct_expect_related(exp, 0);
		switch (ret) {
		case 0:
			atomic_inc(&wga_stat_exp_add_success);
			break;
		case -EEXIST:
		case -EALREADY:
			atomic_inc(&wga_stat_exp_add_eexist);
			break;
		case -EBUSY:
			atomic_inc(&wga_stat_exp_add_ebusy);
			wga_steal_pool(nf_ct_net(anchor), &exp->tuple, anchor);
			break;
		default:
			atomic_inc(&wga_stat_exp_add_other_err);
			pr_warn_ratelimited("xt_wg: nf_ct_expect_related returned %d for anycast=%pI4:%u\n",
					    ret, &anycast_ip, ntohs(anycast_port));
			break;
		}
	}
	nf_ct_expect_put(exp);
}

/* --------------------------------------------------------------------
 *   Pick from pool + rewrite outbound packet
 * -------------------------------------------------------------------- */

static bool wga_pick_and_rewrite(struct sk_buff *skb,
				 struct iphdr *iph, struct udphdr *udph,
				 struct nf_conn *anchor)
{
	struct nf_conn_help *help = nfct_help(anchor);
	struct nf_conntrack_expect *exp, *chosen = NULL;
	unsigned int count = 0, pick;
	__be32 old_addr = iph->daddr, new_addr = 0;
	__be16 old_port = udph->dest, new_port = 0;

	if (!help)
		return false;

	spin_lock_bh(&nf_conntrack_expect_lock);
	hlist_for_each_entry(exp, &help->expectations, lnode)
		count++;
	if (count == 0) {
		spin_unlock_bh(&nf_conntrack_expect_lock);
		return false;
	}

	pick = get_random_u32_below(count);
	count = 0;
	hlist_for_each_entry(exp, &help->expectations, lnode) {
		if (count++ == pick) {
			chosen = exp;
			new_addr = chosen->tuple.src.u3.ip;
			new_port = chosen->tuple.src.u.udp.port;
			break;
		}
	}
	spin_unlock_bh(&nf_conntrack_expect_lock);

	if (!chosen)
		return false;

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

	wga_add_or_refresh_expectation(anchor, anycast_ip, anycast_port,
				       sa_ip, sa_port);
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
