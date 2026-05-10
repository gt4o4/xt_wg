// SPDX-License-Identifier: GPL-2.0-only
/*
 * xt_WGANYCAST kernel module — see xt_WGANYCAST.h for protocol semantics.
 *
 * Use:
 *
 *   # spray WG outbound across two anycast IPs (port preserved)
 *   iptables -t mangle -A OUTPUT -p udp --dport 51821 -d 193.134.211.67 \
 *     -j WGANYCAST --dest 161.248.136.186 --dest 138.252.162.176
 *
 *   # spray with port rewrite (gateway maps anycast :59263 → backend :51821)
 *   iptables -t mangle -A OUTPUT -p udp --dport 51821 -d 193.134.211.67 \
 *     -j WGANYCAST --dest 161.248.136.186:59263 --dest 138.252.162.176:59263
 *
 *   # canonicalise replies so WG sees a single peer endpoint
 *   iptables -t mangle -A PREROUTING -p udp --sport 59263 -s 138.252.162.176 \
 *     -j WGANYCAST --canonical 193.134.211.67:51821
 */

#include <linux/version.h>
#include <linux/module.h>
#include <linux/random.h>
#include <linux/skbuff.h>
#include <linux/netfilter/x_tables.h>
#include <linux/netfilter_ipv4/ip_tables.h>
#include <net/checksum.h>
#include <net/ip.h>
#include <net/udp.h>
#include "xt_WGANYCAST.h"

static unsigned int wganycast_target(struct sk_buff *skb,
				     const struct xt_action_param *par)
{
	const struct xt_wganycast_info *info = par->targinfo;
	struct iphdr *iph;
	struct udphdr *udph;
	__be32 old_addr, new_addr;
	__be16 old_port, new_port;
	unsigned int idx;

	if (skb_ensure_writable(skb, skb_network_offset(skb) + sizeof(*iph) +
				     sizeof(*udph)))
		return NF_DROP;

	iph = ip_hdr(skb);
	if (iph->protocol != IPPROTO_UDP)
		return XT_CONTINUE;

	if (ntohs(iph->tot_len) < (iph->ihl * 4) + sizeof(*udph))
		return XT_CONTINUE;

	udph = (struct udphdr *)((u8 *)iph + iph->ihl * 4);

	if (info->mode == XT_WGANYCAST_MODE_SPRAY) {
		if (info->ndests == 0)
			return XT_CONTINUE;
		/* Uniform random per-packet selection. Stateless — no
		 * per-rule counter to coordinate across CPUs.
		 */
		idx = get_random_u32() % info->ndests;
		new_addr = info->dests[idx].ip;
		new_port = info->dests[idx].port;
		old_addr = iph->daddr;
		old_port = udph->dest;

		if (new_addr != old_addr) {
			iph->daddr = new_addr;
			csum_replace4(&iph->check, old_addr, new_addr);
			if (udph->check)
				inet_proto_csum_replace4(&udph->check, skb,
							 old_addr, new_addr,
							 true);
		}
		if (new_port && new_port != old_port) {
			udph->dest = new_port;
			if (udph->check)
				inet_proto_csum_replace2(&udph->check, skb,
							 old_port, new_port,
							 false);
		}
	} else if (info->mode == XT_WGANYCAST_MODE_CANONICAL) {
		new_addr = info->dests[0].ip;
		new_port = info->dests[0].port;
		old_addr = iph->saddr;
		old_port = udph->source;

		if (new_addr != old_addr) {
			iph->saddr = new_addr;
			csum_replace4(&iph->check, old_addr, new_addr);
			if (udph->check)
				inet_proto_csum_replace4(&udph->check, skb,
							 old_addr, new_addr,
							 true);
		}
		if (new_port && new_port != old_port) {
			udph->source = new_port;
			if (udph->check)
				inet_proto_csum_replace2(&udph->check, skb,
							 old_port, new_port,
							 false);
		}
	}

	return XT_CONTINUE;
}

static int wganycast_checkentry(const struct xt_tgchk_param *par)
{
	const struct xt_wganycast_info *info = par->targinfo;

	if (info->mode != XT_WGANYCAST_MODE_SPRAY &&
	    info->mode != XT_WGANYCAST_MODE_CANONICAL)
		return -EINVAL;

	if (info->ndests == 0 || info->ndests > XT_WGANYCAST_MAX_DESTS)
		return -EINVAL;

	if (info->mode == XT_WGANYCAST_MODE_CANONICAL && info->ndests != 1)
		return -EINVAL;

	return 0;
}

static struct xt_target xt_wganycast_reg[] __read_mostly = {
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

static int __init xt_wganycast_init(void)
{
	return xt_register_targets(xt_wganycast_reg,
				   ARRAY_SIZE(xt_wganycast_reg));
}

static void __exit xt_wganycast_exit(void)
{
	xt_unregister_targets(xt_wganycast_reg,
			      ARRAY_SIZE(xt_wganycast_reg));
}

module_init(xt_wganycast_init);
module_exit(xt_wganycast_exit);
MODULE_LICENSE("GPL v2");
MODULE_DESCRIPTION("xtables target: stateless UDP destination spray + source canonicalisation");
MODULE_ALIAS("ipt_WGANYCAST");
