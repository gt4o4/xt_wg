// SPDX-License-Identifier: GPL-2.0-only
/*
 * xt_WGPTCP — stateless UDP→fake-TCP-SYN encode + reverse decode.
 *
 *   # encode outbound WG/UDP to fake TCP SYN+TFO
 *   iptables -t mangle -A OUTPUT -p udp -d <peer>/32 --dport 51821 \
 *       -j WGPTCP --encode --key <32-hex>
 *
 *   # decode inbound fake TCP back to UDP — MUST be in raw PREROUTING
 *   # (priority -300, before conntrack at -200) so kernel TCP stack
 *   # never sees the fake TCP packet
 *   iptables -t raw -A PREROUTING -p tcp -s <peer>/32 --sport 51821 --syn \
 *       -j WGPTCP --decode --key <32-hex>
 */

#include <linux/version.h>
#include <linux/module.h>
#include <linux/random.h>
#include <linux/siphash.h>
#include <linux/skbuff.h>
#include <linux/string.h>
#include <linux/netfilter/x_tables.h>
#include <linux/netfilter_ipv4/ip_tables.h>
#include <net/checksum.h>
#include <net/ip.h>
#include <net/tcp.h>
#include <net/udp.h>
#include "xt_WGPTCP.h"

/* Wire layout: TCP base header (20) + 8 bytes options
 *   bytes 0..1: NOP NOP	(kind=1 each, 1 byte each — 4-byte alignment pad)
 *   bytes 2..3: TFO_COOKIE	(kind=34, len=6)
 *   bytes 4..7: 4-byte cookie value
 */
#define WGPTCP_TCP_HDR_LEN	28u	/* 20 base + 8 opts */
#define WGPTCP_TCP_DOFF		7u	/* 28 / 4 */
#define WGPTCP_DELTA		20u	/* WGPTCP_TCP_HDR_LEN - sizeof(struct udphdr) */

/* TCP option kinds */
#define WGPTCP_TCPOPT_EOL	0u
#define WGPTCP_TCPOPT_NOP	1u
#define WGPTCP_TCPOPT_TFO	34u	/* RFC 7413 TCP Fast Open cookie */
#define WGPTCP_TCPOPT_TFO_LEN	6u	/* kind(1) + len(1) + 4-byte cookie */

/* --------------------------------------------------------------------
 *   Cookie marker — fixed sentinel or keyed siphash (saddr || daddr)
 * -------------------------------------------------------------------- */
static __be32 wgptcp_cookie(const struct xt_wgptcp_info *info,
			    __be32 saddr, __be32 daddr)
{
	siphash_key_t k;
	u8 buf[8];

	if (!info->has_key)
		return cpu_to_be32(XT_WGPTCP_FIXED_COOKIE);

	memcpy(&k, info->key, sizeof(k));
	memcpy(buf,     &saddr, 4);
	memcpy(buf + 4, &daddr, 4);
	return cpu_to_be32((u32)siphash(buf, 8, &k));
}

/* --------------------------------------------------------------------
 *   ENCODE (UDP → fake-TCP-SYN+TFO)
 * -------------------------------------------------------------------- */
static unsigned int wgptcp_encode_v4(struct sk_buff *skb,
				     const struct xt_wgptcp_info *info)
{
	struct iphdr  *iph;
	struct udphdr *udph;
	struct tcphdr *tcph;
	u8	*opts;
	__be16	 sport, dport;
	__be32	 cookie;
	unsigned int ihl, payload_len, tcp_total_len;

	iph = ip_hdr(skb);
	if (iph->protocol != IPPROTO_UDP)
		return XT_CONTINUE;

	ihl = iph->ihl * 4;
	if (ntohs(iph->tot_len) < ihl + sizeof(struct udphdr))
		return XT_CONTINUE;

	/* Need 20 extra bytes of tailroom; expand if necessary. */
	if (skb_tailroom(skb) < (int)WGPTCP_DELTA) {
		if (pskb_expand_head(skb, 0, WGPTCP_DELTA, GFP_ATOMIC))
			return NF_DROP;
	}
	if (unlikely(skb_ensure_writable(skb, skb->len)))
		return NF_DROP;

	/* Re-fetch — pskb_expand_head may have moved the linear buffer. */
	iph = ip_hdr(skb);
	udph = (struct udphdr *)((u8 *)iph + ihl);

	sport       = udph->source;
	dport       = udph->dest;
	payload_len = ntohs(udph->len) - sizeof(struct udphdr);

	/* Grow skb by +20 bytes at the tail. */
	skb_put(skb, WGPTCP_DELTA);

	/* Shift payload forward by 20 bytes, leaving room at (udph) for a
	 * 28-byte TCP header in place of the 8-byte UDP header.
	 */
	memmove((u8 *)udph + WGPTCP_TCP_HDR_LEN,
		(u8 *)udph + sizeof(struct udphdr),
		payload_len);

	/* Build TCP header in place. */
	tcph = (struct tcphdr *)udph;
	memset(tcph, 0, WGPTCP_TCP_HDR_LEN);
	tcph->source	= sport;
	tcph->dest	= dport;
	tcph->seq	= (__force __be32)cpu_to_be32(get_random_u32());
	tcph->ack_seq	= 0;
	tcph->doff	= WGPTCP_TCP_DOFF;
	tcph->syn	= 1;
	tcph->window	= htons(0xFFFFu);

	/* TCP options: NOP NOP TFO_COOKIE(kind=34, len=6, 4-byte cookie). */
	opts    = (u8 *)tcph + sizeof(struct tcphdr);
	opts[0] = WGPTCP_TCPOPT_NOP;
	opts[1] = WGPTCP_TCPOPT_NOP;
	opts[2] = WGPTCP_TCPOPT_TFO;
	opts[3] = WGPTCP_TCPOPT_TFO_LEN;
	cookie  = wgptcp_cookie(info, iph->saddr, iph->daddr);
	memcpy(opts + 4, &cookie, 4);

	/* Update IP header. */
	iph->protocol = IPPROTO_TCP;
	iph->tot_len  = htons(ntohs(iph->tot_len) + WGPTCP_DELTA);
	iph->check    = 0;
	ip_send_check(iph);

	/* Recompute TCP checksum (full — protocol shape changed). */
	tcp_total_len = ntohs(iph->tot_len) - ihl;
	skb->ip_summed = CHECKSUM_NONE;
	tcph->check = 0;
	tcph->check = csum_tcpudp_magic(iph->saddr, iph->daddr,
					tcp_total_len, IPPROTO_TCP,
					csum_partial(tcph, tcp_total_len, 0));

	return XT_CONTINUE;
}

/* --------------------------------------------------------------------
 *   DECODE (fake-TCP-SYN+TFO → UDP)
 * -------------------------------------------------------------------- */
static unsigned int wgptcp_decode_v4(struct sk_buff *skb,
				     const struct xt_wgptcp_info *info)
{
	struct iphdr  *iph;
	struct tcphdr *tcph;
	struct udphdr *udph;
	const u8 *opts, *opts_end;
	__be16	 sport, dport;
	__be32	 expected_cookie, found_cookie;
	unsigned int ihl, tcp_hdr_len, payload_len, shrink;
	bool	 cookie_ok = false;

	iph = ip_hdr(skb);
	if (iph->protocol != IPPROTO_TCP)
		return XT_CONTINUE;

	ihl = iph->ihl * 4;
	if (ntohs(iph->tot_len) < ihl + sizeof(struct tcphdr))
		return XT_CONTINUE;

	if (unlikely(skb_ensure_writable(skb, skb->len)))
		return XT_CONTINUE;

	iph  = ip_hdr(skb);
	tcph = (struct tcphdr *)((u8 *)iph + ihl);

	/* Sentinel filter: SYN-only (no ACK), header big enough. */
	if (!tcph->syn || tcph->ack)
		return XT_CONTINUE;
	if (tcph->doff < WGPTCP_TCP_DOFF)
		return XT_CONTINUE;

	tcp_hdr_len = tcph->doff * 4;
	if (ntohs(iph->tot_len) < ihl + tcp_hdr_len)
		return XT_CONTINUE;

	/* Walk options looking for our TFO cookie marker. */
	opts     = (const u8 *)tcph + sizeof(struct tcphdr);
	opts_end = (const u8 *)tcph + tcp_hdr_len;
	while (opts < opts_end) {
		u8 kind = opts[0];
		u8 len;

		if (kind == WGPTCP_TCPOPT_EOL)
			break;
		if (kind == WGPTCP_TCPOPT_NOP) {
			opts++;
			continue;
		}
		if (opts + 1 >= opts_end)
			break;
		len = opts[1];
		if (len < 2 || opts + len > opts_end)
			break;
		if (kind == WGPTCP_TCPOPT_TFO &&
		    len == WGPTCP_TCPOPT_TFO_LEN) {
			memcpy(&found_cookie, opts + 2, 4);
			expected_cookie = wgptcp_cookie(info,
							iph->saddr,
							iph->daddr);
			if (found_cookie == expected_cookie)
				cookie_ok = true;
			break;
		}
		opts += len;
	}
	if (!cookie_ok)
		return XT_CONTINUE;

	/* Decode: rewrite TCP back to UDP. */
	sport       = tcph->source;
	dport       = tcph->dest;
	payload_len = ntohs(iph->tot_len) - ihl - tcp_hdr_len;
	shrink      = tcp_hdr_len - sizeof(struct udphdr);

	/* Shift payload backward to land right after a fresh UDP header. */
	memmove((u8 *)tcph + sizeof(struct udphdr),
		(u8 *)tcph + tcp_hdr_len,
		payload_len);

	/* Build UDP header in place where the TCP header used to start. */
	udph = (struct udphdr *)tcph;
	udph->source = sport;
	udph->dest   = dport;
	udph->len    = htons(sizeof(struct udphdr) + payload_len);
	udph->check  = 0;

	/* Trim skb tail by `shrink` bytes — we wrote `tcp_hdr_len` bytes of
	 * header but only need `sizeof(struct udphdr)` now.
	 */
	if (pskb_trim(skb, skb->len - shrink))
		return NF_DROP;
	iph = ip_hdr(skb);

	/* Update IP header. */
	iph->protocol = IPPROTO_UDP;
	iph->tot_len  = htons(ihl + sizeof(struct udphdr) + payload_len);
	iph->check    = 0;
	ip_send_check(iph);

	/* Recompute UDP checksum. WGOBFS computes it (rather than zeroing)
	 * to handle the case where this host isn't the final destination.
	 */
	udph = (struct udphdr *)((u8 *)iph + ihl);
	skb->ip_summed = CHECKSUM_NONE;
	udph->check = csum_tcpudp_magic(iph->saddr, iph->daddr,
					ntohs(udph->len), IPPROTO_UDP,
					csum_partial(udph,
						     ntohs(udph->len), 0));

	return XT_CONTINUE;
}

/* --------------------------------------------------------------------
 *   Hook dispatch + registration
 * -------------------------------------------------------------------- */
static unsigned int wgptcp_target(struct sk_buff *skb,
				  const struct xt_action_param *par)
{
	const struct xt_wgptcp_info *info = par->targinfo;

	if (info->mode == XT_WGPTCP_MODE_ENCODE)
		return wgptcp_encode_v4(skb, info);
	if (info->mode == XT_WGPTCP_MODE_DECODE)
		return wgptcp_decode_v4(skb, info);

	return XT_CONTINUE;
}

static int wgptcp_checkentry(const struct xt_tgchk_param *par)
{
	const struct xt_wgptcp_info *info = par->targinfo;

	if (info->mode != XT_WGPTCP_MODE_ENCODE &&
	    info->mode != XT_WGPTCP_MODE_DECODE)
		return -EINVAL;

	return 0;
}

static struct xt_target xt_wgptcp_reg[] __read_mostly = {
	{
		.name		= "WGPTCP",
		.revision	= 0,
		.family		= NFPROTO_IPV4,
		.target		= wgptcp_target,
		.targetsize	= sizeof(struct xt_wgptcp_info),
		.checkentry	= wgptcp_checkentry,
		.me		= THIS_MODULE,
	},
};

static int __init xt_wgptcp_init(void)
{
	return xt_register_targets(xt_wgptcp_reg, ARRAY_SIZE(xt_wgptcp_reg));
}

static void __exit xt_wgptcp_exit(void)
{
	xt_unregister_targets(xt_wgptcp_reg, ARRAY_SIZE(xt_wgptcp_reg));
}

module_init(xt_wgptcp_init);
module_exit(xt_wgptcp_exit);
MODULE_LICENSE("GPL v2");
MODULE_DESCRIPTION("xtables target: stateless UDP↔fake-TCP-SYN with TFO cookie marker");
MODULE_ALIAS("ipt_WGPTCP");
