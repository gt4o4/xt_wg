// SPDX-License-Identifier: GPL-2.0-only
/*
 * xt_WGPTCP — stateless UDP↔fake-TCP transmutation, WG-protocol-aware.
 *
 * Maps each WireGuard message type onto a different TCP shape so that the
 * wire-level packets reproduce a real TCP 3-way handshake + ESTABLISHED
 * data exchange:
 *
 *	WG initiation (type=1)      → TCP SYN     + TFO opt + data
 *	WG response   (type=2)      → TCP SYN+ACK + TFO opt + data
 *	WG cookie     (type=3)      → TCP SYN+ACK + TFO opt + data
 *	WG transport  (type=4)      → TCP PSH+ACK + data (no opts)
 *
 * Seq/ack are derived statelessly via SipHash-2-4(key, wg_index, role)
 * so that:
 *
 *	• SYN's seq matches what the responder will reference in SYN+ACK's
 *	  ack_seq (firewall sees a clean handshake);
 *	• PSH+ACK seq advances with the WG counter (firewall sees data flow).
 *
 * Both ends share the same `--key` and the same hash inputs (read from
 * the WG message contents — `sender_index` / `receiver_index`) so neither
 * needs per-flow state.
 *
 *   # encode outbound WG/UDP
 *   iptables -t mangle -A OUTPUT -p udp -d <peer>/32 --dport 51821 \
 *       -j WGPTCP --encode --key <32-hex>
 *
 *   # decode inbound (must be in raw PREROUTING; drops --syn since data
 *   # packets are PSH+ACK without SYN)
 *   iptables -t raw -A PREROUTING -p tcp -s <peer>/32 --sport 51821 \
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
#include "wg.h"
#include "xt_wg_common.h"

/* WG message-type byte values (first byte of UDP payload). */
#define WG_TYPE_INIT	0x01u
#define WG_TYPE_RESP	0x02u
#define WG_TYPE_COOKIE	0x03u
#define WG_TYPE_DATA	0x04u

/* WG transport-data header (not in wg.h — defined per WG spec):
 *   __le32 type  + __le32 receiver_index + __le64 counter + ciphertext...
 */
struct wg_message_transport_min {
	__le32 type;
	__le32 receiver_index;
	__le64 counter;
};

/* TCP option layout for handshake-shape encoding (8 bytes appended to the
 * 20-byte TCP base header):
 *
 *	bytes 0..1: NOP NOP	(kind=1, 4-byte alignment pad)
 *	bytes 2..3: TFO_COOKIE	(kind=34, len=6)
 *	bytes 4..7: 4-byte cookie value
 */
#define WGPTCP_TFO_OPTS_LEN	8u
#define WGPTCP_TCP_HDR_HS	(sizeof(struct tcphdr) + WGPTCP_TFO_OPTS_LEN)	/* 28 */
#define WGPTCP_DOFF_HS		(WGPTCP_TCP_HDR_HS / 4)				/* 7 */
#define WGPTCP_DELTA_HS		(WGPTCP_TCP_HDR_HS - sizeof(struct udphdr))	/* +20 */

#define WGPTCP_TCP_HDR_DATA	sizeof(struct tcphdr)				/* 20 */
#define WGPTCP_DOFF_DATA	(WGPTCP_TCP_HDR_DATA / 4)			/* 5 */
#define WGPTCP_DELTA_DATA	(WGPTCP_TCP_HDR_DATA - sizeof(struct udphdr))	/* +12 */

/* TCP option kinds */
#define WGPTCP_TCPOPT_EOL	0u
#define WGPTCP_TCPOPT_NOP	1u
#define WGPTCP_TCPOPT_TFO	34u
#define WGPTCP_TCPOPT_TFO_LEN	6u

/* Domain-separator strings for SipHash inputs (4 ASCII bytes each).
 * Both ends use the same strings so derived values match.
 */
#define ROLE_INIT	"init"	/* SYN seq for type-1 initiator */
#define ROLE_RESP	"resp"	/* SYN+ACK seq for type-2 responder */
#define ROLE_COOK	"cook"	/* SYN+ACK seq for type-3 cookie reply */
#define ROLE_TX		"tx  "	/* PSH+ACK seq base (outbound counter) */
#define ROLE_RX		"rx  "	/* PSH+ACK ack_seq base (inbound counter) */

#define WGPTCP_INIT_TFO_DATA_LEN	148u	/* size of WG handshake initiation */

/* Default key for unkeyed mode — used so derived values are deterministic
 * across encoder/decoder pairs even without a user-supplied --key. The
 * fixed sentinel cookie 0xC07F0001 doubles as the seed pattern.
 */
static const u8 wgptcp_default_key[XT_WGPTCP_KEY_SIZE] = {
	0xc0, 0x7f, 0x00, 0x01, 0xc0, 0x7f, 0x00, 0x01,
	0xc0, 0x7f, 0x00, 0x01, 0xc0, 0x7f, 0x00, 0x01,
};

/* --------------------------------------------------------------------
 *   Cookie + seq derivation (SipHash-2-4)
 * -------------------------------------------------------------------- */
static const u8 *wgptcp_keybytes(const struct xt_wgptcp_info *info)
{
	return info->has_key ? info->key : wgptcp_default_key;
}

static __be32 wgptcp_cookie(const struct xt_wgptcp_info *info,
			    __be32 saddr, __be32 daddr)
{
	siphash_key_t key;
	u8 buf[8];
	__be32 lo, hi;

	if (!info->has_key)
		return cpu_to_be32(XT_WGPTCP_FIXED_COOKIE);

	/* Canonical IP order — hash the (lower-IP, higher-IP) tuple rather
	 * than (saddr, daddr).  Three benefits:
	 *
	 *   1. The same flow gets the same cookie in both directions
	 *      (A→B and B→A) — useful if a deep DPI box correlates
	 *      bidirectional flows by marker.
	 *   2. Survives any path-side address rewriting that preserves
	 *      the {saddr, daddr} set (e.g. ACL gateways that swap
	 *      source/dest for a mirrored port).
	 *   3. Encoder and decoder agree even in the corner case where
	 *      reverse-path filtering or asymmetric routing causes one
	 *      end to see iph fields differently from the other —
	 *      shouldn't happen in normal deployments, but the canonical
	 *      hash sidesteps it without cost.
	 *
	 * It does NOT survive NAT that actually changes IP *values* (DNAT
	 * to a different address, SNAT after the encoder hook).  For that,
	 * exclude the peer from services.gfw-cloudflare-dnat.mappings —
	 * see the wg-ptcp.nix module documentation.
	 */
	if ((u32)be32_to_cpu(saddr) < (u32)be32_to_cpu(daddr)) {
		lo = saddr;
		hi = daddr;
	} else {
		lo = daddr;
		hi = saddr;
	}

	memcpy(&key, info->key, sizeof(key));
	memcpy(buf,     &lo, 4);
	memcpy(buf + 4, &hi, 4);
	return cpu_to_be32((u32)siphash(buf, 8, &key));
}

/* Derive a 32-bit value from (key, wg_index, 4-byte role tag).  Used for
 * stateless seq/ack stamping on SYN / SYN+ACK / PSH+ACK packets so that
 * both ends compute matching values without any per-flow tracking.
 */
static u32 wgptcp_derive(const struct xt_wgptcp_info *info,
			 __le32 wg_index, const char role[4])
{
	siphash_key_t key;
	u8 buf[8];

	memcpy(&key, wgptcp_keybytes(info), sizeof(key));
	memcpy(buf,     &wg_index, 4);
	memcpy(buf + 4, role,      4);
	return (u32)siphash(buf, 8, &key);
}

/* --------------------------------------------------------------------
 *   Encode helpers
 * -------------------------------------------------------------------- */

/* Build IP header + TCP header (with optional TFO) over an existing
 * UDP-shaped packet.  Caller has already grown the skb tail by `delta`
 * (= TCP header size − UDP header size) and the original UDP payload
 * is still at offset (ihl + 8) — wgptcp_encode_v4 below shifts it.
 */
static unsigned int wgptcp_encode_common(struct sk_buff *skb,
					 const struct xt_wgptcp_info *info,
					 u8 tcp_flags, __be32 seq, __be32 ack_seq,
					 unsigned int tcp_hdr_len)
{
	struct iphdr  *iph;
	struct udphdr *udph;
	struct tcphdr *tcph;
	u8	*opts;
	__be16	 sport, dport;
	__be32	 cookie;
	unsigned int ihl, payload_len, tcp_total_len, delta;

	iph = ip_hdr(skb);
	ihl = iph->ihl * 4;
	delta = tcp_hdr_len - sizeof(struct udphdr);

	/* Need `delta` extra bytes of tailroom. */
	if (skb_tailroom(skb) < (int)delta) {
		if (pskb_expand_head(skb, 0, delta, GFP_ATOMIC))
			return NF_DROP;
	}
	if (unlikely(skb_ensure_writable(skb, skb->len)))
		return NF_DROP;

	iph  = ip_hdr(skb);
	udph = (struct udphdr *)((u8 *)iph + ihl);

	sport       = udph->source;
	dport       = udph->dest;
	payload_len = ntohs(udph->len) - sizeof(struct udphdr);

	skb_put(skb, delta);

	/* Shift payload forward by `delta` to make room for the larger TCP
	 * header at the same offset where the UDP header used to be.
	 */
	memmove((u8 *)udph + tcp_hdr_len,
		(u8 *)udph + sizeof(struct udphdr),
		payload_len);

	tcph = (struct tcphdr *)udph;
	memset(tcph, 0, tcp_hdr_len);
	tcph->source	= sport;
	tcph->dest	= dport;
	tcph->seq	= seq;
	tcph->ack_seq	= ack_seq;
	tcph->doff	= tcp_hdr_len / 4;
	tcph->fin	= !!(tcp_flags & TCPHDR_FIN);
	tcph->syn	= !!(tcp_flags & TCPHDR_SYN);
	tcph->rst	= !!(tcp_flags & TCPHDR_RST);
	tcph->psh	= !!(tcp_flags & TCPHDR_PSH);
	tcph->ack	= !!(tcp_flags & TCPHDR_ACK);
	tcph->window	= htons(0xFFFFu);

	/* TFO cookie option only appended for the handshake-shape (28-byte
	 * header).  PSH+ACK data shape has no options.
	 */
	if (tcp_hdr_len == WGPTCP_TCP_HDR_HS) {
		opts    = (u8 *)tcph + sizeof(struct tcphdr);
		opts[0] = WGPTCP_TCPOPT_NOP;
		opts[1] = WGPTCP_TCPOPT_NOP;
		opts[2] = WGPTCP_TCPOPT_TFO;
		opts[3] = WGPTCP_TCPOPT_TFO_LEN;
		cookie  = wgptcp_cookie(info, iph->saddr, iph->daddr);
		memcpy(opts + 4, &cookie, 4);
	}

	iph->protocol = IPPROTO_TCP;
	iph->tot_len  = htons(ntohs(iph->tot_len) + delta);
	iph->check    = 0;
	ip_send_check(iph);

	tcp_total_len = ntohs(iph->tot_len) - ihl;
	skb->ip_summed = CHECKSUM_NONE;
	tcph->check = 0;
	tcph->check = csum_tcpudp_magic(iph->saddr, iph->daddr,
					tcp_total_len, IPPROTO_TCP,
					csum_partial(tcph, tcp_total_len, 0));

	return XT_CONTINUE;
}

/* --------------------------------------------------------------------
 *   ENCODE — dispatch on WG message type
 * -------------------------------------------------------------------- */
static unsigned int wgptcp_encode_v4(struct sk_buff *skb,
				     const struct xt_wgptcp_info *info)
{
	struct iphdr  *iph;
	struct udphdr *udph;
	const u8 *payload;
	unsigned int ihl, payload_len;
	u8	 wg_type;
	__be32	 seq = 0, ack_seq = 0;
	u8	 flags;
	unsigned int tcp_hdr_len;

	iph = ip_hdr(skb);
	if (iph->protocol != IPPROTO_UDP)
		return XT_CONTINUE;

	ihl = iph->ihl * 4;
	if (ntohs(iph->tot_len) < ihl + sizeof(struct udphdr))
		return XT_CONTINUE;

	if (unlikely(skb_ensure_writable(skb, skb->len)))
		return NF_DROP;

	iph  = ip_hdr(skb);
	udph = (struct udphdr *)((u8 *)iph + ihl);
	payload     = (const u8 *)udph + sizeof(struct udphdr);
	payload_len = ntohs(udph->len) - sizeof(struct udphdr);

	if (payload_len < 4)
		return XT_CONTINUE;

	wg_type = payload[0];
	switch (wg_type) {
	case WG_TYPE_INIT: {
		const struct wg_message_handshake_initiation *m;

		if (payload_len != sizeof(*m))
			return XT_CONTINUE;
		m = (const void *)payload;

		flags       = TCPHDR_SYN;
		tcp_hdr_len = WGPTCP_TCP_HDR_HS;
		seq         = (__force __be32)cpu_to_be32(
				wgptcp_derive(info, m->sender_index, ROLE_INIT));
		ack_seq     = 0;
		break;
	}
	case WG_TYPE_RESP: {
		const struct wg_message_handshake_response *m;

		if (payload_len != sizeof(*m))
			return XT_CONTINUE;
		m = (const void *)payload;

		flags       = TCPHDR_SYN | TCPHDR_ACK;
		tcp_hdr_len = WGPTCP_TCP_HDR_HS;
		seq         = (__force __be32)cpu_to_be32(
				wgptcp_derive(info, m->sender_index, ROLE_RESP));
		/* ACK the prior SYN: peer's seq + 1 (SYN consumes 1) +
		 * 148 (TFO data carried in initiator's SYN). */
		ack_seq     = (__force __be32)cpu_to_be32(
				wgptcp_derive(info, m->receiver_index, ROLE_INIT)
				+ 1 + WGPTCP_INIT_TFO_DATA_LEN);
		break;
	}
	case WG_TYPE_COOKIE: {
		const struct wg_message_handshake_cookie *m;

		if (payload_len != sizeof(*m))
			return XT_CONTINUE;
		m = (const void *)payload;

		flags       = TCPHDR_SYN | TCPHDR_ACK;
		tcp_hdr_len = WGPTCP_TCP_HDR_HS;
		/* Cookie reply has no own sender_index — derive seq from
		 * receiver_index with a different role tag so it doesn't
		 * collide with a normal type-2 response on the same flow. */
		seq         = (__force __be32)cpu_to_be32(
				wgptcp_derive(info, m->receiver_index, ROLE_COOK));
		ack_seq     = (__force __be32)cpu_to_be32(
				wgptcp_derive(info, m->receiver_index, ROLE_INIT)
				+ 1 + WGPTCP_INIT_TFO_DATA_LEN);
		break;
	}
	case WG_TYPE_DATA: {
		const struct wg_message_transport_min *m;
		u32 ctr_lo;

		if (payload_len < sizeof(*m))
			return XT_CONTINUE;
		m = (const void *)payload;

		flags       = TCPHDR_PSH | TCPHDR_ACK;
		tcp_hdr_len = WGPTCP_TCP_HDR_DATA;
		ctr_lo      = (u32)le64_to_cpu(m->counter);
		seq         = (__force __be32)cpu_to_be32(
				wgptcp_derive(info, m->receiver_index, ROLE_TX)
				+ ctr_lo);
		ack_seq     = (__force __be32)cpu_to_be32(
				wgptcp_derive(info, m->receiver_index, ROLE_RX));
		break;
	}
	default:
		return XT_CONTINUE;
	}

	/* Optional WGOBFS-style payload mangling — applied while skb is
	 * still UDP-shaped, so wg_obfs_payload's `udp_hdr(skb)` access
	 * works.  After this returns, the WG message has variable random
	 * padding appended (length encoded in the last byte) and its
	 * first 16 bytes are XOR-scrambled.  We update IP/UDP length
	 * fields here; UDP checksum is left zero because wgptcp_encode_common
	 * is about to overwrite the L4 header anyway.
	 */
	if (info->has_obfs) {
		u8 obfs_pad_len;
		unsigned int rc = wg_obfs_payload(skb, &obfs_pad_len,
						  info->obfs_key);
		if (rc != XT_CONTINUE)
			return rc;
		iph = ip_hdr(skb);
		ihl = iph->ihl * 4;
		iph->tos     = 0;
		iph->tot_len = htons(ntohs(iph->tot_len) + obfs_pad_len);
		udph = (struct udphdr *)((u8 *)iph + ihl);
		udph->len    = htons(ntohs(udph->len) + obfs_pad_len);
		udph->check  = 0;
	}

	return wgptcp_encode_common(skb, info, flags, seq, ack_seq, tcp_hdr_len);
}

/* --------------------------------------------------------------------
 *   DECODE — common path; dispatch on TCP flag pattern
 * -------------------------------------------------------------------- */
static bool wgptcp_match_tfo_cookie(const struct tcphdr *tcph,
				    unsigned int tcp_hdr_len,
				    __be32 expected)
{
	const u8 *opts     = (const u8 *)tcph + sizeof(struct tcphdr);
	const u8 *opts_end = (const u8 *)tcph + tcp_hdr_len;

	while (opts < opts_end) {
		u8 kind = opts[0];
		u8 len;
		__be32 found;

		if (kind == WGPTCP_TCPOPT_EOL)
			return false;
		if (kind == WGPTCP_TCPOPT_NOP) {
			opts++;
			continue;
		}
		if (opts + 1 >= opts_end)
			return false;
		len = opts[1];
		if (len < 2 || opts + len > opts_end)
			return false;
		if (kind == WGPTCP_TCPOPT_TFO &&
		    len == WGPTCP_TCPOPT_TFO_LEN) {
			memcpy(&found, opts + 2, 4);
			return found == expected;
		}
		opts += len;
	}
	return false;
}

static unsigned int wgptcp_decode_v4(struct sk_buff *skb,
				     const struct xt_wgptcp_info *info)
{
	struct iphdr  *iph;
	struct tcphdr *tcph;
	struct udphdr *udph;
	__be16	 sport, dport;
	unsigned int ihl, tcp_hdr_len, payload_len, shrink;
	bool	 is_handshake_shape;

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

	if (tcph->doff < 5)
		return XT_CONTINUE;
	tcp_hdr_len = tcph->doff * 4;
	if (ntohs(iph->tot_len) < ihl + tcp_hdr_len)
		return XT_CONTINUE;

	/* SYN-set packets (with or without ACK) must carry our TFO cookie.
	 * Non-SYN packets (PSH+ACK) rely on rule-level filtering — there's
	 * no TFO option in real TCP after the handshake.
	 */
	if (tcph->syn) {
		__be32 expected = wgptcp_cookie(info, iph->saddr, iph->daddr);

		if (!wgptcp_match_tfo_cookie(tcph, tcp_hdr_len, expected))
			return XT_CONTINUE;
		is_handshake_shape = true;
	} else if (tcph->ack) {
		/* PSH+ACK or bare ACK — assume ours per rule filter. */
		is_handshake_shape = false;
	} else {
		/* RST / FIN / etc. — leave for kernel TCP stack. */
		return XT_CONTINUE;
	}

	sport       = tcph->source;
	dport       = tcph->dest;
	payload_len = ntohs(iph->tot_len) - ihl - tcp_hdr_len;
	shrink      = tcp_hdr_len - sizeof(struct udphdr);

	memmove((u8 *)tcph + sizeof(struct udphdr),
		(u8 *)tcph + tcp_hdr_len,
		payload_len);

	udph = (struct udphdr *)tcph;
	udph->source = sport;
	udph->dest   = dport;
	udph->len    = htons(sizeof(struct udphdr) + payload_len);
	udph->check  = 0;

	if (pskb_trim(skb, skb->len - shrink))
		return NF_DROP;
	iph = ip_hdr(skb);

	iph->protocol = IPPROTO_UDP;
	iph->tot_len  = htons(ihl + sizeof(struct udphdr) + payload_len);

	/* Optional WGOBFS-style un-mangling — read the padding-length
	 * marker from the last byte, trim it, restore the head 16 bytes
	 * via the same chacha PRN.  Must run while skb is UDP-shaped
	 * (wg_unobfs_payload uses udp_hdr(skb)).  After this the IP +
	 * UDP length fields shrink by `obfs_pad_len`.
	 */
	if (info->has_obfs) {
		u8 obfs_pad_len;
		unsigned int rc = wg_unobfs_payload(skb, &obfs_pad_len,
						    info->obfs_key);
		if (rc != XT_CONTINUE)
			return rc;
		iph = ip_hdr(skb);
		iph->tot_len = htons(ntohs(iph->tot_len) - obfs_pad_len);
		udph = (struct udphdr *)((u8 *)iph + ihl);
		udph->len    = htons(ntohs(udph->len) - obfs_pad_len);
	}

	iph->check    = 0;
	ip_send_check(iph);

	udph = (struct udphdr *)((u8 *)iph + ihl);
	skb->ip_summed = CHECKSUM_NONE;
	udph->check = csum_tcpudp_magic(iph->saddr, iph->daddr,
					ntohs(udph->len), IPPROTO_UDP,
					csum_partial(udph,
						     ntohs(udph->len), 0));

	(void)is_handshake_shape;	/* Reserved for future per-shape handling. */
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

/* Target array exposed to xt_wg_main.c for central registration in the
 * consolidated xt_wg.ko (see xt_wg_common.h).
 */
struct xt_target xt_wgptcp_targets[] __read_mostly = {
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
const unsigned int xt_wgptcp_targets_n = ARRAY_SIZE(xt_wgptcp_targets);
