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
#include <net/netfilter/nf_conntrack.h>
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

/* TCP option layout (v2 — full Linux SYN option set + TS on data):
 *
 *   SYN / SYN+ACK (handshake shape):  28 B of options
 *     MSS(4) | SACK_Perm(2) TS(10) | NOP WSCALE(3) | NOP NOP TFO(6) = 28 B
 *     TCP header total = 20 + 28 = 48 B  →  doff = 12  →  +40 B vs UDP
 *
 *   PSH+ACK (data shape):              12 B of options
 *     NOP NOP TS(10) = 12 B
 *     TCP header total = 20 + 12 = 32 B  →  doff = 8  →  +24 B vs UDP
 *
 * Stock Linux's `tcp_options_write` packs SACK_Perm directly before
 * the TS option (no NOP between) so the option block matches what a
 * fresh Linux client would emit — fingerprinting middleboxes see no
 * difference from a real TCP handshake.
 */
#define WGPTCP_HS_OPTS_LEN	28u
#define WGPTCP_TCP_HDR_HS	(sizeof(struct tcphdr) + WGPTCP_HS_OPTS_LEN)	/* 48 */
#define WGPTCP_DOFF_HS		(WGPTCP_TCP_HDR_HS / 4)				/* 12 */
#define WGPTCP_DELTA_HS		(WGPTCP_TCP_HDR_HS - sizeof(struct udphdr))	/* +40 */

#define WGPTCP_DATA_OPTS_LEN	12u
#define WGPTCP_TCP_HDR_DATA	(sizeof(struct tcphdr) + WGPTCP_DATA_OPTS_LEN)	/* 32 */
#define WGPTCP_DOFF_DATA	(WGPTCP_TCP_HDR_DATA / 4)			/* 8 */
#define WGPTCP_DELTA_DATA	(WGPTCP_TCP_HDR_DATA - sizeof(struct udphdr))	/* +24 */

/* TCP option kinds (RFC 9293 / 7323 / 2018 / 7413) */
#define WGPTCP_TCPOPT_EOL	0u
#define WGPTCP_TCPOPT_NOP	1u
#define WGPTCP_TCPOPT_MSS	2u
#define WGPTCP_TCPOPT_WSCALE	3u
#define WGPTCP_TCPOPT_SACK_PERM	4u
#define WGPTCP_TCPOPT_TS	8u
#define WGPTCP_TCPOPT_TFO	34u
#define WGPTCP_TCPOPT_MSS_LEN	4u
#define WGPTCP_TCPOPT_WSCALE_LEN 3u
#define WGPTCP_TCPOPT_SACK_PERM_LEN 2u
#define WGPTCP_TCPOPT_TS_LEN	10u
#define WGPTCP_TCPOPT_TFO_LEN	6u

#define WGPTCP_DEFAULT_MSS	1460u
#define WGPTCP_DEFAULT_WSCALE	7u	/* matches stock Linux tcp_select_initial_window */

/* Domain-separator strings for SipHash inputs (4 ASCII bytes each).
 * Both ends use the same strings so derived values match.
 *
 * v2 uses just two roles — one for outbound seq base (keyed on
 * iph->saddr, stable across re-handshakes for one host's outbound),
 * and one for outbound ack_seq (keyed on iph->daddr, which mirrors
 * the peer's seq base from their POV).
 */
#define ROLE_OUT	"out "	/* outbound seq base */
#define ROLE_ACK	"ack "	/* outbound ack_seq base (= peer's seq base + 149) */

#define WGPTCP_INIT_TFO_DATA_LEN	148u	/* size of WG handshake initiation */

/* `ct->mark` stores OUTBOUND state for this flow on this host:
 *   0       = no outbound packet emitted yet on this conntrack entry.
 *             Next encode emits SYN (initiator) or SYN+ACK (responder).
 *   1       = SYN/SYN+ACK has been emitted; no PSH+ACK data yet.
 *             cum_bytes (post-handshake PSH+ACK payload) = 0.
 *   1 + N   = N bytes of PSH+ACK payload have been emitted since the
 *             initial SYN/SYN+ACK.
 *
 * Lifetime is bound to the conntrack entry — when WG goes silent past
 * the UDP-conntrack timeout, the entry ages out, mark vanishes with
 * it, and the next outbound packet starts a fresh SYN. Re-handshakes
 * inside the conntrack lifetime don't touch the mark sentinel; they
 * just contribute their payload to cum_bytes, riding as PSH+ACK.
 */
#define WGPTCP_MARK_INITIAL_SENTINEL	1u

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
			    __be32 tcph_seq)
{
	siphash_key_t key;
	u8 buf[8];

	if (!info->has_key)
		return cpu_to_be32(XT_WGPTCP_FIXED_COOKIE);

	/* Cookie hash input: the TCP `seq` field from this packet.
	 *
	 * `tcph->seq` is itself derived (via wgptcp_derive) from the WG
	 * payload's sender_index / receiver_index — a value that travels
	 * inside the encrypted WG message and is therefore NAT-immune
	 * (no SNAT / DNAT box rewrites TCP sequence numbers; if one did
	 * it would break real TCP).  By hashing seq, the cookie inherits
	 * the same NAT-immunity, so encoder and decoder agree even when
	 * the path between them does 1:1 NAT, Cloudflare-Spectrum DNAT,
	 * or anything else that mangles iph->saddr / iph->daddr.
	 *
	 * The "ckie" 4-byte domain separator prevents this hash from
	 * accidentally colliding with a `wgptcp_derive` output for some
	 * (key, role) combination.
	 */
	memcpy(&key, info->key, sizeof(key));
	memcpy(buf,     &tcph_seq, 4);
	memcpy(buf + 4, "ckie",    4);
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

	/* TCP options — full stock-Linux SYN set on handshake-shape
	 * (matches what `tcp_options_write` would emit for a fresh
	 * Linux TCP client + server) so fingerprinting middleboxes see
	 * an indistinguishable handshake; TS-only on PSH+ACK data
	 * (matches stock Linux ESTABLISHED data flows).
	 *
	 *   handshake (28 B):
	 *     [MSS(4)] [SACK_Perm(2) TS(10)] [NOP WSCALE(3)] [NOP NOP TFO(6)]
	 *
	 *   data (12 B):
	 *     [NOP NOP TS(10)]
	 */
	opts = (u8 *)tcph + sizeof(struct tcphdr);
	if (tcp_hdr_len == WGPTCP_TCP_HDR_HS) {
		u32 ts_val = tcp_time_stamp_raw();
		__be32 cookie_v;

		/* MSS (4 B): kind=2 len=4 value=1460 */
		opts[0] = WGPTCP_TCPOPT_MSS;
		opts[1] = WGPTCP_TCPOPT_MSS_LEN;
		*(__be16 *)(opts + 2) = htons(WGPTCP_DEFAULT_MSS);

		/* SACK_Perm + TS (12 B): packed together, matching Linux's
		 *   tcp_options_write when both options are present.
		 *     [SACK_Perm kind=4 len=2] [TS kind=8 len=10] [val(4)] [ecr(4)]
		 */
		opts[4]  = WGPTCP_TCPOPT_SACK_PERM;
		opts[5]  = WGPTCP_TCPOPT_SACK_PERM_LEN;
		opts[6]  = WGPTCP_TCPOPT_TS;
		opts[7]  = WGPTCP_TCPOPT_TS_LEN;
		*(__be32 *)(opts +  8) = htonl(ts_val);
		*(__be32 *)(opts + 12) = 0;	/* TS_ecr = 0 (no peer tracking) */

		/* NOP + WSCALE (4 B): kind=3 len=3 shift=7 */
		opts[16] = WGPTCP_TCPOPT_NOP;
		opts[17] = WGPTCP_TCPOPT_WSCALE;
		opts[18] = WGPTCP_TCPOPT_WSCALE_LEN;
		opts[19] = WGPTCP_DEFAULT_WSCALE;

		/* NOP NOP + TFO cookie (8 B): kind=34 len=6 cookie(4) */
		opts[20] = WGPTCP_TCPOPT_NOP;
		opts[21] = WGPTCP_TCPOPT_NOP;
		opts[22] = WGPTCP_TCPOPT_TFO;
		opts[23] = WGPTCP_TCPOPT_TFO_LEN;
		/* tcph->seq is already populated above and is derived from
		 * the WG payload (via ROLE_OUT siphash) — the cookie is a
		 * hash of seq, NAT-immune since TCP seq is preserved by
		 * any conventional NAT.
		 */
		cookie_v = wgptcp_cookie(info, tcph->seq);
		memcpy(opts + 24, &cookie_v, 4);
	} else {
		/* PSH+ACK: NOP NOP + TS only (12 B) */
		u32 ts_val = tcp_time_stamp_raw();

		opts[0] = WGPTCP_TCPOPT_NOP;
		opts[1] = WGPTCP_TCPOPT_NOP;
		opts[2] = WGPTCP_TCPOPT_TS;
		opts[3] = WGPTCP_TCPOPT_TS_LEN;
		*(__be32 *)(opts + 4) = htonl(ts_val);
		*(__be32 *)(opts + 8) = 0;
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
 *   ENCODE — flow-state-driven via ct->mark + ctinfo (v2)
 *
 * The WG message-type byte is parsed only for size validation
 * (defensive: don't TCP-wrap arbitrary non-WG UDP).  Wire-shape
 * selection (SYN / SYN+ACK / PSH+ACK) comes from the conntrack
 * state, not from the WG type:
 *
 *   mark == 0 + ctinfo == IP_CT_NEW             → SYN
 *   mark == 0 + ctinfo == IP_CT_ESTABLISHED_REPLY → SYN+ACK
 *   mark >= 1                                    → PSH+ACK
 *
 * This makes re-handshakes (further type=1 INITs on the same
 * conntrack entry) ride as PSH+ACK with cumulative seq — the in-path
 * middlebox sees an uninterrupted ESTABLISHED stream and never
 * sees a SYN→ESTABLISHED transition to dislike.
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
	struct nf_conn *ct;
	enum ip_conntrack_info ctinfo;
	u32	 syn_seq_base, ack_seq_base, mark;

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

	/* Validate the WG message type + size.  Defensive: only TCP-wrap
	 * well-formed WG packets.
	 */
	wg_type = payload[0];
	switch (wg_type) {
	case WG_TYPE_INIT:
		if (payload_len != sizeof(struct wg_message_handshake_initiation))
			return XT_CONTINUE;
		break;
	case WG_TYPE_RESP:
		if (payload_len != sizeof(struct wg_message_handshake_response))
			return XT_CONTINUE;
		break;
	case WG_TYPE_COOKIE:
		if (payload_len != sizeof(struct wg_message_handshake_cookie))
			return XT_CONTINUE;
		break;
	case WG_TYPE_DATA:
		if (payload_len < sizeof(struct wg_message_transport_min))
			return XT_CONTINUE;
		break;
	default:
		return XT_CONTINUE;
	}

	/* Seq base for our outbound: stateless derivation keyed on our
	 * pre-NAT local IP.  Encoder runs before POSTROUTING SNAT, so
	 * iph->saddr is the canonical local address regardless of any
	 * upstream NAT.  Same base across re-handshakes and across
	 * different WG message types within one flow → continuous seq
	 * advancement for any middlebox tracking the flow.
	 */
	syn_seq_base = wgptcp_derive(info, iph->saddr, ROLE_OUT);
	ack_seq_base = wgptcp_derive(info, iph->daddr, ROLE_OUT);

	ct = nf_ct_get(skb, &ctinfo);
	mark = ct ? READ_ONCE(ct->mark) : 0;

	if (mark == 0) {
		/* First outbound packet on this conntrack entry. */
		if (!ct || ctinfo == IP_CT_NEW) {
			/* We initiated this flow — emit a SYN with TFO data. */
			flags   = TCPHDR_SYN;
			ack_seq = 0;
		} else {
			/* Peer initiated — emit SYN+ACK with TFO data, acking
			 * the peer's prior SYN. */
			flags   = TCPHDR_SYN | TCPHDR_ACK;
			ack_seq = (__force __be32)cpu_to_be32(
				ack_seq_base + 1 + WGPTCP_INIT_TFO_DATA_LEN);
		}
		seq         = (__force __be32)cpu_to_be32(syn_seq_base);
		tcp_hdr_len = WGPTCP_TCP_HDR_HS;
		if (ct)
			WRITE_ONCE(ct->mark, WGPTCP_MARK_INITIAL_SENTINEL);
	} else {
		/* ESTABLISHED — every subsequent outbound packet (including
		 * WG re-handshakes) rides as PSH+ACK with cumulative seq.
		 * Stationary ack_seq (= peer's SYN seq + 149) — looks like a
		 * "duplicate ACK" pattern; loose-mode middleboxes accept.
		 */
		u32 cum_bytes = mark - WGPTCP_MARK_INITIAL_SENTINEL;

		flags       = TCPHDR_PSH | TCPHDR_ACK;
		seq         = (__force __be32)cpu_to_be32(
				syn_seq_base + 1 + WGPTCP_INIT_TFO_DATA_LEN
				+ cum_bytes);
		ack_seq     = (__force __be32)cpu_to_be32(
				ack_seq_base + 1 + WGPTCP_INIT_TFO_DATA_LEN);
		tcp_hdr_len = WGPTCP_TCP_HDR_DATA;
		WRITE_ONCE(ct->mark, mark + payload_len);
	}

	/* Suppress unused-var warning if wg_type ends up unused after the
	 * size-validation switch (no per-type seq derivation in v2). */
	(void)wg_type;

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
		__be32 expected = wgptcp_cookie(info, tcph->seq);

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
