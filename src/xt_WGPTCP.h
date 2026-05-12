/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Author: Bingchen Gong <gongbingchen@gmail.com>
 *
 * xt_WGPTCP — shared header (kernel + userspace)
 *
 * UDP↔fake-TCP transmutation for WireGuard-over-DPI.  Per-direction
 * byte/packet state is read from `nf_conn_acct` on the underlying
 * UDP conntrack entry (no `ct->mark` or `ct->labels` claim).
 *
 *   ENCODE — rewrite outbound UDP packet to a WG-protocol-aware TCP
 *            shape (SYN / SYN+ACK for the first outbound on each side,
 *            PSH+ACK for subsequent data) with a TFO cookie option
 *            (RFC 7413) as the protocol marker on handshake-shape
 *            packets.  Use in OUTPUT mangle.  Net packet growth:
 *            +40 bytes for handshake shape (48 B TCP header − 8 B UDP),
 *            +24 bytes for data shape (32 B TCP header − 8 B UDP).
 *
 *   DECODE — recognise a fake-TCP packet by its TFO cookie marker and
 *            rewrite it back to UDP. MUST be installed in raw PREROUTING
 *            (priority −300, before conntrack at −200) so the kernel
 *            TCP stack never sees the fake-TCP packet — this is what
 *            makes companion `iptables -t raw -j DROP` rules unnecessary.
 *
 * The 4-byte TFO cookie is either a fixed sentinel (0xC07F0001) when
 * `has_key == 0`, or the first 4 bytes of siphash24(key, saddr || daddr)
 * when `has_key == 1`. Keyed mode prevents legitimate inbound TFO
 * connections from being mis-decoded into UDP.
 */
#ifndef _XT_WGPTCP_H
#define _XT_WGPTCP_H

#include <linux/types.h>

#define XT_WGPTCP_MODE_ENCODE 0
#define XT_WGPTCP_MODE_DECODE 1

#define XT_WGPTCP_KEY_SIZE        16
#define XT_WGPTCP_OBFS_KEY_SIZE   32
#define XT_WGPTCP_FIXED_COOKIE    0xC07F0001U

struct xt_wgptcp_info {
	__u8 mode;	/* XT_WGPTCP_MODE_* */
	__u8 has_key;	/* 0 = fixed sentinel, 1 = siphash-keyed */
	__u8 has_obfs;	/* 0 = TCP-wrap only, 1 = WGOBFS-style payload mangle */
	__u8 _pad[1];
	__u8 key[XT_WGPTCP_KEY_SIZE];
	__u8 obfs_key[XT_WGPTCP_OBFS_KEY_SIZE];
};

#endif
