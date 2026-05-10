/*
 * xt_WGPTCP — shared header (kernel + userspace)
 *
 * Stateless UDP↔fake-TCP transmutation for WireGuard-over-DPI.
 *
 *   ENCODE — rewrite outbound UDP packet to a TCP SYN that carries the
 *            UDP payload as TCP data, with a TFO cookie option (RFC 7413)
 *            as the protocol marker. Use in OUTPUT or POSTROUTING. Net
 *            packet growth: +20 bytes (TCP base 20 + 8-byte TFO option −
 *            UDP header 8).
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

#define XT_WGPTCP_KEY_SIZE     16
#define XT_WGPTCP_FIXED_COOKIE 0xC07F0001U

struct xt_wgptcp_info {
	__u8 mode;	/* XT_WGPTCP_MODE_* */
	__u8 has_key;	/* 0 = fixed sentinel, 1 = siphash-keyed */
	__u8 _pad[2];
	__u8 key[XT_WGPTCP_KEY_SIZE];
};

#endif
