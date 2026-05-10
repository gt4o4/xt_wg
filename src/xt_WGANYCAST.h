/*
 * xt_WGANYCAST — shared header (kernel + userspace)
 *
 * Two stateless modes for fan-out across multiple anycast endpoints:
 *
 *   SPRAY     — rewrite outbound packet's destination IP to one of
 *               `dests[0..ndests-1]`, picked uniformly at random per
 *               packet. Use in mangle/raw OUTPUT or POSTROUTING. Does
 *               not interact with conntrack.
 *
 *   CANONICAL — rewrite inbound packet's source IP to `dests[0]`. Use
 *               in mangle/raw PREROUTING to canonicalise replies that
 *               arrive from any of the SPRAY destinations back into a
 *               single peer endpoint, so WireGuard's roaming sees one
 *               stable address.
 */
#ifndef _XT_WGANYCAST_H
#define _XT_WGANYCAST_H

#include <linux/types.h>

#define XT_WGANYCAST_MAX_DESTS 8

#define XT_WGANYCAST_MODE_SPRAY     0
#define XT_WGANYCAST_MODE_CANONICAL 1

struct xt_wganycast_info {
	__u8 mode;	/* XT_WGANYCAST_MODE_* */
	__u8 ndests;	/* number of valid entries in dests[] */
	__u8 _pad[2];
	__be32 dests[XT_WGANYCAST_MAX_DESTS];
};

#endif
