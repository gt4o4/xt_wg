// SPDX-License-Identifier: GPL-2.0-only
/*
 * Author: Bingchen Gong <gongbingchen@gmail.com>
 *
 * iptables WGANYCAST target plugin — v9 (argument-less SPRAY).
 *
 * The target takes no flags.  Install in `raw` OUTPUT to rewrite
 * outbound WG packets' iph->daddr (+ udph->dest) to a random entry
 * from the per-session pool learned from inbound traffic:
 *
 *   iptables -t raw -A OUTPUT -p udp --sport 51821 -j WGANYCAST
 *
 * The inbound LEARN side is no longer an iptables target — it's
 * done implicitly via the WGANYCAST conntrack helper.  Attach the
 * helper to inbound WG cts using the standard `CT` target:
 *
 *   iptables -t raw -A PREROUTING -p udp --dport 51821 \
 *            -j CT --helper WGANYCAST
 *
 * Pre-v9 `--learn` / `--spray` flags are gone — the target has
 * one mode (SPRAY) and is direction-determined by the chain it's
 * installed in.
 */
#include <stdio.h>
#include <xtables.h>
#include "xt_WGANYCAST.h"

static void wganycast_help(void)
{
	printf("WGANYCAST target options:\n"
	       "    (no arguments)\n"
	       "\n"
	       "  Install in raw OUTPUT to rewrite outbound WG packets'\n"
	       "  destination to a random entry from a per-session pool\n"
	       "  learned from observed inbound traffic.  The pool capacity\n"
	       "  is %u entries per session (LRU eviction on overflow).\n"
	       "\n"
	       "  To enable LEARN on inbound, attach the WGANYCAST conntrack\n"
	       "  helper to WG ingress via:\n"
	       "    iptables -t raw -A PREROUTING -p udp --dport <port> \\\n"
	       "             -j CT --helper WGANYCAST\n",
	       XT_WGANYCAST_POOL_MAX);
}

static struct xtables_target wganycast_reg = {
	.version       = XTABLES_VERSION,
	.name          = "WGANYCAST",
	.revision      = 0,
	.family        = NFPROTO_IPV4,
	.size          = 0,
	.userspacesize = 0,
	.help          = wganycast_help,
};

static __attribute__((constructor)) void wganycast_ldr(void)
{
	xtables_register_target(&wganycast_reg);
}
