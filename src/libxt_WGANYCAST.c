// SPDX-License-Identifier: GPL-2.0-only
/*
 * Author: Bingchen Gong <gongbingchen@gmail.com>
 *
 * iptables WGANYCAST target plugin — v3 (LEARN / SPRAY).
 *
 * Two modes, no other arguments:
 *
 *   --learn   for `raw` PREROUTING.  Observe inbound WG packets,
 *             register/refresh permanent expectations under a
 *             per-session anchor conntrack.
 *
 *   --spray   for `raw` OUTPUT.  Look up the anchor by WG receiver
 *             index, pick a random anycast door from the anchor's
 *             expectations, rewrite iph->daddr (+ udph->dest if the
 *             entry's port differs).  Empty pool → packet goes to
 *             WG's configured peer.endpoint as-is.
 *
 * Pre-v3 `--dest` / `--canonical` are gone — the door pool is now
 * dynamic and learned from observed WG handshake/data traffic.
 */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <getopt.h>
#include <xtables.h>
#include "xt_WGANYCAST.h"

enum {
	OPT_LEARN = 0,
	OPT_SPRAY,
};

#define F_LEARN	(1u << 0)
#define F_SPRAY	(1u << 1)

static const struct option wganycast_opts[] = {
	{ .name = "learn", .has_arg = false, .val = OPT_LEARN },
	{ .name = "spray", .has_arg = false, .val = OPT_SPRAY },
	{}
};

static void wganycast_help(void)
{
	printf("WGANYCAST target options:\n"
	       "    --learn    observe inbound WG packets and learn the anycast\n"
	       "               source pool (raw PREROUTING)\n"
	       "    --spray    rewrite outbound WG dst to a random pool entry\n"
	       "               for the current session (raw OUTPUT)\n"
	       "\n"
	       "  Exactly one of --learn or --spray is required.  No pool is\n"
	       "  configured at the rule level; per-session anchor conntracks\n"
	       "  encode (Sa, our_idx) / (Sa, peer_idx) and self-reap via\n"
	       "  standard conntrack GC.  Pool capacity is %u entries per\n"
	       "  anchor (LRU eviction on overflow).\n",
	       XT_WGANYCAST_POOL_MAX);
}

static int wganycast_parse(int c, char **argv, int invert, unsigned int *flags,
			   const void *entry, struct xt_entry_target **tgt)
{
	struct xt_wganycast_info *info = (void *)(*tgt)->data;

	switch (c) {
	case OPT_LEARN:
		if (*flags & F_SPRAY)
			xtables_error(PARAMETER_PROBLEM,
				"WGANYCAST: --learn and --spray are mutually exclusive");
		if (*flags & F_LEARN)
			xtables_error(PARAMETER_PROBLEM,
				"WGANYCAST: --learn can only be specified once");
		info->mode = XT_WGANYCAST_MODE_LEARN;
		*flags |= F_LEARN;
		return true;

	case OPT_SPRAY:
		if (*flags & F_LEARN)
			xtables_error(PARAMETER_PROBLEM,
				"WGANYCAST: --learn and --spray are mutually exclusive");
		if (*flags & F_SPRAY)
			xtables_error(PARAMETER_PROBLEM,
				"WGANYCAST: --spray can only be specified once");
		info->mode = XT_WGANYCAST_MODE_SPRAY;
		*flags |= F_SPRAY;
		return true;
	}

	return false;
}

static void wganycast_check(unsigned int flags)
{
	if (!flags)
		xtables_error(PARAMETER_PROBLEM,
			"WGANYCAST: exactly one of --learn or --spray is required");
}

static void wganycast_print(const void *entry,
			    const struct xt_entry_target *tgt, int numeric)
{
	const struct xt_wganycast_info *info = (const void *)tgt->data;

	if (info->mode == XT_WGANYCAST_MODE_LEARN)
		printf(" --learn");
	else if (info->mode == XT_WGANYCAST_MODE_SPRAY)
		printf(" --spray");
}

static void wganycast_save(const void *entry,
			   const struct xt_entry_target *tgt)
{
	wganycast_print(entry, tgt, 0);
}

static struct xtables_target wganycast_reg = {
	.version       = XTABLES_VERSION,
	.name          = "WGANYCAST",
	.revision      = 0,
	.family        = NFPROTO_IPV4,
	.size          = XT_ALIGN(sizeof(struct xt_wganycast_info)),
	.userspacesize = XT_ALIGN(sizeof(struct xt_wganycast_info)),
	.help          = wganycast_help,
	.parse         = wganycast_parse,
	.final_check   = wganycast_check,
	.print         = wganycast_print,
	.save          = wganycast_save,
	.extra_opts    = wganycast_opts,
};

static __attribute__((constructor)) void wganycast_ldr(void)
{
	xtables_register_target(&wganycast_reg);
}
