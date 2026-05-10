/*
 * iptables WGANYCAST target plugin
 */
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <getopt.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <xtables.h>
#include "xt_WGANYCAST.h"

enum {
	OPT_DEST = 0,
	OPT_CANONICAL,
};

static const struct option wganycast_opts[] = {
	{ .name = "dest",      .has_arg = true, .val = OPT_DEST },
	{ .name = "canonical", .has_arg = true, .val = OPT_CANONICAL },
	{}
};

static void wganycast_help(void)
{
	printf("WGANYCAST target options:\n"
	       "    --dest <ip>          spray packets to this IP (repeat for pool, max %d)\n"
	       "    --canonical <ip>     rewrite source IP to <ip>\n"
	       "\n"
	       "  --dest is for OUTPUT/POSTROUTING (per-packet random destination\n"
	       "  selection across the pool). --canonical is for PREROUTING\n"
	       "  (canonicalise replies from any anycast IP back to a single\n"
	       "  source so WireGuard roaming stays pinned). The two flags are\n"
	       "  mutually exclusive.\n",
	       XT_WGANYCAST_MAX_DESTS);
}

static int wganycast_parse(int c, char **argv, int invert, unsigned int *flags,
			   const void *entry, struct xt_entry_target **tgt)
{
	struct xt_wganycast_info *info = (void *)(*tgt)->data;
	struct in_addr addr;

	switch (c) {
	case OPT_DEST:
		if (info->mode == XT_WGANYCAST_MODE_CANONICAL)
			xtables_error(PARAMETER_PROBLEM,
				"WGANYCAST: --dest and --canonical are mutually exclusive");
		if (info->ndests >= XT_WGANYCAST_MAX_DESTS)
			xtables_error(PARAMETER_PROBLEM,
				"WGANYCAST: too many --dest entries (max %d)",
				XT_WGANYCAST_MAX_DESTS);
		if (!inet_aton(optarg, &addr))
			xtables_error(PARAMETER_PROBLEM,
				"WGANYCAST: bad --dest address: %s", optarg);
		info->mode = XT_WGANYCAST_MODE_SPRAY;
		info->dests[info->ndests++] = addr.s_addr;
		*flags |= 1;
		return true;

	case OPT_CANONICAL:
		if (info->mode == XT_WGANYCAST_MODE_SPRAY)
			xtables_error(PARAMETER_PROBLEM,
				"WGANYCAST: --dest and --canonical are mutually exclusive");
		if (info->ndests > 0)
			xtables_error(PARAMETER_PROBLEM,
				"WGANYCAST: --canonical can only be specified once");
		if (!inet_aton(optarg, &addr))
			xtables_error(PARAMETER_PROBLEM,
				"WGANYCAST: bad --canonical address: %s", optarg);
		info->mode = XT_WGANYCAST_MODE_CANONICAL;
		info->dests[0] = addr.s_addr;
		info->ndests = 1;
		*flags |= 1;
		return true;
	}

	return false;
}

static void wganycast_check(unsigned int flags)
{
	if (!flags)
		xtables_error(PARAMETER_PROBLEM,
			"WGANYCAST: --dest or --canonical is required");
}

static void wganycast_print(const void *entry,
			    const struct xt_entry_target *tgt, int numeric)
{
	const struct xt_wganycast_info *info = (const void *)tgt->data;
	char buf[INET_ADDRSTRLEN];
	struct in_addr a;
	int i;

	if (info->mode == XT_WGANYCAST_MODE_SPRAY) {
		for (i = 0; i < info->ndests; i++) {
			a.s_addr = info->dests[i];
			inet_ntop(AF_INET, &a, buf, sizeof(buf));
			printf(" --dest %s", buf);
		}
	} else if (info->mode == XT_WGANYCAST_MODE_CANONICAL) {
		a.s_addr = info->dests[0];
		inet_ntop(AF_INET, &a, buf, sizeof(buf));
		printf(" --canonical %s", buf);
	}
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
