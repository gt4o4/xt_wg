/*
 * iptables WGANYCAST target plugin
 */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <getopt.h>
#include <arpa/inet.h>
#include <xtables.h>
#include "xt_WGANYCAST.h"

enum {
	OPT_DEST = 0,
	OPT_CANONICAL,
};

/* `*flags` bits — tracked per-invocation in xtables_target.parse() so we
 * can detect mutual exclusion / repetition without inspecting `info`
 * (which has SPRAY=0 as a default and would falsely trigger on a
 * freshly-zeroed struct).
 */
#define F_SPRAY     (1u << 0)
#define F_CANONICAL (1u << 1)

static const struct option wganycast_opts[] = {
	{ .name = "dest",      .has_arg = true, .val = OPT_DEST },
	{ .name = "canonical", .has_arg = true, .val = OPT_CANONICAL },
	{}
};

static void wganycast_help(void)
{
	printf("WGANYCAST target options:\n"
	       "    --dest <ip>[:<port>]      spray packets to this IP[:port]\n"
	       "                              (repeat for pool, max %d entries)\n"
	       "    --canonical <ip>[:<port>] rewrite source IP[:port] to this\n"
	       "\n"
	       "  Port is optional; when omitted, the packet's existing port is\n"
	       "  preserved. --dest is for OUTPUT/POSTROUTING (per-packet random\n"
	       "  destination selection across the pool). --canonical is for\n"
	       "  PREROUTING (canonicalise replies from any anycast IP back to a\n"
	       "  single source so WireGuard roaming stays pinned). The two flags\n"
	       "  are mutually exclusive.\n",
	       XT_WGANYCAST_MAX_DESTS);
}

/* Parse "IP" or "IP:PORT" into (addr, port). Returns 0 on success, -1 on
 * bad format. port_out is set to 0 (network-order) when no :port given.
 */
static int parse_addr_port(const char *s, struct in_addr *addr_out,
			   __be16 *port_out)
{
	char buf[64];
	char *colon;
	unsigned long p;

	if (strlen(s) >= sizeof(buf))
		return -1;
	strncpy(buf, s, sizeof(buf) - 1);
	buf[sizeof(buf) - 1] = '\0';

	colon = strrchr(buf, ':');
	if (colon) {
		*colon = '\0';
		p = strtoul(colon + 1, NULL, 10);
		if (p == 0 || p > 65535)
			return -1;
		*port_out = htons((uint16_t)p);
	} else {
		*port_out = 0;
	}

	if (!inet_aton(buf, addr_out))
		return -1;
	return 0;
}

static int wganycast_parse(int c, char **argv, int invert, unsigned int *flags,
			   const void *entry, struct xt_entry_target **tgt)
{
	struct xt_wganycast_info *info = (void *)(*tgt)->data;
	struct in_addr addr;
	__be16 port;

	switch (c) {
	case OPT_DEST:
		if (*flags & F_CANONICAL)
			xtables_error(PARAMETER_PROBLEM,
				"WGANYCAST: --dest and --canonical are mutually exclusive");
		if (info->ndests >= XT_WGANYCAST_MAX_DESTS)
			xtables_error(PARAMETER_PROBLEM,
				"WGANYCAST: too many --dest entries (max %d)",
				XT_WGANYCAST_MAX_DESTS);
		if (parse_addr_port(optarg, &addr, &port) < 0)
			xtables_error(PARAMETER_PROBLEM,
				"WGANYCAST: bad --dest \"%s\" (expected IP or IP:PORT)",
				optarg);
		info->mode = XT_WGANYCAST_MODE_SPRAY;
		info->dests[info->ndests].ip = addr.s_addr;
		info->dests[info->ndests].port = port;
		info->ndests++;
		*flags |= F_SPRAY;
		return true;

	case OPT_CANONICAL:
		if (*flags & F_SPRAY)
			xtables_error(PARAMETER_PROBLEM,
				"WGANYCAST: --dest and --canonical are mutually exclusive");
		if (*flags & F_CANONICAL)
			xtables_error(PARAMETER_PROBLEM,
				"WGANYCAST: --canonical can only be specified once");
		if (parse_addr_port(optarg, &addr, &port) < 0)
			xtables_error(PARAMETER_PROBLEM,
				"WGANYCAST: bad --canonical \"%s\" (expected IP or IP:PORT)",
				optarg);
		info->mode = XT_WGANYCAST_MODE_CANONICAL;
		info->dests[0].ip = addr.s_addr;
		info->dests[0].port = port;
		info->ndests = 1;
		*flags |= F_CANONICAL;
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

static void print_dest(const struct xt_wganycast_dest *d, const char *opt)
{
	char buf[INET_ADDRSTRLEN];
	struct in_addr a = { .s_addr = d->ip };
	inet_ntop(AF_INET, &a, buf, sizeof(buf));
	if (d->port)
		printf(" %s %s:%u", opt, buf, ntohs(d->port));
	else
		printf(" %s %s", opt, buf);
}

static void wganycast_print(const void *entry,
			    const struct xt_entry_target *tgt, int numeric)
{
	const struct xt_wganycast_info *info = (const void *)tgt->data;
	int i;

	if (info->mode == XT_WGANYCAST_MODE_SPRAY) {
		for (i = 0; i < info->ndests; i++)
			print_dest(&info->dests[i], "--dest");
	} else if (info->mode == XT_WGANYCAST_MODE_CANONICAL) {
		print_dest(&info->dests[0], "--canonical");
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
