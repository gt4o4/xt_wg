// SPDX-License-Identifier: GPL-2.0-only
/*
 * Author: Bingchen Gong <gongbingchen@gmail.com>
 *
 * iptables WGANYCAST target plugin — v10 (optional --init-pool).
 *
 * Install in `raw` OUTPUT to rewrite outbound WG packets' iph->daddr
 * (+ udph->dest) to a random entry chosen from:
 *
 *   1. A per-session pool learned from observed inbound traffic
 *      (steady-state, when the WG flow has a master ct).
 *   2. A static `--init-pool` carried on the rule (cold-start
 *      fallback, when no master ct exists yet).
 *
 * The static pool is also seeded into master's inline pool once a
 * master is promoted; LRU decay then transitions seamlessly from
 * "static" to "fully learned" as real doors are observed.
 *
 *   iptables -t raw -A OUTPUT -d 193.134.211.67 -p udp --dport 51821 \
 *            -j WGANYCAST --init-pool 138.252.162.176:59263,161.248.136.186:59263
 *
 *   iptables -t raw -A OUTPUT -d 38.38.250.57 -p udp --dport 51821 \
 *            -j WGANYCAST --init-dest 161.248.136.186:50552 \
 *                         --init-dest 138.252.162.176:50552
 *
 *   # No init pool (receiver-side hosts — pool grows from inbound RX):
 *   iptables -t raw -A OUTPUT -p udp --sport 51821 -j WGANYCAST
 *
 * The inbound LEARN side is *not* an iptables target — it's done
 * implicitly via the WGANYCAST conntrack helper.  Attach via the
 * standard `CT` target in BOTH directions:
 *
 *   iptables -t raw -A PREROUTING -p udp --dport 51821 \
 *            -j CT --helper WGANYCAST
 *   iptables -t raw -A OUTPUT     -p udp --dport 51821 \
 *            -j CT --helper WGANYCAST
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
	OPT_INIT_POOL = 0,
	OPT_INIT_DEST,
};

static const struct option wganycast_opts[] = {
	{ .name = "init-pool", .has_arg = true, .val = OPT_INIT_POOL },
	{ .name = "init-dest", .has_arg = true, .val = OPT_INIT_DEST },
	{}
};

static void wganycast_help(void)
{
	printf("WGANYCAST target options:\n"
	       "    --init-pool <ip>[:<port>][,<ip>[:<port>]]...\n"
	       "                              comma-separated cold-start init pool\n"
	       "                              (max %u entries)\n"
	       "    --init-dest <ip>[:<port>] add one entry to the cold-start init\n"
	       "                              pool (repeat flag, max %u entries\n"
	       "                              total; equivalent to --init-pool)\n"
	       "\n"
	       "  Port is optional; when omitted, the packet's existing\n"
	       "  udph->dest is preserved.  --init-pool and --init-dest are\n"
	       "  cumulative — both flags may be combined.  If no init entries\n"
	       "  are given, the target behaves identically to receive-only\n"
	       "  mode: outbound packets are rewritten only when a per-session\n"
	       "  master ct exists with a non-empty learned pool.\n",
	       XT_WGANYCAST_INIT_MAX, XT_WGANYCAST_INIT_MAX);
}

/* Parse "IP" or "IP:PORT" into (addr, port).  Returns 0 on success,
 * -1 on bad format.  port_out is set to 0 (network-order) when no
 * :port is given. */
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

/* Append one (ip, port) tuple to info->init[], bumping ninit.
 * xtables_error()s out on overflow / malformed input. */
static void append_init_entry(struct xt_wganycast_info *info,
			      const char *s, const char *opt)
{
	struct in_addr addr;
	__be16 port;

	if (info->ninit >= XT_WGANYCAST_INIT_MAX)
		xtables_error(PARAMETER_PROBLEM,
			"WGANYCAST: too many init entries (max %u)",
			XT_WGANYCAST_INIT_MAX);
	if (parse_addr_port(s, &addr, &port) < 0)
		xtables_error(PARAMETER_PROBLEM,
			"WGANYCAST: bad %s \"%s\" (expected IP or IP:PORT)",
			opt, s);
	info->init[info->ninit].ip   = addr.s_addr;
	info->init[info->ninit].port = port;
	info->init[info->ninit]._pad = 0;
	info->ninit++;
}

static int wganycast_parse(int c, char **argv, int invert,
			   unsigned int *flags, const void *entry,
			   struct xt_entry_target **tgt)
{
	struct xt_wganycast_info *info = (void *)(*tgt)->data;
	char *spec, *next;

	switch (c) {
	case OPT_INIT_POOL: {
		/* `optarg` is a mutable string in the parse callback —
		 * splice on commas in place. */
		char buf[512];

		if (strlen(optarg) >= sizeof(buf))
			xtables_error(PARAMETER_PROBLEM,
				"WGANYCAST: --init-pool string too long");
		strncpy(buf, optarg, sizeof(buf) - 1);
		buf[sizeof(buf) - 1] = '\0';

		for (spec = buf; spec && *spec; spec = next) {
			next = strchr(spec, ',');
			if (next)
				*next++ = '\0';
			append_init_entry(info, spec, "--init-pool entry");
		}
		return true;
	}

	case OPT_INIT_DEST:
		append_init_entry(info, optarg, "--init-dest");
		return true;
	}

	return false;
}

static void wganycast_check(unsigned int flags)
{
	/* No required options — empty init pool is fine for
	 * receiver-side hosts. */
}

static void print_init(const struct xt_wganycast_init_entry *e)
{
	char buf[INET_ADDRSTRLEN];
	struct in_addr a = { .s_addr = e->ip };

	inet_ntop(AF_INET, &a, buf, sizeof(buf));
	if (e->port)
		printf("%s:%u", buf, ntohs(e->port));
	else
		printf("%s", buf);
}

static void wganycast_print(const void *entry,
			    const struct xt_entry_target *tgt, int numeric)
{
	const struct xt_wganycast_info *info = (const void *)tgt->data;
	unsigned i;

	if (info->ninit == 0)
		return;

	printf(" --init-pool ");
	for (i = 0; i < info->ninit; i++) {
		if (i > 0)
			printf(",");
		print_init(&info->init[i]);
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
	.revision      = 1,
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
