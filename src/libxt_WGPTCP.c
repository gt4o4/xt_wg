// SPDX-License-Identifier: GPL-2.0-only
/*
 * Author: Bingchen Gong <gongbingchen@gmail.com>
 *
 * iptables WGPTCP target plugin
 */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>
#include <stdint.h>
#include <errno.h>
#include <getopt.h>
#include <xtables.h>
#include "xt_WGPTCP.h"

enum {
	OPT_ENCODE = 0,
	OPT_DECODE,
	OPT_KEY,
	OPT_OBFS,
};

/* `*flags` bits — set per-invocation in xtables_target.parse() so we can
 * detect mutual exclusion / repetition without inspecting `info` (which
 * has ENCODE=0 as a valid default and would falsely trigger on a freshly
 * zeroed struct).
 */
#define F_ENCODE (1u << 0)
#define F_DECODE (1u << 1)
#define F_KEY    (1u << 2)
#define F_OBFS   (1u << 3)

static const struct option wgptcp_opts[] = {
	{ .name = "encode", .has_arg = false, .val = OPT_ENCODE },
	{ .name = "decode", .has_arg = false, .val = OPT_DECODE },
	{ .name = "key",    .has_arg = true,  .val = OPT_KEY },
	{ .name = "obfs",   .has_arg = false, .val = OPT_OBFS },
	{}
};

static void wgptcp_help(void)
{
	printf("WGPTCP target options:\n"
	       "    --encode             rewrite UDP → fake-TCP with WG-protocol-aware shape\n"
	       "    --decode             reverse: fake-TCP → UDP\n"
	       "    --key <32 hex chars> 16-byte key for siphash-derived cookie marker\n"
	       "                         and (when --obfs is set) WGOBFS chacha key\n"
	       "                         (default: fixed sentinel cookie 0xC07F0001,\n"
	       "                          --obfs requires --key)\n"
	       "    --obfs               also apply WGOBFS-style payload obfuscation:\n"
	       "                         chacha-XOR the first 16 bytes of the WG message,\n"
	       "                         append random padding (length encoded in last\n"
	       "                         byte), drop ~80%% of WG keepalives, mac2-zero\n"
	       "                         restoration on handshake messages.  Requires\n"
	       "                         --key; chacha key = key||key (32 bytes).\n"
	       "\n"
	       "  --encode and --decode are mutually exclusive; exactly one is required.\n"
	       "  Decoder rule MUST be installed in `raw` PREROUTING (priority -300,\n"
	       "  before conntrack at -200) so the kernel TCP stack never sees the\n"
	       "  fake TCP packet — this is what avoids the need for `-j DROP` rules.\n"
	       "  Encoder rule belongs in any chain after routing (typically OUTPUT\n"
	       "  mangle).\n");
}

static int parse_hex_key(const char *hex, uint8_t *out, size_t outlen)
{
	size_t i;

	if (strlen(hex) != outlen * 2)
		return -1;
	for (i = 0; i < outlen; i++) {
		char c1 = hex[i * 2];
		char c2 = hex[i * 2 + 1];
		int v1, v2;

		if (!isxdigit((unsigned char)c1) ||
		    !isxdigit((unsigned char)c2))
			return -1;
		v1 = (c1 >= '0' && c1 <= '9') ? (c1 - '0')
		   : (c1 >= 'a' && c1 <= 'f') ? (c1 - 'a' + 10)
		   :                            (c1 - 'A' + 10);
		v2 = (c2 >= '0' && c2 <= '9') ? (c2 - '0')
		   : (c2 >= 'a' && c2 <= 'f') ? (c2 - 'a' + 10)
		   :                            (c2 - 'A' + 10);
		out[i] = (uint8_t)((v1 << 4) | v2);
	}
	return 0;
}

static int wgptcp_parse(int c, char **argv, int invert, unsigned int *flags,
			const void *entry, struct xt_entry_target **tgt)
{
	struct xt_wgptcp_info *info = (void *)(*tgt)->data;

	switch (c) {
	case OPT_ENCODE:
		if (*flags & F_DECODE)
			xtables_error(PARAMETER_PROBLEM,
				"WGPTCP: --encode and --decode are mutually exclusive");
		if (*flags & F_ENCODE)
			xtables_error(PARAMETER_PROBLEM,
				"WGPTCP: --encode can only be specified once");
		info->mode = XT_WGPTCP_MODE_ENCODE;
		*flags |= F_ENCODE;
		return true;

	case OPT_DECODE:
		if (*flags & F_ENCODE)
			xtables_error(PARAMETER_PROBLEM,
				"WGPTCP: --encode and --decode are mutually exclusive");
		if (*flags & F_DECODE)
			xtables_error(PARAMETER_PROBLEM,
				"WGPTCP: --decode can only be specified once");
		info->mode = XT_WGPTCP_MODE_DECODE;
		*flags |= F_DECODE;
		return true;

	case OPT_KEY:
		if (*flags & F_KEY)
			xtables_error(PARAMETER_PROBLEM,
				"WGPTCP: --key can only be specified once");
		if (parse_hex_key(optarg, info->key,
				  XT_WGPTCP_KEY_SIZE) < 0)
			xtables_error(PARAMETER_PROBLEM,
				"WGPTCP: --key must be exactly %d hex characters",
				XT_WGPTCP_KEY_SIZE * 2);
		info->has_key = 1;
		/* Derive a 32-byte chacha key for the optional --obfs payload
		 * mangling: obfs_key = key || key.  Always set; kernel only
		 * uses it when info->has_obfs is true.
		 */
		memcpy(info->obfs_key,                      info->key,
		       XT_WGPTCP_KEY_SIZE);
		memcpy(info->obfs_key + XT_WGPTCP_KEY_SIZE, info->key,
		       XT_WGPTCP_KEY_SIZE);
		*flags |= F_KEY;
		return true;

	case OPT_OBFS:
		if (*flags & F_OBFS)
			xtables_error(PARAMETER_PROBLEM,
				"WGPTCP: --obfs can only be specified once");
		info->has_obfs = 1;
		*flags |= F_OBFS;
		return true;
	}

	return false;
}

static void wgptcp_check(unsigned int flags)
{
	if (!(flags & (F_ENCODE | F_DECODE)))
		xtables_error(PARAMETER_PROBLEM,
			"WGPTCP: --encode or --decode is required");
	if ((flags & F_OBFS) && !(flags & F_KEY))
		xtables_error(PARAMETER_PROBLEM,
			"WGPTCP: --obfs requires --key (chacha key = key||key)");
}

static void wgptcp_print(const void *entry,
			 const struct xt_entry_target *tgt, int numeric)
{
	const struct xt_wgptcp_info *info = (const void *)tgt->data;

	if (info->mode == XT_WGPTCP_MODE_ENCODE)
		printf(" --encode");
	else if (info->mode == XT_WGPTCP_MODE_DECODE)
		printf(" --decode");

	if (info->has_key) {
		size_t i;
		printf(" --key ");
		for (i = 0; i < XT_WGPTCP_KEY_SIZE; i++)
			printf("%02x", info->key[i]);
	}
	if (info->has_obfs)
		printf(" --obfs");
}

static void wgptcp_save(const void *entry,
			const struct xt_entry_target *tgt)
{
	wgptcp_print(entry, tgt, 0);
}

static struct xtables_target wgptcp_reg = {
	.version       = XTABLES_VERSION,
	.name          = "WGPTCP",
	.revision      = 0,
	.family        = NFPROTO_IPV4,
	.size          = XT_ALIGN(sizeof(struct xt_wgptcp_info)),
	.userspacesize = XT_ALIGN(sizeof(struct xt_wgptcp_info)),
	.help          = wgptcp_help,
	.parse         = wgptcp_parse,
	.final_check   = wgptcp_check,
	.print         = wgptcp_print,
	.save          = wgptcp_save,
	.extra_opts    = wgptcp_opts,
};

static __attribute__((constructor)) void wgptcp_ldr(void)
{
	xtables_register_target(&wgptcp_reg);
}
