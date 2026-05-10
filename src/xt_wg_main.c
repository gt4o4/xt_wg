// SPDX-License-Identifier: GPL-2.0-only
/*
 * xt_wg.ko — consolidated entry point for the WireGuard helper xtables
 * targets:
 *
 *   - WGOBFS    — chacha-keyed payload obfuscation
 *   - WGANYCAST — stateless per-packet UDP destination spray
 *   - WGPTCP    — WG-protocol-aware UDP↔fake-TCP transmutation
 *
 * Each target's xt_target[] array lives in its own translation unit
 * (xt_WGOBFS_main.c / xt_WGANYCAST_main.c / xt_WGPTCP_main.c) and is
 * declared in xt_wg_common.h.  This file just glues them together
 * with one module_init that registers all three (atomically — if any
 * fails, the earlier ones are unregistered before propagating the
 * error).
 *
 * Backward compatibility: a separate MODULE_ALIAS for each target
 * name + family means `modprobe xt_WGOBFS` (or any of the others)
 * still loads xt_wg.ko via the kernel's modalias resolution.
 */

#include <linux/module.h>
#include <linux/netfilter/x_tables.h>
#include "xt_wg_common.h"

static int __init xt_wg_init(void)
{
	int rc;

	rc = xt_register_targets(xt_wgobfs_targets, xt_wgobfs_targets_n);
	if (rc)
		return rc;

	rc = xt_register_targets(xt_wganycast_targets, xt_wganycast_targets_n);
	if (rc)
		goto err_anycast;

	rc = xt_register_targets(xt_wgptcp_targets, xt_wgptcp_targets_n);
	if (rc)
		goto err_ptcp;

	return 0;

err_ptcp:
	xt_unregister_targets(xt_wganycast_targets, xt_wganycast_targets_n);
err_anycast:
	xt_unregister_targets(xt_wgobfs_targets, xt_wgobfs_targets_n);
	return rc;
}

static void __exit xt_wg_exit(void)
{
	xt_unregister_targets(xt_wgptcp_targets, xt_wgptcp_targets_n);
	xt_unregister_targets(xt_wganycast_targets, xt_wganycast_targets_n);
	xt_unregister_targets(xt_wgobfs_targets, xt_wgobfs_targets_n);
}

module_init(xt_wg_init);
module_exit(xt_wg_exit);

MODULE_LICENSE("GPL v2");
MODULE_DESCRIPTION("xtables WireGuard helpers: WGOBFS + WGANYCAST + WGPTCP");
MODULE_AUTHOR("Wei Chen <weichen302@gmail.com>");
MODULE_VERSION("0.7.0");

/* Backward-compat aliases — modprobe by old per-target name still
 * resolves to xt_wg.ko.  iptables auto-loads via modprobe when a rule
 * uses `-j WGOBFS` etc., and the kernel's request_module path
 * prepends the family prefix, so we need each combination.
 */
MODULE_ALIAS("xt_WGOBFS");
MODULE_ALIAS("ipt_WGOBFS");
MODULE_ALIAS("ip6t_WGOBFS");
MODULE_ALIAS("xt_WGANYCAST");
MODULE_ALIAS("ipt_WGANYCAST");
MODULE_ALIAS("xt_WGPTCP");
MODULE_ALIAS("ipt_WGPTCP");
