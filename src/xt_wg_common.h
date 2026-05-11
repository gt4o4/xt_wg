/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Author: Bingchen Gong <gongbingchen@gmail.com>
 *
 * Shared declarations for the consolidated xt_wg.ko module.
 *
 * Each target translation unit (xt_WGOBFS_main.c, xt_WGANYCAST_main.c,
 * xt_WGPTCP_main.c) exposes its `xt_target[]` array as a non-static
 * symbol so the central xt_wg_main.c can register all three from a
 * single module_init.  This means:
 *
 *   - One .ko file (xt_wg.ko) instead of three separate .ko's;
 *   - Shared chacha.o, no duplication across modules;
 *   - One modprobe; backward-compat via per-target MODULE_ALIAS so
 *     `modprobe xt_WGOBFS` / `xt_WGANYCAST` / `xt_WGPTCP` all still
 *     resolve to xt_wg.ko via the kernel's modalias lookup;
 *   - Easy code reuse — e.g. WGPTCP's `--obfs` mode can call the
 *     same chacha-based payload obfuscation that WGOBFS does.
 */
#ifndef _XT_WG_COMMON_H
#define _XT_WG_COMMON_H

#include <linux/netfilter/x_tables.h>
#include <linux/skbuff.h>

extern struct xt_target xt_wgobfs_targets[];
extern const unsigned int xt_wgobfs_targets_n;

extern struct xt_target xt_wganycast_targets[];
extern const unsigned int xt_wganycast_targets_n;

extern struct xt_target xt_wgptcp_targets[];
extern const unsigned int xt_wgptcp_targets_n;

/* WGOBFS payload-mangling helpers — exposed so xt_WGPTCP's --obfs
 * mode can apply the same chacha-keyed obfuscation before/after its
 * fake-TCP wrap.  See xt_WGOBFS_main.c for the per-byte details.
 *
 * Both operate on the UDP payload of a UDP-shaped skb.  Caller must
 * update IP / UDP headers (tot_len + checksum) for the size delta.
 *
 * `chacha_key` is the 32-byte chacha key (XT_CHACHA_KEY_SIZE in
 * xt_WGOBFS.h).  Both ends must use the same key.
 */
unsigned int wg_obfs_payload(struct sk_buff *skb, u8 *rnd_len_out,
                             const u8 *chacha_key);
int wg_unobfs_payload(struct sk_buff *skb, u8 *rnd_len_out,
                      const u8 *chacha_key);

#endif
