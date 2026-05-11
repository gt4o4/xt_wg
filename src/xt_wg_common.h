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

/* WG message-type byte (first byte of UDP payload).  Shared by
 * xt_WGPTCP_main.c (encoder validation, refire gating) and
 * xt_WGANYCAST_main.c (LEARN/SPRAY type-byte filter + session-index
 * extraction).
 */
#define WG_TYPE_INIT	0x01u
#define WG_TYPE_RESP	0x02u
#define WG_TYPE_COOKIE	0x03u
#define WG_TYPE_DATA	0x04u

/* WG header field offsets within the UDP payload (start = type byte).
 *
 *   type=1 INIT  : [type 1][reserved 3][sender_index 4][...]
 *   type=2 RESP  : [type 1][reserved 3][sender_index 4][receiver_index 4][...]
 *   type=3 COOKIE: [type 1][reserved 3][receiver_index 4][...]
 *   type=4 DATA  : [type 1][reserved 3][receiver_index 4][counter 8][...]
 *
 * type byte itself is offset 0; the 32-bit index fields start at the
 * post-reserved-3-byte slot, which is offset 4.
 */
#define WG_OFF_SENDER_IDX_INIT	4u
#define WG_OFF_SENDER_IDX_RESP	4u
#define WG_OFF_RECEIVER_IDX_RESP	8u
#define WG_OFF_RECEIVER_IDX_COOKIE	4u
#define WG_OFF_RECEIVER_IDX_DATA	4u

extern struct xt_target xt_wgobfs_targets[];
extern const unsigned int xt_wgobfs_targets_n;

extern struct xt_target xt_wganycast_targets[];
extern const unsigned int xt_wganycast_targets_n;

/* WGANYCAST registers a no-op nf_conntrack_helper alongside its xt
 * target — see xt_WGANYCAST_main.c for why.  The consolidated
 * xt_wg.ko init/exit calls these to register/unregister the helper.
 */
int xt_wganycast_module_init(void);
void xt_wganycast_module_exit(void);

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
