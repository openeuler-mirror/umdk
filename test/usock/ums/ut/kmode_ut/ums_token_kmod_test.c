// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2026-2026. All rights reserved.
 *
 * Kmod unit tests for the UMS out-of-band token_value exchange netlink layer.
 *
 * Exercises ums_nl.c (clc_ht ownership model: register/claim/duplicate/
 * unregister/put) and ums_core.c (token_xchg_ctx_init/wait/clc_session_id)
 * directly. Compiled into ums_test.ko alongside ums_api_test.c and invoked from
 * its __init. Relies on the UMS_UT_TEST-guarded EXPORT_SYMBOL_GPL entries in
 * ums.ko (active only under BUILD_WITH_UT=ON).
 *
 * Note: the genl doit handlers (ums_nl_token_deliver / _submit_fail) and the
 * real genlmsg_unicast send path are NOT exercised here -- invoking a doit
 * requires constructing an sk_buff + genl_info, and the send path needs a
 * registered agent (ums_nl_agent_available==true). Those remain covered by the
 * userspace agent + E2E gtest (ums_token_e2e_ut). The wait timeout path is also
 * skipped (UMS_TOKEN_DELIVER_TIMEOUT_MS=5000 would block module init).
 */

#include <linux/kernel.h>
#include <linux/printk.h>
#include <linux/refcount.h>
#include <linux/string.h>
#include <linux/types.h>

#include "ums_mod.h"
#include "ums_nl.h"

static unsigned int g_token_ut_total;
static unsigned int g_token_ut_fail;

#define TOKEN_UT_CHECK(cond)                                                   \
	do {                                                                   \
		g_token_ut_total++;                                           \
		if (!(cond)) {                                                \
			g_token_ut_fail++;                                    \
			pr_err("UMS_TOKEN_UT FAIL [%s] line %d\n", #cond,    \
				__LINE__);                                   \
		}                                                             \
	} while (0)

static const u8 g_test_id[UMS_SYSTEMID_LEN] = {1, 2, 3, 4, 5, 6, 7, 8};

static void token_ut_session_id(void)
{
	u32 s1 = ums_clc_session_id_generate();
	u32 s2 = ums_clc_session_id_generate();

	TOKEN_UT_CHECK(s2 != s1);
	TOKEN_UT_CHECK(s2 == (u32)(s1 + 1)); /* atomic_inc_return */
}

static void token_ut_agent_available_default_false(void)
{
	TOKEN_UT_CHECK(ums_nl_agent_available() == false);
}

static void token_ut_ctx_init(void)
{
	struct ums_token_xchg_ctx ctx;

	ums_token_xchg_ctx_init(&ctx, 0xCAFEBABE, g_test_id);
	TOKEN_UT_CHECK(ctx.clc_session_id == 0xCAFEBABE);
	TOKEN_UT_CHECK(memcmp(ctx.initiator_id, g_test_id, UMS_SYSTEMID_LEN) == 0);
	TOKEN_UT_CHECK(refcount_read(&ctx.nl_refcnt) == 0);
	TOKEN_UT_CHECK(ctx.jetty_token.token == 0);
	TOKEN_UT_CHECK(ctx.seg_token.token == 0);
	TOKEN_UT_CHECK(ctx.peer_seg_token.token == 0);
	TOKEN_UT_CHECK(ctx.peer_jetty_token.token == 0);
}

/* register (SECURE) inserts and sets nl_refcnt=1 (holder A = hash entry). */
static void token_ut_register_and_duplicate(void)
{
	struct ums_token_xchg_ctx ctx;

	ums_token_xchg_ctx_init(&ctx, 0x00010001, g_test_id);
	TOKEN_UT_CHECK(ums_nl_register_clc_session(&ctx) == 0);
	TOKEN_UT_CHECK(refcount_read(&ctx.nl_refcnt) == 1);

	/* duplicate (clc_session_id, initiator_id) rejected */
	TOKEN_UT_CHECK(ums_nl_register_clc_session(&ctx) == -EEXIST);
	TOKEN_UT_CHECK(refcount_read(&ctx.nl_refcnt) == 1);

	/* different initiator_id with same session id coexists (hash collision) */
	struct ums_token_xchg_ctx other;
	u8 other_id[UMS_SYSTEMID_LEN] = {9, 9, 9, 9, 9, 9, 9, 9};

	ums_token_xchg_ctx_init(&other, 0x00010001, other_id);
	TOKEN_UT_CHECK(ums_nl_register_clc_session(&other) == 0);

	/* cleanup: holder A release for both */
	ums_nl_unregister_clc_session(&ctx);
	TOKEN_UT_CHECK(refcount_read(&ctx.nl_refcnt) == 0);
	ums_nl_unregister_clc_session(&other);
	TOKEN_UT_CHECK(refcount_read(&other.nl_refcnt) == 0);
}

/*
 * The core ownership-transfer flow: register (holder A) -> first claim removes
 * the entry and transfers ownership to holder B without changing nl_refcnt ->
 * second claim returns NULL (prevents duplicate TOKEN_DELIVER/_SUBMIT_FAIL
 * callbacks) -> unregister finds nothing (no double-put) -> holder B releases.
 */
static void token_ut_claim_ownership_transfer(void)
{
	struct ums_token_xchg_ctx ctx;
	struct ums_token_xchg_ctx *claimed;

	ums_token_xchg_ctx_init(&ctx, 0x00020002, g_test_id);
	TOKEN_UT_CHECK(ums_nl_register_clc_session(&ctx) == 0);
	TOKEN_UT_CHECK(refcount_read(&ctx.nl_refcnt) == 1);

	claimed = ums_nl_claim_token_ctx(0x00020002, g_test_id);
	TOKEN_UT_CHECK(claimed == &ctx);
	TOKEN_UT_CHECK(refcount_read(&ctx.nl_refcnt) == 1); /* count unchanged */

	/* duplicate claim prevented */
	TOKEN_UT_CHECK(ums_nl_claim_token_ctx(0x00020002, g_test_id) == NULL);

	/* unknown session returns NULL */
	TOKEN_UT_CHECK(ums_nl_claim_token_ctx(0xDEADBEEF, g_test_id) == NULL);

	/* unregister is a no-op: entry already claimed by holder B */
	ums_nl_unregister_clc_session(&ctx);
	TOKEN_UT_CHECK(refcount_read(&ctx.nl_refcnt) == 1);

	/* holder B releases -> 1->0, no waiters so wake_up is harmless */
	ums_token_ctx_nl_put(&ctx);
	TOKEN_UT_CHECK(refcount_read(&ctx.nl_refcnt) == 0);
}

/* wait_token_xchg via the completion path (no 5s timeout blocking). */
static void token_ut_wait_completion(void)
{
	struct ums_token_xchg_ctx ctx;

	ums_token_xchg_ctx_init(&ctx, 0x00030003, g_test_id);

	/* success: pre-complete with 0 */
	ums_token_xchg_init(&ctx.xchg);
	ums_token_xchg_complete(&ctx.xchg, 0);
	TOKEN_UT_CHECK(ums_wait_token_xchg(&ctx) == 0);

	/* failure: pre-complete with -EINVAL */
	ums_token_xchg_init(&ctx.xchg);
	ums_token_xchg_complete(&ctx.xchg, -EINVAL);
	TOKEN_UT_CHECK(ums_wait_token_xchg(&ctx) == -EINVAL);
}

/* submit_tokens: SECURE mode with no agent registered -> -ENOTCONN. */
static void token_ut_submit_no_agent(void)
{
	struct ums_token_xchg_ctx ctx;
	struct ums_ip_addr peer;

	memset(&peer, 0, sizeof(peer));
	peer.family = AF_INET;

	ums_token_xchg_ctx_init(&ctx, 0x00040004, g_test_id);
	TOKEN_UT_CHECK(ums_nl_submit_tokens(&ctx, &peer, true) == -ENOTCONN);
	TOKEN_UT_CHECK(ums_nl_submit_tokens(&ctx, &peer, false) == -ENOTCONN);
}

/*
 * Non-SECURE mode: register/submit/unregister/wait are all no-ops returning 0
 * and must NOT insert into clc_ht or touch nl_refcnt.
 */
static void token_ut_non_secure_mode_noop(void)
{
	struct ums_token_xchg_ctx ctx;
	struct ums_ip_addr peer;
	enum ums_token_mode saved = g_ums_sys_tuning_config.ub_token_mode;

	memset(&peer, 0, sizeof(peer));
	peer.family = AF_INET;

	g_ums_sys_tuning_config.ub_token_mode = UMS_TOKEN_MODE_LEGACY;
	ums_token_xchg_ctx_init(&ctx, 0x00050005, g_test_id);

	TOKEN_UT_CHECK(ums_nl_register_clc_session(&ctx) == 0);
	TOKEN_UT_CHECK(refcount_read(&ctx.nl_refcnt) == 0); /* untouched */
	TOKEN_UT_CHECK(ums_nl_submit_tokens(&ctx, &peer, true) == 0);
	ums_nl_unregister_clc_session(&ctx); /* void no-op */

	ums_token_xchg_init(&ctx.xchg);
	TOKEN_UT_CHECK(ums_wait_token_xchg(&ctx) == 0);

	g_ums_sys_tuning_config.ub_token_mode = UMS_TOKEN_MODE_DISABLE;
	TOKEN_UT_CHECK(ums_nl_register_clc_session(&ctx) == 0);
	TOKEN_UT_CHECK(ums_nl_submit_tokens(&ctx, &peer, false) == 0);

	g_ums_sys_tuning_config.ub_token_mode = saved;
}

void ums_token_kmod_test_run(void)
{
	g_token_ut_total = 0;
	g_token_ut_fail = 0;

	pr_info("UMS_TOKEN_UT: begin\n");
	token_ut_session_id();
	token_ut_agent_available_default_false();
	token_ut_ctx_init();
	token_ut_register_and_duplicate();
	token_ut_claim_ownership_transfer();
	token_ut_wait_completion();
	token_ut_submit_no_agent();
	token_ut_non_secure_mode_noop();

	pr_info("UMS_TOKEN_UT: end, %u checks, %u failures\n",
		g_token_ut_total, g_token_ut_fail);
	if (g_token_ut_fail != 0) {
		WARN_ON(1);
	}
}
