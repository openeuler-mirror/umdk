/* SPDX-License-Identifier: MIT */
/*
 * DT case: control-plane object lifecycle (liburma core create/delete paths).
 * Covers standalone JFS/JFR creation and deletion, the extra JFCE/JFC lifecycle,
 * and token id alloc/free.
 */

#include <gtest/gtest.h>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <unistd.h>

#include "dt_fixture.hpp"
#include "baseline_macros.h"

TEST(test_obj_lifecycle, Run)
{
    dt_ctx_t *c = dt_setup(0, URMA_TM_UM);
    ASSERT_NE(nullptr, c);
    ASSERT_NE(nullptr, c->ctx);
    ASSERT_NE(nullptr, c->jfc);

    urma_jfs_cfg_t jfs_cfg = {};
    jfs_cfg.depth = 64;
    jfs_cfg.max_sge = 2;
    jfs_cfg.max_rsge = 2;
    jfs_cfg.max_inline_data = 32;
    jfs_cfg.trans_mode = URMA_TM_UM;
    jfs_cfg.jfc = c->jfc;
    urma_jfs_t *jfs = urma_create_jfs(c->ctx, &jfs_cfg);
    EXPECT_NE(nullptr, jfs);
    if (jfs != nullptr) {
        EXPECT_EQ(URMA_SUCCESS, urma_delete_jfs(jfs));
    }

    urma_jfr_cfg_t jfr_cfg = {};
    jfr_cfg.depth = 64;
    jfr_cfg.max_sge = 2;
    jfr_cfg.trans_mode = URMA_TM_UM;
    jfr_cfg.jfc = c->jfc;
    urma_jfr_t *jfr = urma_create_jfr(c->ctx, &jfr_cfg);
    EXPECT_NE(nullptr, jfr);
    if (jfr != nullptr) {
        EXPECT_EQ(URMA_SUCCESS, urma_delete_jfr(jfr));
    }

    urma_jfce_t *jfce = urma_create_jfce(c->ctx);
    ASSERT_NE(nullptr, jfce);
    urma_jfc_cfg_t jfc_cfg = {};
    jfc_cfg.depth = 64;
    jfc_cfg.jfce = jfce;
    urma_jfc_t *jfc = urma_create_jfc(c->ctx, &jfc_cfg);
    EXPECT_NE(nullptr, jfc);
    if (jfc != nullptr) {
        EXPECT_EQ(URMA_SUCCESS, urma_delete_jfc(jfc));
    }
    EXPECT_EQ(URMA_SUCCESS, urma_delete_jfce(jfce));

    urma_token_id_t *tid = urma_alloc_token_id(c->ctx);
    EXPECT_NE(nullptr, tid);
    if (tid != nullptr) {
        EXPECT_EQ(URMA_SUCCESS, urma_free_token_id(tid));
    }
    DT_WRITE_VAL("obj_lifecycle_done", 1);

    dt_teardown(c);
}
