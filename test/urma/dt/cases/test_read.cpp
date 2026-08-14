/* SPDX-License-Identifier: MIT */
/* 自动生成：gen_baseline gen_test <src.c> <expected.txt> <out.cpp>
 * 由 baseline 生成器从测试源 + 录制基准合成。改源改基准后重生成，勿手编。 */

#include <gtest/gtest.h>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <cstdint>
#include <unistd.h>
#include "dt_fixture.hpp"
#include "baseline_macros.h"

#define SEG_LEN 4096
TEST(test_read, Run)
{
    dt_ctx_t *c = NULL;
    char *src = NULL;
    char *dst = NULL;
    urma_target_seg_t *tseg = NULL;
    urma_target_seg_t *dst_tseg = NULL;
    urma_target_jetty_t *tj = NULL;
    int ret = -1;
    int n = 0;
    urma_cr_t cr = {};

    c = dt_setup(0, URMA_TM_UM);
    ASSERT_NE(nullptr, c);
    if (c == NULL) {
        goto cleanup;
    }
    ASSERT_NE(nullptr, c->jfc);
    ASSERT_NE(nullptr, c->jfr);
    ASSERT_NE(nullptr, c->jetty);
    if (c->jfc == NULL || c->jfr == NULL || c->jetty == NULL) {
        goto cleanup;
    }

    src = static_cast<char *>(calloc(1, SEG_LEN));
    ASSERT_NE(nullptr, src);
    if (src == NULL) {
        goto cleanup;
    }
    memset(src, 'A', SEG_LEN);
    tseg = dt_register_seg(c, src, SEG_LEN);
    ASSERT_NE(nullptr, tseg);
    if (tseg == NULL) {
        goto cleanup;
    }

    dst = static_cast<char *>(calloc(1, SEG_LEN));
    ASSERT_NE(nullptr, dst);
    if (dst == NULL) {
        goto cleanup;
    }
    memset(dst, 'Z', SEG_LEN);
    dst_tseg = dt_register_seg(c, dst, SEG_LEN);
    ASSERT_NE(nullptr, dst_tseg);
    if (dst_tseg == NULL) {
        goto cleanup;
    }
    tj = dt_import_self(c);
    ASSERT_NE(nullptr, tj);
    if (tj == NULL) {
        goto cleanup;
    }

    ret = dt_post_read(c, tj, dst, dst_tseg, src, tseg, SEG_LEN, 0x42);
    EXPECT_EQ(0, ret);

    n = dt_poll_cr(c, &cr);
    EXPECT_EQ(1, n);
    EXPECT_EQ(0, cr.status);
    EXPECT_EQ(0x42, cr.user_ctx);
    EXPECT_EQ(0, strncmp("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", dst, strlen("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")));
    EXPECT_EQ(65, dst[0]);

cleanup:
    if (tj) {
        urma_unimport_jetty(tj);
    }
    free(dst);
    free(src);
    if (c) {
        dt_teardown(c);
    }
}

