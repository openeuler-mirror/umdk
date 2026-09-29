/* SPDX-License-Identifier: MIT */
/*
 * DT case: WRITE data path (jetty embedded SQ -> remote SGE).
 * Covers urma_post_jetty_send_wr(WRITE), urma_poll_jfc and the CR status/user_ctx restore.
 */

#include <gtest/gtest.h>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <unistd.h>

#include "dt_fixture.hpp"
#include "baseline_macros.h"

#define WR_SEG_LEN 4096

TEST(test_write, Run)
{
    dt_ctx_t *c = dt_setup(0, URMA_TM_UM);
    ASSERT_NE(nullptr, c);
    ASSERT_NE(nullptr, c->jetty);

    char *src = static_cast<char *>(calloc(1, WR_SEG_LEN));
    char *dst = static_cast<char *>(calloc(1, WR_SEG_LEN));
    ASSERT_NE(nullptr, src);
    ASSERT_NE(nullptr, dst);
    memset(src, 'W', 128);
    memset(dst, 0, WR_SEG_LEN);

    urma_target_seg_t *src_seg = dt_register_seg(c, src, WR_SEG_LEN);
    urma_target_seg_t *dst_seg = dt_register_seg(c, dst, WR_SEG_LEN);
    ASSERT_NE(nullptr, src_seg);
    ASSERT_NE(nullptr, dst_seg);

    urma_target_jetty_t *tj = dt_import_self(c);
    ASSERT_NE(nullptr, tj);

    EXPECT_EQ(0, dt_post_write(c, tj, src, src_seg, dst, dst_seg, 128, 0x71));

    urma_cr_t cr = {};
    EXPECT_EQ(1, dt_poll_cr(c, &cr));
    EXPECT_EQ(0, cr.status);
    EXPECT_EQ(0x71, cr.user_ctx);
    EXPECT_EQ(0, cr.flag.bs.s_r);
    EXPECT_EQ('W', dst[0]);
    EXPECT_EQ('W', dst[127]);
    EXPECT_EQ(0, dst[128]);
    DT_WRITE_VAL("write_first_byte", dst[0]);

    urma_unimport_jetty(tj);
    free(dst);
    free(src);
    dt_teardown(c);
}
