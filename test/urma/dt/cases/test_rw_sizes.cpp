/* SPDX-License-Identifier: MIT */
/*
 * DT case: multi-size WRITE/READ round trip (1/8/64/1024/4096 bytes).
 * Covers the SGE encoding, data copy and CR generation for different WQE lengths.
 */

#include <gtest/gtest.h>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <unistd.h>

#include "dt_fixture.hpp"
#include "baseline_macros.h"

#define RW_SEG_LEN 4096

TEST(test_rw_sizes, Run)
{
    dt_ctx_t *c = dt_setup(0, URMA_TM_UM);
    ASSERT_NE(nullptr, c);
    ASSERT_NE(nullptr, c->jetty);

    char *src = static_cast<char *>(calloc(1, RW_SEG_LEN));
    char *mid = static_cast<char *>(calloc(1, RW_SEG_LEN));
    char *back = static_cast<char *>(calloc(1, RW_SEG_LEN));
    ASSERT_NE(nullptr, src);
    ASSERT_NE(nullptr, mid);
    ASSERT_NE(nullptr, back);

    urma_target_seg_t *src_seg = dt_register_seg(c, src, RW_SEG_LEN);
    urma_target_seg_t *mid_seg = dt_register_seg(c, mid, RW_SEG_LEN);
    urma_target_seg_t *back_seg = dt_register_seg(c, back, RW_SEG_LEN);
    ASSERT_NE(nullptr, src_seg);
    ASSERT_NE(nullptr, mid_seg);
    ASSERT_NE(nullptr, back_seg);

    urma_target_jetty_t *tj = dt_import_self(c);
    ASSERT_NE(nullptr, tj);

    const size_t sizes[] = {1, 8, 64, 1024, 4096};
    int round = 0;
    for (size_t i = 0; i < sizeof(sizes) / sizeof(sizes[0]); i++) {
        size_t len = sizes[i];
        memset(src, (int)('a' + i), RW_SEG_LEN);
        memset(mid, 0, RW_SEG_LEN);
        memset(back, 0, RW_SEG_LEN);

        urma_cr_t cr = {};
        EXPECT_EQ(0, dt_post_write(c, tj, src, src_seg, mid, mid_seg, len, 0x100 + i));
        EXPECT_EQ(1, dt_poll_cr(c, &cr));
        EXPECT_EQ(0, cr.status);
        EXPECT_EQ(0U, memcmp(src, mid, len));

        memset(&cr, 0, sizeof(cr));
        EXPECT_EQ(0, dt_post_read(c, tj, back, back_seg, mid, mid_seg, len, 0x200 + i));
        EXPECT_EQ(1, dt_poll_cr(c, &cr));
        EXPECT_EQ(0, cr.status);
        EXPECT_EQ(0U, memcmp(src, back, len));
        round++;
    }
    EXPECT_EQ(5, round);
    DT_WRITE_VAL("rw_rounds", round);

    urma_unimport_jetty(tj);
    free(back);
    free(mid);
    free(src);
    dt_teardown(c);
}
