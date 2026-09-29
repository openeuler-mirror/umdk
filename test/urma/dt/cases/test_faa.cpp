/* SPDX-License-Identifier: MIT */
/*
 * DT case: FAA (Fetch and Add) atomic add. dst starts at 10, operand 5 -> 15.
 */

#include <gtest/gtest.h>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <unistd.h>

#include "dt_fixture.hpp"
#include "baseline_macros.h"

TEST(test_faa, Run)
{
    dt_ctx_t *c = dt_setup(0, URMA_TM_UM);
    ASSERT_NE(nullptr, c);
    ASSERT_NE(nullptr, c->jetty);

    uint64_t *atom = static_cast<uint64_t *>(calloc(1, sizeof(uint64_t)));
    uint64_t *orig = static_cast<uint64_t *>(calloc(1, sizeof(uint64_t)));
    ASSERT_NE(nullptr, atom);
    ASSERT_NE(nullptr, orig);
    *atom = 10;
    *orig = 0;

    urma_target_seg_t *atom_seg = dt_register_seg(c, atom, sizeof(uint64_t));
    urma_target_seg_t *orig_seg = dt_register_seg(c, orig, sizeof(uint64_t));
    ASSERT_NE(nullptr, atom_seg);
    ASSERT_NE(nullptr, orig_seg);

    urma_target_jetty_t *tj = dt_import_self(c);
    ASSERT_NE(nullptr, tj);

    EXPECT_EQ(0, dt_post_faa(c, tj, atom, atom_seg, orig, orig_seg, 5,
                             sizeof(uint64_t), 0xF1));

    urma_cr_t cr = {};
    EXPECT_EQ(1, dt_poll_cr(c, &cr));
    EXPECT_EQ(0, cr.status);
    EXPECT_EQ(0xF1, cr.user_ctx);
    EXPECT_EQ(15ULL, *atom);
    DT_WRITE_VAL("faa_new_value", *atom);

    urma_unimport_jetty(tj);
    free(orig);
    free(atom);
    dt_teardown(c);
}
