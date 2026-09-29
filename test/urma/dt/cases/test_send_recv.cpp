/* SPDX-License-Identifier: MIT */
/*
 * DT case: one-to-one SEND + RECV. Post the RQE first, then post SEND, and expect two
 * CRs (recv/send); verifies the receive buffer content and the s_r bit.
 */

#include <gtest/gtest.h>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <unistd.h>

#include "dt_fixture.hpp"
#include "baseline_macros.h"

#define SR_SEG_LEN 4096

TEST(test_send_recv, Run)
{
    dt_ctx_t *c = dt_setup(0, URMA_TM_UM);
    ASSERT_NE(nullptr, c);
    ASSERT_NE(nullptr, c->jetty);

    char *data = static_cast<char *>(calloc(1, SR_SEG_LEN));
    char *recv = static_cast<char *>(calloc(1, SR_SEG_LEN));
    ASSERT_NE(nullptr, data);
    ASSERT_NE(nullptr, recv);
    memset(data, 'S', 64);
    memset(recv, 0, SR_SEG_LEN);

    urma_target_seg_t *data_seg = dt_register_seg(c, data, SR_SEG_LEN);
    urma_target_seg_t *recv_seg = dt_register_seg(c, recv, SR_SEG_LEN);
    ASSERT_NE(nullptr, data_seg);
    ASSERT_NE(nullptr, recv_seg);

    urma_target_jetty_t *tj = dt_import_self(c);
    ASSERT_NE(nullptr, tj);

    EXPECT_EQ(0, dt_post_recv(c, recv, recv_seg, 256, 0x91));
    EXPECT_EQ(0, dt_post_send(c, tj, data, data_seg, 64, 0x92));

    int got = 0;
    int got_recv = 0;
    for (int i = 0; i < 2; i++) {
        urma_cr_t cr = {};
        if (dt_poll_cr(c, &cr) == 1) {
            got++;
            EXPECT_EQ(0, cr.status);
            if (cr.flag.bs.s_r != 0) {
                got_recv++;
            }
        }
    }
    EXPECT_EQ(2, got);
    EXPECT_EQ(1, got_recv);
    EXPECT_EQ('S', recv[0]);
    EXPECT_EQ('S', recv[63]);
    EXPECT_EQ(0, recv[64]);
    DT_WRITE_VAL("send_recv_cr_count", got);

    urma_unimport_jetty(tj);
    free(recv);
    free(data);
    dt_teardown(c);
}
