/* SPDX-License-Identifier: MIT */
/*
 * DT case: WRITE_WITH_IMM -- build the WR directly to verify the imm variant WQE
 * encoding, the CQE opcode restore (HW_CQE_OPC_WRITE_WITH_IMM) and data landing.
 */

#include <gtest/gtest.h>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <unistd.h>

#include "dt_fixture.hpp"
#include "baseline_macros.h"

#define IMM_SEG_LEN 4096

TEST(test_write_imm, Run)
{
    dt_ctx_t *c = dt_setup(0, URMA_TM_UM);
    ASSERT_NE(nullptr, c);
    ASSERT_NE(nullptr, c->jetty);

    char *src = static_cast<char *>(calloc(1, IMM_SEG_LEN));
    char *dst = static_cast<char *>(calloc(1, IMM_SEG_LEN));
    char *recv = static_cast<char *>(calloc(1, IMM_SEG_LEN));
    ASSERT_NE(nullptr, src);
    ASSERT_NE(nullptr, dst);
    ASSERT_NE(nullptr, recv);
    memset(src, 'I', 64);
    memset(dst, 0, IMM_SEG_LEN);
    memset(recv, 0, IMM_SEG_LEN);

    urma_target_seg_t *src_seg = dt_register_seg(c, src, IMM_SEG_LEN);
    urma_target_seg_t *dst_seg = dt_register_seg(c, dst, IMM_SEG_LEN);
    urma_target_seg_t *recv_seg = dt_register_seg(c, recv, IMM_SEG_LEN);
    ASSERT_NE(nullptr, src_seg);
    ASSERT_NE(nullptr, dst_seg);
    ASSERT_NE(nullptr, recv_seg);

    urma_target_jetty_t *tj = dt_import_self(c);
    ASSERT_NE(nullptr, tj);

    urma_sge_t rsg = {};
    rsg.addr = (uint64_t)(uintptr_t)dst;
    rsg.len = 64;
    rsg.tseg = dst_seg;
    urma_sge_t lsg = {};
    lsg.addr = (uint64_t)(uintptr_t)src;
    lsg.len = 64;
    lsg.tseg = src_seg;
    urma_sg_t rwrap = {.sge = &rsg, .num_sge = 1};
    urma_sg_t lwrap = {.sge = &lsg, .num_sge = 1};

    /* WRITE_WITH_IMM requires a posted RQE on the receiver (otherwise imm delivery fails -> RNR error CR) */
    ASSERT_EQ(0, dt_post_recv(c, recv, recv_seg, 256, 0xA4));

    urma_jfs_wr_t wr = {};
    wr.opcode = URMA_OPC_WRITE_IMM;
    wr.flag.bs.complete_enable = 1;
    wr.tjetty = tj;
    wr.user_ctx = 0xA5;
    wr.rw.dst = rwrap;
    wr.rw.src = lwrap;
    wr.rw.notify_data = 0x1234;

    urma_jfs_wr_t *bad = nullptr;
    EXPECT_EQ(URMA_SUCCESS, urma_post_jetty_send_wr(c->jetty, &wr, &bad));
    EXPECT_EQ(nullptr, bad);

    /* Expect two CRs: the imm receive CR and the send CR */
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
    EXPECT_EQ('I', dst[0]);
    EXPECT_EQ('I', dst[63]);
    EXPECT_EQ(0, dst[64]);
    DT_WRITE_HEX("write_imm_imm_data", wr.rw.notify_data);

    urma_unimport_jetty(tj);
    free(recv);
    free(dst);
    free(src);
    dt_teardown(c);
}
