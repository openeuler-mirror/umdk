/*
* SPDX-License-Identifier: MIT
* Copyright (c) Huawei Technologies Co., Ltd. 2024-2024. All rights reserved.
* Description: urma sample
*/

#include "../public.h"

#define WR_NUM 3
#define SEND 0
#define RECV 1

static int run_test(test_context_t *test_ctx)
{
    int rc = TEST_FAILED, ret;
    test_urma_ctx_t *ctx = NULL;
    urma_jfs_wr_flag_t flag = get_default_wr_flag();
    urma_jfr_wr_t *jfr_wr[WR_NUM], *bad_jfr_wr;
    urma_jfs_wr_t *jfs_wr[WR_NUM], *bad_jfs_wr;
    urma_cr_t cr[TEST_CR_NUM];
    uint32_t length = 100;
    int c_cnt = 0;

    ctx = create_default_ctx(test_ctx);
    CHECK_JUMP(ctx == NULL, EXIT, "ctx=NULL!\n");

    for (int i = 0; i < WR_NUM; i++) {
        jfs_wr[i] = test_fill_jfs_wr_send(ctx, ctx->l_ctx.seg_cfg[i].va, (i + 1) * length, ctx->l_ctx.tseg[i]);
        jfr_wr[i] = test_fill_jfr_wr(ctx, ctx->l_ctx.seg_cfg[i].va, (i + 1) * length, ctx->l_ctx.tseg[i]);
        
        jfs_wr[i]->opcode = URMA_OPC_SEND;
        jfs_wr[i]->flag = flag;
        jfs_wr[i]->user_ctx = i;
        jfs_wr[i]->tjetty = ctx->r_ctx[PROC_2 - 1].tjetty[i];
        jfr_wr[i]->next = NULL;
        jfr_wr[i]->user_ctx = i;
    }

    if (ctx->app_id == PROC_2) {
        for (int i = 0; i < WR_NUM; i++) {
            test_urma_post_jetty_recv_wr(ctx->l_ctx.jetty[i], jfr_wr[i], &bad_jfr_wr);
        }
    }

    sync_time("--------------------------1");
    if (ctx->app_id == PROC_1) {
        for (int i = 0; i < WR_NUM; i++) {
            ret = test_urma_post_jetty_send_wr(ctx->l_ctx.jetty[i], jfs_wr[i], &bad_jfs_wr);
            ret = test_poll_jfc_wait(ctx->l_ctx.jfc[0], 1, cr, 1);
            TEST_LOG_INFO("status                = %u\n", cr[0].status);
            CHECK_JUMP(cr[0].status != URMA_CR_SUCCESS, EXIT, "post_jetty_wr cr.status=%d\n", cr[0].status);
            TEST_LOG_INFO("user_ctx              = %llu\n", cr[0].user_ctx);
            CHECK_JUMP(cr[0].user_ctx != jfs_wr[i]->user_ctx, EXIT, "post_jetty_wr cr.user_ctx=%d\n", cr[0].user_ctx);
            TEST_LOG_INFO("flag.bs.s_r           = %u\n", cr[0].flag.bs.s_r);
            CHECK_JUMP(cr[0].flag.bs.s_r != SEND, EXIT, "post_jetty_wr cr.flag.bs.s_r=%d\n", cr[0].flag.bs.s_r);
            TEST_LOG_INFO("flag.bs.jetty         = %u\n", cr[0].flag.bs.jetty);
            TEST_LOG_INFO("flag.bs.suspend_done  = %u\n", cr[0].flag.bs.suspend_done);
            TEST_LOG_INFO("flag.bs.flush_err_done= %u\n", cr[0].flag.bs.flush_err_done);
            TEST_LOG_INFO("completion_len        = %u\n", cr[0].completion_len);
            TEST_LOG_INFO("local_id              = %u\n", cr[0].local_id);
            CHECK_JUMP(cr[0].local_id != ctx->l_ctx.jetty[i]->jetty_id.id, EXIT, "post_jetty_wr cr.local_id=%d\n",
                       cr[0].local_id);
            TEST_LOG_INFO("remote_id.eid         = " EID_FMT "\n", EID_ARGS(cr[0].remote_id.eid));
            TEST_LOG_INFO("remote_id.uasid       = %u\n", cr[0].remote_id.uasid);
            TEST_LOG_INFO("remote_id.id          = %u\n", cr[0].remote_id.id);
            TEST_LOG_INFO("tpn                   = %u\n", cr[0].tpn);
            TEST_LOG_INFO("user_data             = %llu\n", cr[0].user_data);
        }
    }

    if (ctx->app_id == PROC_2) {
        ret = test_poll_jfc_wait(ctx->l_ctx.jfc[0], WR_NUM, cr, 1);
        for (int i = 0; i < ret; i++) {
            for (int j = 0; j < WR_NUM; j++) {
                if (cr[i].local_id == ctx->l_ctx.jetty[j]->jetty_id.id) {
                    TEST_LOG_INFO("status                = %u\n", cr[i].status);
                    CHECK_JUMP(cr[i].status != URMA_CR_SUCCESS, EXIT, "post_jetty_wr cr.status=%d\n", cr[i].status);
                    TEST_LOG_INFO("user_ctx              = %llu\n", cr[i].user_ctx);
                    CHECK_JUMP(cr[i].user_ctx != jfr_wr[j]->user_ctx, EXIT, "post_jetty_wr cr.user_ctx=%d\n",
                               cr[i].user_ctx);
                    TEST_LOG_INFO("opcode                = %u\n", cr[i].opcode);
                    CHECK_JUMP(cr[i].opcode != URMA_CR_OPC_SEND, EXIT, "post_jetty_wr cr.opcode=%d\n", cr[i].opcode);
                    TEST_LOG_INFO("flag.bs.s_r           = %u\n", cr[i].flag.bs.s_r);
                    CHECK_JUMP(cr[i].flag.bs.s_r != RECV, EXIT, "post_jetty_wr cr.flag.bs.s_r=%d\n", cr[i].flag.bs.s_r);
                    TEST_LOG_INFO("flag.bs.jetty         = %u\n", cr[i].flag.bs.jetty);
                    TEST_LOG_INFO("flag.bs.suspend_done  = %u\n", cr[i].flag.bs.suspend_done);
                    TEST_LOG_INFO("flag.bs.flush_err_done= %u\n", cr[i].flag.bs.flush_err_done);
                    TEST_LOG_INFO("completion_len        = %u\n", cr[i].completion_len);
                    if (ctx->tp_mode != URMA_TM_UM) {
                        TEST_LOG_INFO("remote_id.eid         = " EID_FMT "\n", EID_ARGS(cr[i].remote_id.eid));
                        TEST_LOG_INFO("remote_id.uasid       = %u\n", cr[i].remote_id.uasid);
                        CHECK_JUMP(cr[i].remote_id.uasid != ctx->r_ctx->jetty_id[j].uasid, EXIT,
                                   "post_jetty_wr cr.remote_id.uasid=%d\n", cr[i].remote_id.uasid);
                        TEST_LOG_INFO("remote_id.id          = %u\n", cr[i].remote_id.id);
                        CHECK_JUMP(cr[i].remote_id.id != ctx->r_ctx->jetty_id[j].id, EXIT,
                                   "post_jetty_wr cr.remote_id.eid=%d\n", cr[i].remote_id.id);
                    }
                    TEST_LOG_INFO("tpn                   = %u\n", cr[i].tpn);
                    TEST_LOG_INFO("user_data             = %llu\n", cr[i].user_data);
                }
            }
        }
        // after recv txt is 'a'
        for (int i = 0; i < WR_NUM; i++) {
            TEST_LOG_INFO("--- end msg:%s\n", (char *)jfr_wr[i]->src.sge[0].addr);
        }
    }

    sync_time("--------------------------2");
    rc = TEST_SUCCESS;
EXIT:
    sync_time("--------------------------3");
    for (int i = 0; i < WR_NUM; i++) {
        test_delete_jfs_wr(jfs_wr[i]);
        test_delete_jfr_wr(jfr_wr[i]);
    }
    delete_default_ctx(ctx);
    return rc;
}

int main(int argc, char *argv[])
{
    int rc = TEST_FAILED;
    test_context_t *ctx = create_test_ctx(argc, argv, 3);
    rc = run_test(ctx);
    TEST_LOG_INFO("test result is %d\n", rc);
    destroy_test_ctx(ctx);
    return rc;
}
