/*
* SPDX-License-Identifier: MIT
* Copyright (c) Huawei Technologies Co., Ltd. 2024-2024. All rights reserved.
* Description: urma sample
*/

#include "../public.h"

#define WR_NUM 3

static int run_test(test_context_t *test_ctx)
{
    int rc = TEST_FAILED, ret;
    test_urma_ctx_t *ctx = NULL;
    urma_jfs_wr_flag_t flag = get_default_wr_flag();
    urma_jfs_wr_t *jfs_wr[WR_NUM], *bad_jfs_wr;
    urma_cr_t cr[TEST_CR_NUM];
    int c_cnt = 0;
    uint32_t length = 100;

    ctx = create_default_ctx(test_ctx);
    CHECK_JUMP(ctx == NULL, EXIT, "ctx=NULL!\n");

    // 目的端初始赋值b 被写内存后变为a
    if (ctx->app_id == PROC_1) {
        for (int i = 0; i < WR_NUM; i++) {
            memset(ctx->l_ctx.tseg[i]->seg.ubva.va, 'a', (i + 1) * length);
        }      
    } else {
        for (int i = 0; i < WR_NUM; i++) {
            memset(ctx->l_ctx.tseg[i]->seg.ubva.va, 'b', (i + 1) * length);
        }
    }

    if (ctx->app_id == PROC_1) {
        for (int i = 0; i < WR_NUM; i++) {
            jfs_wr[i] = calloc(1, sizeof(urma_jfs_wr_t));
            jfs_wr[i]->opcode = URMA_OPC_WRITE;
            jfs_wr[i]->flag = flag;
            jfs_wr[i]->user_ctx = i + 100;
            jfs_wr[i]->rw.src.num_sge = 1;
            jfs_wr[i]->rw.dst.num_sge = 1;
            jfs_wr[i]->next = NULL;
            jfs_wr[i]->tjetty = ctx->r_ctx[PROC_2 - 1].tjetty[i];

            jfs_wr[i]->rw.src.sge = calloc(jfs_wr[i]->rw.src.num_sge, sizeof(urma_sge_t));
            CHECK_JUMP(jfs_wr[i]->rw.src.sge == NULL, EXIT, "calloc err!\n");
            jfs_wr[i]->rw.src.sge[0].addr = ctx->l_ctx.seg_cfg[i].va;
            jfs_wr[i]->rw.src.sge[0].len = (i + 1) * length;
            jfs_wr[i]->rw.src.sge[0].tseg = ctx->l_ctx.tseg[i];
            
            // 写目的端地址
            jfs_wr[i]->rw.dst.sge = calloc(jfs_wr[i]->rw.dst.num_sge, sizeof(urma_sge_t));
            CHECK_JUMP(jfs_wr[i]->rw.dst.sge == NULL, EXIT, "calloc err!\n");
            jfs_wr[i]->rw.dst.sge[0].addr = ctx->r_ctx[PROC_2 - 1].tseg[i]->seg.ubva.va;
            jfs_wr[i]->rw.dst.sge[0].len = (i + 1) * length;
            jfs_wr[i]->rw.dst.sge[0].tseg = ctx->r_ctx[PROC_2 - 1].tseg[i];
        }
    }

    // before write seg is 'b'
    if (ctx->app_id == PROC_2) {
        for (int i = 0; i < WR_NUM; i++) {
            TEST_LOG_INFO("--- before msg:%s\n", (char *)ctx->l_ctx.tseg[i]->seg.ubva.va);
        }
    }

    if (ctx->app_id == PROC_1) {
        for (int i = 0; i < WR_NUM; i++) {
            ret = test_urma_post_jetty_send_wr(ctx->l_ctx.jetty[i], jfs_wr[i], &bad_jfs_wr);
            TEST_LOG_INFO("test_urma_post_jetty_send_wr ret=%d\n", ret);
            ret = test_poll_jfc_wait(ctx->l_ctx.jfc[0], 1, cr, 1);
            TEST_LOG_INFO("status                = %u\n", cr[0].status);
            CHECK_JUMP(cr[0].status != URMA_CR_SUCCESS, EXIT, "post_jetty_wr cr.status=%d\n", cr[0].status);
            TEST_LOG_INFO("user_ctx              = %llu\n", cr[0].user_ctx);
            CHECK_JUMP(cr[0].user_ctx != jfs_wr[i]->user_ctx, EXIT, "post_jetty_wr cr.user_ctx=%d\n", cr[0].user_ctx);
            TEST_LOG_INFO("flag.bs.s_r           = %u\n", cr[0].flag.bs.s_r);
            CHECK_JUMP(cr[0].flag.bs.s_r != 0, EXIT, "post_jetty_wr cr.flag.bs.s_r=%d\n", cr[0].flag.bs.s_r);
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

    sync_time("--------------------------2");
    sleep(1);
    // after write seg is 'a'
    if (ctx->app_id == PROC_2) {
        for (int i = 0; i < WR_NUM; i++) {
            TEST_LOG_INFO("--- end msg:%s\n", (char *)ctx->l_ctx.tseg[i]->seg.ubva.va);
        }
    }
    rc = TEST_SUCCESS;
EXIT:
    sync_time("--------------------------3");
    if (ctx->app_id == PROC_1) {
        for (int i = 0; i < WR_NUM; i++) {
            test_delete_jfs_wr(jfs_wr[i]);
        }
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
