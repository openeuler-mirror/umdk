/*
 * SPDX-License-Identifier: MT
 * Copyright (c) Huawei Technologies Co., Ltd. 2024-2024. All rights reserved.
 * Description: umq example
 */

 #include "umq_atom.h"

static int run_test(test_umq_ctx_t *ctx)
{
    int rc = TEST_FAILED, ret;

    for (int i = 0; i < 2; i ++) {
        TEST_LOG_INFO("\n\nLoop i = %d\n", i);
        ctx->cfg.feature = UMQ_FEATURE_API_PRO;
        switch (i) {
            case 1:
                ctx->cfg.feature |= UMQ_FEATURE_ENABLE_TOKEN_POLICY;
                break;
            default:
                break;
        }
        ret = test_umq_prepare(ctx);
        CHKERR_JUMP(ret != TEST_SUCCESS, "test_umq_prepare", EXIT);
        sync_time("------------------------------1");
        for (int j = 0; j < UMQ_MAX_WR_COUNT * 2; j++) {
            TEST_LOG_INFO("\n\nLoop i = %d, j = %d\n", i, j);
            sync_time("------------------------------11");
            if (ctx->app_id == PROC_2) {
                ret = test_umq_post_tx_buf(&ctx->umqh_ops[0]);
                CHKERR_JUMP(ret != TEST_SUCCESS, "test_umq_post_tx_buf", EXIT);
            }
            sync_time("------------------------------22");
            if (ctx->app_id == PROC_1) {
                ret = test_umq_poll_rx_buf(&ctx->umqh_ops[0]);
                CHKERR_JUMP(ret != TEST_SUCCESS, "test_umq_poll_rx_buf", EXIT);
            }
            if (ctx->app_id == PROC_2) {
                ret = test_umq_poll_tx_buf(&ctx->umqh_ops[0]);
                CHKERR_JUMP(ret != TEST_SUCCESS, "test_umq_poll_tx_buf", EXIT);
            }
            sync_time("------------------------------33");
            if (ctx->app_id == PROC_1) {
                ret = test_umq_post_rx(ctx, 1);
                CHKERR_JUMP(ret != TEST_SUCCESS, "test_umq_post_rx", EXIT);
            }
        }
        ret = test_umq_undo_prepare(ctx);
        CHKERR_JUMP(ret != TEST_SUCCESS, "test_umq_undo_prepare", EXIT);
    }

    rc = TEST_SUCCESS;
EXIT:
    sync_time("------------------------------4");
    return rc;
}

int main(int argc, char *argv[])
{
    int ret;
    test_umq_ctx_t *ctx = test_umq_ctx_init(argc, argv);
    ret = run_test(ctx);
    TEST_LOG_INFO("run_test ret=%d\n", ret);
    ret += test_umq_ctx_uninit(ctx);
    TEST_LOG_INFO("test_umq_ctx_uninit ret=%d\n", ret);
    return ret;
}