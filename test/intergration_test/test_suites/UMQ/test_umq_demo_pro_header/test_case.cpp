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
        ctx->cfg.headroom_size = TEST_DATA_HEADER_SIZE;
        test_data_args_t data_args = {};

        ret = test_umq_prepare(ctx);
        CHKERR_JUMP(ret != TEST_SUCCESS, "test_umq_prepare", EXIT);
        sync_time("------------------------------1");
        if (ctx->app_id == PROC_2) {
            data_args.umqh_ops = &ctx->umqh_ops[0];
            ret = test_umq_pro_func_req(&data_args);
            CHKERR_JUMP(ret != TEST_SUCCESS, "test_umq_pro_func_req", EXIT);
        }
        sync_time("------------------------------2");
        if (ctx->app_id == PROC_1) {
            data_args.umqh_ops = &ctx->umqh_ops[0];
            ret = test_umq_pro_func_rsp(&data_args);
            CHKERR_JUMP(ret != TEST_SUCCESS, "test_umq_pro_func_rsp", EXIT);
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