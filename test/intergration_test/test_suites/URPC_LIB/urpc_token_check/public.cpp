/*
 * SPDX-License-Identifier: MT
 * Copyright (c) Huawei Technologies Co., Ltd. 2024-2024. All rights reserved.
 * Description: urpclib example
 */

#include "public.h"

int recalloc_ctx_queue_handles(test_urpc_ctx_t *ctx, uint64_t queue_nums)
{
    CHECK_FREE(ctx->queue_handles);
    ctx->queue_handles = (uint64_t *)calloc(queue_nums, sizeof(uint64_t));
    if (ctx->queue_handles == nullptr) {
        TEST_LOG_ERROR("queue_handles calloc failed\n");
        return TEST_FAILED;
    }
    return TEST_SUCCESS;
}

int test_rpc_send_read(test_urpc_ctx_t *ctx)
{
    int ret;
    test_func_args_t func_args = {0};
    server_thread_arg_t server_args[1] = {0};
    if (ctx->app_id == PROC_1) {
        for (int i = 0; i < 1; i++) {
            server_args[i].tid = i;
        }
        ret = start_server_poll_thread(1, server_args);
        CHKERR_JUMP(ret != TEST_SUCCESS, "start_server_poll_thread", EXIT);
    }
    sync_time("--------------------------88");
    if (ctx->app_id >= PROC_2) {
        for (uint32_t i = 0; i < ctx->channel_num; i++) {
            TEST_LOG_INFO("====ctx->channel_ids[%u]=%lu\n", i, ctx->channel_ids[i]);
            func_args.channel_id = ctx->channel_ids[i];
            func_args.lqueue_handle = ctx->channel_ops[i].lqueue_ops[0].qh;
            func_args.rqueue_handle = ctx->channel_ops[i].rqueue_ops[0].qh;
            func_args.func_id = ctx->func_id;
            ret = test_func_call_read_custom(&func_args);
            CHKERR_JUMP(ret != TEST_SUCCESS, "test_func_call_read_custom", EXIT);
        }
    }
    sync_time("--------------------------99");
    if (ctx->app_id == PROC_1) {
        ret = stop_server_poll_thread(1, server_args);
        CHKERR_JUMP(ret != TEST_SUCCESS, "stop_server_poll_thread", EXIT);
    }
    
    return TEST_SUCCESS;
EXIT:
    return TEST_FAILED;
}