/*
 * SPDX-License-Identifier: MT
 * Copyright (c) Huawei Technologies Co., Ltd. 2024-2024. All rights reserved.
 * Description: urpclib example
 */

 #include "urpc_lib_atom.h"

 #define SHARE_RQ_QUEUE_NUM 7
 #define TEST_LOOP 1
 #define SERVER_POLL_THREAD_NUM 1

 static int run_test(test_urpc_ctx_t *ctx)
 {
    int rc = TEST_FAILED, ret;
    server_thread_arg_t targ[SERVER_POLL_THREAD_NUM] = {0};
    test_func_args_t func_args = {0};
    ctx->async_ops.flag = ASYNC_FLAG_BLOCK;
    ctx->queue_num = SHARE_RQ_QUEUE_NUM;
    int chidx = 0;
    if (ctx->app_id == PROC_1) {
        ret = test_server_init(ctx, nullptr);
        CHKERR_JUMP(ret != TEST_SUCCESS, "test_server_init", EXIT);
        ret = test_allocator_register(ctx);
        CHKERR_JUMP(ret != TEST_SUCCESS, "test_allocator_register", EXIT);
        ret = test_queue_create(ctx);
        CHKERR_JUMP(ret != TEST_SUCCESS, "test_queue_create", EXIT);
        ret = test_func_register(ctx);
        CHKERR_JUMP(ret != TEST_SUCCESS, "test_func_register", EXIT);
        ret = test_server_start(ctx);
        CHKERR_JUMP(ret != TEST_SUCCESS, "urpc_server_start", EXIT);
    }
    sync_time("--------------------------1");
    if (ctx->app_id == PROC_2) {
        ret = test_client_init(ctx, nullptr);
        CHKERR_JUMP(ret != TEST_SUCCESS, "test_client_init", EXIT);
        ret = test_allocator_register(ctx);
        CHKERR_JUMP(ret != TEST_SUCCESS, "test_allocator_register", EXIT);

        ctx->queue_handles = (uint64_t *)calloc(ctx->queue_num, sizeof(uint64_t));
        CHKERR_JUMP(ctx->queue_handles == NULL, "ctx->queue_handles error", EXIT);

        ctx-> queue_handles[0] = create_original_queue();
        CHKERR_JUMP(ctx->queue_handles[0] == 0, "urpc_queue_create", EXIT);

        for (int i = 1; i <= 2; i++) {
            ctx->queue_handles[i] = create_share_rq_queue(ctx->queue_handles[0]);
            CHKERR_JUMP(ctx->queue_handles[i] == 0, "urpc_queue_create", EXIT);
        }
        for (int i = 3; i <= 4; i++) {
            ctx->queue_handles[i] = create_share_rq_queue(ctx->queue_handles[1]);
            CHKERR_JUMP(ctx->queue_handles[i] == 0, "urpc_queue_create", EXIT);
        }
        for (int i = 5; i <= 6; i++) {
            ctx->queue_handles[i] = create_share_rq_queue(ctx->queue_handles[4]);
            CHKERR_JUMP(ctx->queue_handles[i] == 0, "urpc_queue_create", EXIT);
        }
        ctx->ctx_flag |= CTX_FLAG_QUEUE_CREATE;

        ctx->channel_num = SHARE_RQ_QUEUE_NUM;
        ret = test_channel_create(ctx);
        CHKERR_JUMP(ret != TEST_SUCCESS, "test_channel_create", EXIT);
        ret = test_mem_seg_remote_access_enable(ctx);
        CHKERR_JUMP(ret != TEST_SUCCESS, "test_mem_seg_remote_access_enable", EXIT);
        ret = test_server_attach(ctx);
        CHKERR_JUMP(ret != TEST_SUCCESS, "test_server_attach", EXIT);
        ret = test_add_local_queue(ctx);
        CHKERR_JUMP(ret != TEST_SUCCESS, "test_add_local_queue", EXIT);
        ret = test_add_remote_queue(ctx);
        CHKERR_JUMP(ret != TEST_SUCCESS, "test_add_remote_queue", EXIT);
        ret = test_normal_queue_pair(ctx);
        CHKERR_JUMP(ret != TEST_SUCCESS, "test_normal_queue_pair", EXIT);
    }
    sync_time("--------------------------2");
    if (ctx->app_id == PROC_1) {
        ret = test_urpc_queue_rx_post(ctx, 2);
        CHKERR_JUMP(ret != TEST_SUCCESS, "test_urpc_queue_rx_post", EXIT);
    } else {
        ret = test_urpc_queue_rx_post(nullptr, 2, ctx->queue_handles[0]);
        CHKERR_JUMP(ret != TEST_SUCCESS, "test_urpc_queue_rx_post", EXIT);
    }
    sync_time("--------------------------22");
    if (ctx->app_id == PROC_1) {
        for (int i = 0; i < SERVER_POLL_THREAD_NUM; i++) {
            targ[i].tid = i;
        }
        ret = start_server_poll_thread(SERVER_POLL_THREAD_NUM, targ);
        CHKERR_JUMP(ret != TEST_SUCCESS, "start_server_poll_thread", EXIT);
    }
    sync_time("--------------------------3");
    if (ctx->app_id == PROC_2) {
        for (int k = 0; k < TEST_LOOP; k++) {
            ret = test_func_call_all_type(ctx);
            CHKERR_JUMP(ret != TEST_SUCCESS, "test_func_call_all_type", EXIT);
        }
    }
    sync_time("--------------------------4");
    if (ctx->app_id == PROC_2) {
        chidx = 4;
        ret = test_channel_queue_unpair(ctx, ctx->channel_ids[chidx], ctx->channel_ops[chidx].lqueue_ops[0].qh, ctx->channel_ops[chidx].rqueue_ops[0].qh);
        CHKERR_JUMP(ret != TEST_SUCCESS, "test_channel_queue_unpair", EXIT);
        ret = rm_queue_from_channel_and_destroy(ctx->channel_ids[chidx], ctx->queue_handles[chidx]);
        CHKERR_JUMP(ret != TEST_SUCCESS, "rm_queue_from_channel_and_destroy", EXIT);
        ctx->queue_handles[chidx] = 0;

        ret = test_func_call_all_type_by_one_channel(ctx, 5);
        CHKERR_JUMP(ret != TEST_SUCCESS, "test_func_call_all_type_by_one_channel", EXIT);
        ret = test_func_call_all_type_by_one_channel(ctx, 6);
        CHKERR_JUMP(ret != TEST_SUCCESS, "test_func_call_all_type_by_one_channel", EXIT);

        chidx = 0;
        ret = test_channel_queue_unpair(ctx, ctx->channel_ids[chidx], ctx->channel_ops[chidx].lqueue_ops[0].qh, ctx->channel_ops[chidx].rqueue_ops[0].qh);
        CHKERR_JUMP(ret != TEST_SUCCESS, "test_channel_queue_unpair", EXIT);
        ret = rm_queue_from_channel_and_destroy(ctx->channel_ids[chidx], ctx->queue_handles[chidx]);
        CHKERR_JUMP(ret != TEST_SUCCESS, "rm_queue_from_channel_and_destroy", EXIT);
        ctx->queue_handles[chidx] = 0;

        for (uint32_t chidx = 1; chidx <= 6; chidx++) {
            if (chidx == 4) {
                continue;
            }
            TEST_LOG_INFO("run_test use queue=%d\n", chidx);
            ret = test_func_call_all_type_by_one_channel(ctx, chidx);
            CHKERR_JUMP(ret != TEST_SUCCESS, "test_func_call_all_type_by_one_channel", EXIT);
        }

        for (uint32_t chidx = 1; chidx <= 5; chidx++) {
            if (chidx == 4) {
                continue;
            }
            TEST_LOG_INFO("run_test_ destroy queue=%d\n", chidx); 
            ret = test_channel_queue_unpair(ctx, ctx->channel_ids[chidx], ctx->channel_ops[chidx].lqueue_ops[0].qh, ctx->channel_ops[chidx].rqueue_ops[0].qh);
            CHKERR_JUMP(ret != TEST_SUCCESS, "test_channel_queue_unpair", EXIT);
            ret = rm_queue_from_channel_and_destroy(ctx->channel_ids[chidx], ctx->queue_handles[chidx]);
            CHKERR_JUMP(ret != TEST_SUCCESS, "rm_queue_from_channel_and_destroy", EXIT);
            ctx->queue_handles[chidx] = 0;

        }

        ret = test_func_call_all_type_by_one_channel(ctx, 6);
        CHKERR_JUMP(ret != TEST_SUCCESS, "test_func_call_all_type_by_one_channel", EXIT);

        urpc_qcfg_get_t qcfg_get_cfg = print_queue_cfg(ctx->queue_handles[6]);
        CHKERR_JUMP(qcfg_get_cfg.max_rx_sge != MAX_RX_SGE, "check max_rx_sge", EXIT);
        
        chidx = 6;
        ret = test_channel_queue_unpair(ctx, ctx->channel_ids[chidx], ctx->channel_ops[chidx].lqueue_ops[0].qh, ctx->channel_ops[chidx].rqueue_ops[0].qh);
        CHKERR_JUMP(ret != TEST_SUCCESS, "test_channel_queue_unpair", EXIT);
        ret = rm_queue_from_channel_and_destroy(ctx->channel_ids[chidx], ctx->queue_handles[chidx]);
        CHKERR_JUMP(ret != TEST_SUCCESS, "rm_queue_from_channel_and_destroy", EXIT);
        ctx->queue_handles[chidx] = 0;

        ctx->ctx_flag &= ~CTX_FLAG_QUEUE_PAIR;
        ctx->ctx_flag &= ~CTX_FLAG_CHANNEL_ADD_LOCAL_QUEUE;
        ret = test_rm_remote_queue(ctx);
        CHKERR_JUMP(ret != TEST_SUCCESS, "test_rm_remote_queue", EXIT);
    }
    sync_time("--------------------------5");
    if (ctx->app_id == PROC_1) {
        ret = stop_server_poll_thread(SERVER_POLL_THREAD_NUM, targ);
        CHKERR_JUMP(ret != TEST_SUCCESS, "stop_server_poll_thread", EXIT);
    }
    rc = TEST_SUCCESS;
EXIT:
    sync_time("--------------------------5");
    return rc;
}

 int main(int argc, char *argv[])
{
    int ret;
    test_urpc_ctx_t *ctx = test_urpc_ctx_init(argc, argv, 1);
    test_log_set_level(TEST_LOG_LEVEL_DEBUG);
    ctx->unix_domain_file_path = "/tmp/";
    ret = run_test(ctx);
    TEST_LOG_INFO("run_test ret=%d\n", ret);
    ret += test_urpc_ctx_uninit(ctx);
    TEST_LOG_INFO("test_urpc_ctx_uninit ret=%d\n", ret);
    return ret;
}