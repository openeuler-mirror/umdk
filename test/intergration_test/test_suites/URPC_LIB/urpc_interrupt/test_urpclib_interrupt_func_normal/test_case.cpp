/*
 * SPDX-License-Identifier: MT
 * Copyright (c) Huawei Technologies Co., Ltd. 2024-2024. All rights reserved.
 * Description: urpclib example
 */

 #include "urpc_lib_atom.h"

 #define TEST_ROUND_NUM 10

 static int run_test(test_urpc_ctx_t *ctx)
 {
    int rc = TEST_FAILED, ret = 0;
    server_thread_arg_t targ[1] = {0};
    test_func_args_t func_args = {0};
    uint64_t stats_total[STATS_TYPE_MAX] = {0};
    memset(&stats_total, 0, sizeof(uint64_t) * STATS_TYPE_MAX);
    int total_num = 0;
    ctx->async_ops.flag = ASYNC_FLAG_BLOCK;
    ctx->channel_num =1;
    ctx->queue_num = 1;
    ret = set_queue_ops_interrupt(ctx);
    CHKERR_JUMP(ret != TEST_SUCCESS, "set_queue_ops_interrupt", EXIT);
    if (ctx->app_id == PROC_1) {
        ret = test_server_prepare(ctx);
        CHKERR_JUMP(ret != TEST_SUCCESS, "test_server_prepare", EXIT);
    }
    sync_time("--------------------------1");
    if (ctx->app_id == PROC_2) {
        ret = test_client_prepare(ctx);
        CHKERR_JUMP(ret != TEST_SUCCESS, "test_client_prepare", EXIT);
    }
    sync_time("--------------------------2");
    ret = test_urpc_queue_rx_post(ctx, 2);
    CHKERR_JUMP(ret != TEST_SUCCESS, "test_urpc_queue_rx_post", EXIT);
    sync_time("--------------------------22");
    if (ctx->app_id == PROC_1) {
        for (int i = 0; i < 1; i++) {
            targ[i].tid = i;
        }
        ret = start_server_poll_thread(1, targ);
        CHKERR_JUMP(ret != TEST_SUCCESS, "start_server_poll_thread", EXIT);
    }
    sync_time("--------------------------3");
    if (ctx->app_id == PROC_2) {
        for (uint32_t r = 0; r < TEST_ROUND_NUM; r++) {
            TEST_LOG_INFO("test round r=%u\n", r);
            for (uint32_t i = 0; i < ctx->channel_num; i++) {
                TEST_LOG_INFO("test channel id =%u\n", i);
                func_args.channel_id = ctx->channel_ids[i];
                func_args.lqueue_handle = ctx->channel_ops[i].lqueue_ops[0].qh;
                func_args.rqueue_handle = ctx->channel_ops[i].rqueue_ops[0].qh;
                func_args.func_id = ctx->func_id;
                ret = test_func_call_recv_rsp_no_ack(&func_args);
                CHKERR_JUMP(ret != TEST_SUCCESS, "test_func_call_recv_rsp_no_ack", EXIT);
                ret = test_func_call_no_rsp_no_ack(&func_args);
                CHKERR_JUMP(ret != TEST_SUCCESS, "test_func_call_no_rsp_no_ack", EXIT);
            }
        }
    }
    sync_time("--------------------------4");
    sleep(3);
    if (ctx->app_id == PROC_1) {
        ret = stop_server_poll_thread(1, targ);
        CHKERR_JUMP(ret != TEST_SUCCESS, "stop_server_poll_thread", EXIT);
    }
    for (uint32_t i = 0; i < ctx->queue_num; i++) {
        TEST_LOG_INFO("test stats i=%d\n", i);
        ret = test_get_queue_stats(ctx->queue_handles[i], stats_total);
        CHKERR_JUMP(ret != TEST_SUCCESS, "test_get_queue_stats", EXIT);
    }
    print_queue_stats(stats_total);
    total_num = 2 * ctx->channel_num * TEST_ROUND_NUM;
    TEST_LOG_INFO("test stats total_num = %d\n", total_num);
    if (ctx->app_id == PROC_1) {
        CHKERR_JUMP(stats_total[STATS_TYPE_RESPONSE_SEND] != total_num, "resp_send_num", EXIT);
        CHKERR_JUMP(stats_total[STATS_TYPE_RESPONSE_SEND_CONFIRMED] != total_num, "resp_send_conf_num", EXIT);
        CHKERR_JUMP(stats_total[STATS_TYPE_REQUEST_RECEIVE] != total_num, "req_recv_num", EXIT);
    }
    if (ctx->app_id == PROC_2) {
        CHKERR_JUMP(stats_total[STATS_TYPE_REQUEST_SEND] != total_num, "req_send_num", EXIT);
        CHKERR_JUMP(stats_total[STATS_TYPE_REQUEST_SEND_CONFIRMED] != total_num, "req_send_conf_num", EXIT);
        CHKERR_JUMP(stats_total[STATS_TYPE_RESPONSE_RECEIVE] != total_num, "resp_recv_num", EXIT);
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
    ret = run_test(ctx);
    TEST_LOG_INFO("run_test ret=%d\n", ret);
    ret += test_urpc_ctx_uninit(ctx);
    TEST_LOG_INFO("test_urpc_ctx_uninit ret=%d\n", ret);
    CHECK_FREE(ctx->queue_ops.is_polling);
    return ret;
}