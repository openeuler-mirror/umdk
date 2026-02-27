/*
 * SPDX-License-Identifier: MT
 * Copyright (c) Huawei Technologies Co., Ltd. 2024-2024. All rights reserved.
 * Description: urpclib example
 */

#include "urpc_lib_atom.h"

#define TEST_POLL_TIIMEOUT 10
 
#define TEST_THREAD_NUM URPC_CLIENT_CHANNEL_ATTACH_MAX
 
typedef struct {
    test_urpc_ctx_t *ctx;
    pthread_barrier_t *barrier;
    uint64_t va;
    uint64_t len;
    uint32_t index;
    int result;
 } thread_args_t;

void *test_exec_thread(void *arg)
{
    int ret = 0;
    thread_args_t *args = (thread_args_t *)arg;
    test_func_args_t func_args = {0};
    uint32_t i = args->index;
    TEST_LOG_INFO("--- thread start index:[%d] ----------\n", args->index);

    for (uint32_t r = 0; r < 10; r ++) {
        func_args.channel_id = args->ctx->channel_ids[i];
        func_args.lqueue_handle = args->ctx->channel_ops[i].lqueue_ops[0].qh;
        func_args.rqueue_handle = args->ctx->channel_ops[i].rqueue_ops[0].qh;
        func_args.func_id = args->ctx->func_id;
        ret = test_func_call_recv_rsp_no_ack(&func_args);
        if (ret != TEST_SUCCESS) {
            TEST_LOG_INFO("test round rsp_no_ack channel id=%u lqueue id=%u rqueue id=%u\n", i, i, i);
        }
        CHKERR_JUMP(ret != TEST_SUCCESS, "test_func_call_recv_rsp_no_ack", EXIT);
        ret = test_func_call_no_rsp_no_ack(&func_args);
        if (ret != TEST_SUCCESS) {
            TEST_LOG_INFO("test round no_rsp_no_ack channel id=%u lqueue id=%u rqueue id=%u\n", i, i, i);
        }
        CHKERR_JUMP(ret != TEST_SUCCESS, "test_func_call_no_rsp_no_ack", EXIT);
    }
EXIT:
    args->result = (ret == 0) ? TEST_SUCCESS : TEST_FAILED;
    TEST_LOG_INFO("---thread end index:[%d] ret:[%d]----------\n", args->index, ret);
    pthread_barrier_wait(args->barrier);
}

static int run_test(test_urpc_ctx_t *ctx)
{
    int rc = TEST_FAILED, ret = 0;
    server_thread_arg_t server_thread_arg[1] = {0};
    thread_args_t thread_args[TEST_THREAD_NUM];
    pthread_barrier_t barrier;
    pthread_barrier_init(&barrier, NULL, TEST_THREAD_NUM + 1);
    ctx->queue_num = TEST_THREAD_NUM;
    ctx->channel_num = TEST_THREAD_NUM;
    ctx->async_ops.flag = ASYNC_FLAG_BLOCK;
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
            server_thread_arg[i].tid = i;
        }
        ret = start_server_poll_thread(1, server_thread_arg);
        CHKERR_JUMP(ret != TEST_SUCCESS, "start_server_poll_thread", EXIT);
    }
    sync_time("--------------------------3");
    if (ctx->app_id == PROC_2) {
        TEST_LOG_INFO("create_multi_thread start\n");
        for (int i = 0; i < TEST_THREAD_NUM; i++) {
            thread_args[i].ctx = ctx;
            thread_args[i].barrier = &barrier;
            thread_args[i].index = i;
            thread_args[i].result = TEST_FAILED;
            ret = TestPoolAddWorker(test_exec_thread, (void *)&thread_args[i]);
            CHKERR_JUMP(ret != TEST_SUCCESS, "TestPoolAddWorker", EXIT);
        }
        pthread_barrier_wait(&barrier);
        for (int i = 0; i < TEST_THREAD_NUM; i++){
            TEST_LOG_INFO("check thread [%d] result:[%d] \n", i, thread_args[i].result)
            CHKERR_JUMP(thread_args[i].result != TEST_SUCCESS, "thread join", EXIT);
        }
    }
    sync_time("--------------------------4");
    if (ctx->app_id == PROC_1) {
        ret = stop_server_poll_thread(1, server_thread_arg);
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
    test_urpc_ctx_t *ctx = test_urpc_ctx_init(argc, argv, 1 + TEST_THREAD_NUM);
    ret = run_test(ctx);
    TEST_LOG_INFO("run_test ret=%d\n", ret);
    ret += test_urpc_ctx_uninit(ctx);
    TEST_LOG_INFO("test_urpc_ctx_uninit ret=%d\n", ret);
    return ret;
}