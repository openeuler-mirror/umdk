/*
 * SPDX-License-Identifier: MT
 * Copyright (c) Huawei Technologies Co., Ltd. 2024-2024. All rights reserved.
 * Description: urpclib example
 */

 #include "urpc_lib_atom.h"

 #define THREAD_NUM 1

 static int run_test(test_urpc_ctx_t *ctx)
 {
    int rc = TEST_FAILED, ret;
    server_thread_arg_t targ[THREAD_NUM] = {0};
    test_func_args_t func_args = {0};
    uint32_t hit_event_num = 0;
    uint32_t hit_events = 0;
    uint32_t timeout = 3 * MILLISECOND_PER_SECOND;
    uint32_t tm = 5;
    uint32_t polled_num = 0;
    ctx->async_ops.flag = ASYNC_FLAG_BLOCK;
    if (ctx->app_id == PROC_1) {
        ret = test_server_prepare(ctx);
        CHKERR_JUMP(ret != TEST_SUCCESS, "test_server_prepare", EXIT);
    }
    sync_time("--------------------------1");
    if (ctx->app_id == PROC_2) {
        urpc_config_t urpc_config = get_urpc_client_config(ctx);
        urpc_config.feature |= URPC_FEATURE_TIMEOUT;
        ret = test_client_prepare(ctx, &urpc_config);
        CHKERR_JUMP(ret != TEST_SUCCESS, "test_client_prepare", EXIT);
    }
    sync_time("--------------------------2");
    if (ctx->app_id == PROC_1) {
        ret = start_server_poll_thread(THREAD_NUM, targ);
        CHKERR_JUMP(ret != TEST_SUCCESS, "start_server_poll_thread", EXIT);
    }
    sync_time("--------------------------3");
    if (ctx->app_id == PROC_2) {
        urpc_poll_msg_t msg = {};
        memset(&msg, 0, sizeof(urpc_poll_msg_t));
        urpc_poll_option_t option = {0};
        option.urpc_qh = ctx->queue_handles[0];

        func_args.channel_id = ctx->channel_ids[0];
        func_args.lqueue_handle = ctx->queue_handles[0];
        func_args.func_id = ctx->func_id;
        func_args.call_option.timeout = timeout;
        func_args.call_option.option_flag |= FUNC_CALL_FLAG_TIMEOUT;

        func_args.call_option.option_flag |= FUNC_CALL_FLAG_FUNC_DEFINED;
        func_args.call_option.call_mode = 0;
        func_args.expect_poll_num = 1;
        func_args.expect_hit_events = (1 << POLL_EVENT_REQ_RSPED);
        func_args.is_not_poll = true;
        ret = test_client_process_call(&func_args);
        CHKERR_JUMP(ret != TEST_SUCCESS, "test_client_process_call", EXIT);
        TEST_LOG_INFO("normal rsp no-ack --- sleep %d s\n", tm);
        sleep(tm);
        polled_num = test_func_poll_one_queue(&option, &msg, 1);
        TEST_LOG_INFO("test_func_poll_one_queue polled_num=%d\n", polled_num);
        CHKERR_JUMP(polled_num != 1, "check polled_num", EXIT);
        TEST_LOG_INFO("msg.event:%d\n", msg.event);
        CHKERR_JUMP(msg.event != POLL_EVENT_REQ_ERR, "check event", EXIT);

    }
    sync_time("--------------------------4");
    if (ctx->app_id == PROC_1) {
        ret = stop_server_poll_thread(THREAD_NUM, targ);
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
    test_log_set_level(TEST_LOG_LEVEL_INFO);
    ret = run_test(ctx);
    TEST_LOG_INFO("run_test ret=%d\n", ret);
    ret += test_urpc_ctx_uninit(ctx);
    TEST_LOG_INFO("test_urpc_ctx_uninit ret=%d\n", ret);
    return ret;
}