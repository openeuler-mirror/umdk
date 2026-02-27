/*
 * SPDX-License-Identifier: MT
 * Copyright (c) Huawei Technologies Co., Ltd. 2024-2024. All rights reserved.
 * Description: urpclib example
 */

#include "urpc_lib_atom.h"

#define CHANNEL_NUM 16
#define TEST_ROUND_NUM 100

static int run_test(test_urpc_ctx_t *ctx)
{
    int rc = TEST_FAILED, ret;
    server_thread_arg_t targ[1] = {0};
    test_func_args_t func_args = {0};
    ctx->async_ops.flag = ASYNC_FLAG_BLOCK;
    urpc_channel_connect_option_t option = get_channel_connect_option(true);

    ctx->log_cfg.level = URPC_LOG_LEVEL_DEBUG;
    ret = urpc_log_config_set(&ctx->log_cfg);

    ctx->queue_num = CHANNEL_NUM;
    char msg[CHANNEL_NUM][CTRL_MSG_MAX_SIZE];
    if (ctx->app_id == PROC_1) {
        ctx->ctrl_cb = process_ctrl_msg;
        ret = test_server_prepare(ctx);
        CHKERR_JUMP(ret != TEST_SUCCESS, "test_server_prepare", EXIT);
    }
    sync_time("--------------------------1");
    if (ctx->app_id != PROC_1) {
        ctx->channel_num = CHANNEL_NUM;
        ret = test_client_init(ctx, nullptr);
        CHKERR_JUMP(ret != TEST_SUCCESS, "test_client_init", EXIT);

        ctx->ctrl_cb = process_ctrl_msg;
        ctx->ctrl_msg = (urpc_ctrl_msg_t *)calloc(CHANNEL_NUM, sizeof(urpc_ctrl_msg_t));
        for (int i = 0; i < CHANNEL_NUM; i++) {
            get_random_string(msg[i], 128, &ctx->ctx->seed);
            ctx->ctrl_msg[i].msg = msg[i];
            ctx->ctrl_msg[i].msg_size = strlen(msg[i]) + 1;
            ctx->ctrl_msg[i].msg_max_size = CTRL_MSG_MAX_SIZE;
            ctx->ctrl_msg[i].user_ctx = (void *)&ctx->pid;
        }
        ret = test_urpc_ctrl_msg_cb_register(ctx);
        CHKERR_JUMP(ret != TEST_SUCCESS, "test_urpc_ctrl_msg_cb_register", EXIT);

        ret = test_allocator_register(ctx);
        CHKERR_JUMP(ret != TEST_SUCCESS, "test_allocator_register", EXIT);
        ret = test_queue_create(ctx);
        CHKERR_JUMP(ret != TEST_SUCCESS, "test_queue_create", EXIT);

        ret = test_channel_create(ctx);
        CHKERR_JUMP(ret != TEST_SUCCESS, "test_channel_create", EXIT);

        for (int k = 0; k < TEST_ROUND_NUM; k++) {
            TEST_LOG_INFO("loop :%d\n", k);
            ret = test_mem_seg_remote_access_enable(ctx);
            CHKERR_JUMP(ret != TEST_SUCCESS, "test_mem_seg_remote_access_enable", EXIT);

            for (uint32_t i = 0; i < ctx->channel_num; i++) {
                (void *)memcpy(&ctx->channel_ops[i].server, ctx->host_info, sizeof(urpc_host_info_t));
                for (int kk = 0; kk < 1; kk++) {
                    ret = urpc_channel_server_attach(ctx->channel_ids[i], ctx->host_info, &option);
                    if (ret == TEST_SUCCESS) {
                        break;
                    } else {
                        usleep(1000);
                    }
                    TEST_LOG_ERROR("[i:%d kk%d] attach  ret:%d, errno:%d, message: %s.\n", i, kk, ret, errno, strerror(errno));
                }
                CHKERR_JUMP(ret != TEST_SUCCESS, "urpc_channel_server_attach", EXIT);
            }
            ctx->ctx_flag |= CTX_FLAG_SERVER_ATTACH;
            ret = test_add_local_queue(ctx);
            CHKERR_JUMP(ret != TEST_SUCCESS, "test_add_local_queue", EXIT);
            for (uint32_t i = 0; i < ctx->channel_num; i++) {
                for (int kk = 0; kk < 1; kk++) {
                    ret = urpc_channel_server_refresh(ctx->channel_ids[i], &option);
                    if (ret == TEST_SUCCESS) {
                        break;
                    } else {
                        usleep(1000);
                    }
                    TEST_LOG_ERROR("[i:%d kk%d] refresh  ret:%d, errno:%d, message: %s.\n", i, kk, ret, errno, strerror(errno));
                }
                CHKERR_JUMP(ret != TEST_SUCCESS, "urpc_channel_server_refresh", EXIT);
            }
            ret = test_add_remote_queue(ctx);
            CHKERR_JUMP(ret != TEST_SUCCESS, "test_add_remote_queue", EXIT);

            if (k < TEST_ROUND_NUM - 1) {
                ret = test_mem_seg_remote_access_disable(ctx);
                CHKERR_JUMP(ret != TEST_SUCCESS, "test_mem_seg_remote_access_disable", EXIT);
                ret = test_rm_local_queue(ctx);
                CHKERR_JUMP(ret != TEST_SUCCESS, "test_rm_local_queue", EXIT);
                ret = test_rm_remote_queue(ctx);
                CHKERR_JUMP(ret != TEST_SUCCESS, "test_rm_remote_queue", EXIT);
                for (uint32_t i = 0; i < ctx->channel_num; i++) {
                    for (int kk = 0; kk < 1; kk++) {
                        ret = urpc_channel_server_detach(ctx->channel_ids[i], ctx->host_info, &option);
                        if (ret == TEST_SUCCESS) {
                            break;
                        } else {
                            usleep(1000);
                        }
                        TEST_LOG_ERROR("[i:%d kk%d] refresh  ret:%d, errno:%d, mesage: %s.\n", i, kk, ret, errno, strerror(errno));
                    }
                    CHKERR_JUMP(ret != TEST_SUCCESS, "urpc_channel_server_detach", EXIT);
                }
            }
            TEST_LOG_INFO("loop :%d\n", k)
        }
    }
    sync_time("--------------------------2");
    if (ctx->app_id != PROC_1) {
        ret = test_normal_queue_pair(ctx);
        CHKERR_JUMP(ret != TEST_SUCCESS, "test_normal_queue_pair", EXIT);
    }
    sync_time("--------------------------22");
    ret = test_urpc_queue_rx_post(ctx, 2);
    CHKERR_JUMP(ret != TEST_SUCCESS, "test_urpc_queue_rx_post", EXIT);
    sync_time("--------------------------33");
    sleep(2);
    TEST_LOG_INFO("attach_cb_count:%d detach_cb_count:%d\n", ctx->attach_cb_count, ctx->detach_cb_count);
    if (ctx->app_id != PROC_1) {
        CHKERR_JUMP(ctx->attach_cb_count != 3200, "attach_cb_count", EXIT);
        CHKERR_JUMP(ctx->detach_cb_count != 1584, "detach_cb_count", EXIT);
    }
    if (ctx->app_id == PROC_1) {
        CHKERR_JUMP(ctx->attach_cb_count < 3200, "attach_cb_count", EXIT);
        CHKERR_JUMP(ctx->detach_cb_count < 1584, "detach_cb_count", EXIT);
    }
    if (ctx->app_id == PROC_1) {
        for (int i = 0; i < 1; i++) {
            targ[i].tid = i;
        }
        ret = start_server_poll_thread(1, targ);
        CHKERR_JUMP(ret != TEST_SUCCESS, "start_server_poll_thread", EXIT);
    }
    sync_time("--------------------------3");
    if (ctx->app_id != PROC_1) {
        ret = 0;
        for (uint32_t k = 0; k < 10; k++) {
            TEST_LOG_INFO("[k:%d] start\n", k);
            for (int i = 0; i < ctx->channel_num; i++) {
                func_args.channel_id = ctx->channel_ids[i];
                func_args.lqueue_handle = ctx->channel_ops[i].lqueue_ops[0].qh;
                func_args.rqueue_handle = ctx->channel_ops[i].rqueue_ops[0].qh;
                func_args.func_id = ctx->func_id;
                ret = test_func_call_recv_rsp_no_ack(&func_args);
                CHKERR_JUMP(ret != TEST_SUCCESS, "test_func_call_recv_rsp_no_ack", EXIT);
                ret = test_func_call_no_rsp_no_ack(&func_args);
                CHKERR_JUMP(ret != TEST_SUCCESS, "test_func_call_no_rsp_no_ack", EXIT);
            }
            TEST_LOG_INFO("[k:%d] end\n", k);
        }
    }
    sync_time("--------------------------4");
    if (ctx->app_id == PROC_1) {
        ret = stop_server_poll_thread(1, targ);
        CHKERR_JUMP(ret != TEST_SUCCESS, "stop_server_poll_thread", EXIT);
    }
    rc = TEST_SUCCESS;
EXIT:
    sync_time("--------------------------5");
    if (ctx->app_id == PROC_2) {
        ret = test_mem_seg_remote_access_disable(ctx);
        CHKERR_JUMP(ret != TEST_SUCCESS, "test_mem_seg_remote_access_disable", EXIT);
        ret = test_normal_queue_unpair(ctx);
        CHKERR_JUMP(ret != TEST_SUCCESS, "test_normal_queue_unpair", EXIT);
        ret = test_rm_local_queue(ctx);
        CHKERR_JUMP(ret != TEST_SUCCESS, "test_rm_local_queue", EXIT);
        ret = test_rm_remote_queue(ctx);
        CHKERR_JUMP(ret != TEST_SUCCESS, "test_rm_remote_queue", EXIT);
        ret = test_server_detach(ctx, &option);
        CHKERR_JUMP(ret != TEST_SUCCESS, "test_server_detach", EXIT);
    }
    sync_time("--------------------------6");
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
    return ret;
}