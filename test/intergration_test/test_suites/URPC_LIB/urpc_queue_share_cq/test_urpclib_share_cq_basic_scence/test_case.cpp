/*
 * SPDX-License-Identifier: MT
 * Copyright (c) Huawei Technologies Co., Ltd. 2024-2024. All rights reserved.
 * Description: urpclib example
 */

 #include "public.h"

 #define TEST_LOOP 1
 #define TEST_QUEUE_NUM 2

static int run_test(test_urpc_ctx_t *ctx)
{
    int rc = TEST_FAILED, ret;
    share_queue_cfg_t share_cfg;
    test_func_args_t func_args = {0};
    ctx->async_ops.flag = ASYNC_FLAG_BLOCK;
    urpc_config_t urpc_config = get_urpc_server_client_config(ctx);
    ctx->queue_cfg->create_flag |= QCREATE_FLAG_TX_CQ_DEPTH;
    ctx->queue_cfg->tx_cq_depth = (ctx->queue_cfg->tx_depth + 1) * TEST_QUEUE_NUM;
    ctx->channel_num = TEST_QUEUE_NUM;
    if (ctx->app_id == PROC_1) {
        ret = get_urpc_host_info(ctx->host_info, 1);
        CHKERR_JUMP(ret != TEST_SUCCESS, "get_urpc_host_info", EXIT);
        ret = test_server_client_prepare(ctx, &urpc_config);
        CHKERR_JUMP(ret != TEST_SUCCESS, "test_server_client_prepare", EXIT);
    }
    sync_time("--------------------------1");
    if (ctx->app_id == PROC_2) {
        ret = get_urpc_control_plane_config(ctx->urpc_cp_config, 1);
        CHKERR_JUMP(ret != TEST_SUCCESS, "get_urpc_control_plane_config", EXIT);
        ret = test_server_client_prepare(ctx, &urpc_config);
        CHKERR_JUMP(ret != TEST_SUCCESS, "test_server_client_prepare", EXIT);
    }
    sync_time("--------------------------2");
    ctx->queue_num = TEST_QUEUE_NUM;
    if (ctx->app_id == PROC_1) {
        share_queue_cfg_t share_cfg = {.create_flag = QCREATE_FLAG_QH_SHARE_TX_CQ, .tx_cq_qh = ctx->queue_handles[0]};
        ret = create_share_queue_by_q0(ctx, &share_cfg);
        CHKERR_JUMP(ret != TEST_SUCCESS, "create_share_queue_by_q0", EXIT);
    }

    if (ctx->app_id == PROC_2) {
        share_queue_cfg_t share_cfg ={.create_flag = QCREATE_FLAG_QH_SHARE_TX_CQ, .tx_cq_qh = ctx->queue_handles[0]};
        ret = create_share_queue_by_q0(ctx, &share_cfg);
        CHKERR_JUMP(ret != TEST_SUCCESS, "create_share_queue_by_q0", EXIT);
    }
    sync_time("--------------------------3");
    if (ctx->app_id == PROC_2) {
        ret = test_channel_queue_add_attach(ctx);
        CHKERR_JUMP(ret != TEST_SUCCESS, "test_channel_queue_add_attach", EXIT);
    }
    sync_time("--------------------------4");
    ret = test_urpc_queue_rx_post(ctx, 2);
    CHKERR_JUMP(ret != 0, "test_urpc_queue_rx_post", EXIT);
    sync_time("--------------------------22");
    if (ctx->app_id == PROC_1) {
        func_args.expect_poll_num = 4 * TEST_LOOP * TEST_QUEUE_NUM;
        func_args.timeout = 10;
        ret = test_server_run_response(&func_args);
        CHKERR_JUMP(ret != TEST_SUCCESS, "test_server_run_resonese", EXIT);
    }
    if (ctx->app_id == PROC_2) {
        for (int k = 0; k < TEST_LOOP; k++) {
            for (uint32_t i = 0; i < ctx->channel_num; i++){
                func_args.channel_id = ctx->channel_ids[i];
                func_args.lqueue_handle = ctx->channel_ops[i].lqueue_ops[0].qh;
                func_args.rqueue_handle = ctx->channel_ops[i].rqueue_ops[0].qh;
                func_args.func_id = ctx->func_id;
                ret = test_func_call_recv_rsp_no_ack(&func_args);
                if (ret != TEST_SUCCESS) {
                    TEST_LOG_INFO("test round channel id=%u lq =%lu rq=%lu\n", i, func_args.lqueue_handle, func_args.rqueue_handle);
                }
                CHKERR_JUMP(ret != TEST_SUCCESS, "test_func_call_recv_rsp_no_ack", EXIT);
                ret = test_func_call_no_rsp_no_ack(&func_args);
                if (ret != TEST_SUCCESS) {
                    TEST_LOG_INFO("test round channel id=%u lq =%lu rq=%lu\n", i, func_args.lqueue_handle, func_args.rqueue_handle);
                }
                CHKERR_JUMP(ret != TEST_SUCCESS, "test_func_call_no_rsp_no_ack", EXIT);
            }
        }
    }
    rc = TEST_SUCCESS;
EXIT:
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