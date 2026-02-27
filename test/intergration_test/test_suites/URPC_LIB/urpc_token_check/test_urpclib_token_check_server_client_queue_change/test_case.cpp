/*
 * SPDX-License-Identifier: MT
 * Copyright (c) Huawei Technologies Co., Ltd. 2024-2024. All rights reserved.
 * Description: urpclib example
 */

 #include "../public.h"

 #define CHANNEL_NUM 6

static int run_test(test_urpc_ctx_t *ctx)
{
    int rc = TEST_FAILED, ret;
    uint64_t squeue_handles1[3] = {0};
    uint64_t sqh1[3] = {0};
    test_func_args_t func_args = {0};
    urpc_channel_qinfos_t qinfos;
    ctx->async_ops.flag = ASYNC_FLAG_BLOCK;
    ctx->queue_num = CHANNEL_NUM / 2;
    memset(&qinfos, 0, sizeof(qinfos));
    urpc_sge_t *sges;
    uint32_t sge_num = 0;
    urpc_qcfg_get_t cfg = {};
    uint32_t post_rx_num = 0;
    uint32_t rx_buf_size = 0;
    if (ctx->app_id == PROC_1) {
        ret = test_server_prepare(ctx);
        CHKERR_JUMP(ret != TEST_SUCCESS, "test_server_prepare", EXIT);
    }
    sync_time("--------------------------1");
    if (ctx->app_id >= PROC_2) {
        ret = test_client_init(ctx);
        CHKERR_JUMP(ret != TEST_SUCCESS, "test_client_init", EXIT);
        ret = test_urpc_ctrl_msg_cb_register(ctx);
        CHKERR_JUMP(ret != TEST_SUCCESS, "test_urpc_ctrl_msg_cb_register", EXIT);
        ret = test_allocator_register(ctx);
        CHKERR_JUMP(ret != TEST_SUCCESS, "test_allocator_register", EXIT);
        ret = test_queue_create(ctx, QUEUE_TRANS_MODE_JETTY);
        CHKERR_JUMP(ret != TEST_SUCCESS, "test_queue_create", EXIT);

        ctx->channel_num = CHANNEL_NUM;
        ret = test_channel_create(ctx);
        CHKERR_JUMP(ret != TEST_SUCCESS, "test_channel_create", EXIT);
        ret = test_mem_seg_remote_access_enable(ctx);
        CHKERR_JUMP(ret != TEST_SUCCESS, "test_mem_seg_remote_access_enable", EXIT);
        ret = test_server_attach(ctx);
        CHKERR_JUMP(ret != TEST_SUCCESS, "test_server_attach", EXIT);
        ctx->channel_num = CHANNEL_NUM / 2;
        ret = test_add_local_queue(ctx);
        CHKERR_JUMP(ret != TEST_SUCCESS, "test_add_local_queue", EXIT);
        ret = test_add_remote_queue(ctx);
        CHKERR_JUMP(ret != TEST_SUCCESS, "test_add_remote_queue", EXIT);
        ret = test_normal_queue_pair(ctx);
        CHKERR_JUMP(ret != TEST_SUCCESS, "test_normal_queue_pair", EXIT);
    }
    sync_time("--------------------------2");
    ret = test_urpc_queue_rx_post(ctx, 2);
    CHKERR_JUMP(ret != TEST_SUCCESS, "test_urpc_queue_rx_post", EXIT);
    sync_time("--------------------------22");
    ret = test_rpc_send_read(ctx);
    TEST_LOG_INFO("test_rpc_send_read ret=%d\n", ret);
    CHKERR_JUMP(ret != TEST_SUCCESS, "test_rpc_send_read", EXIT);
    sync_time("--------------------------3");
    for (uint32_t i = 0; i < CHANNEL_NUM / 2; i++) {
        squeue_handles1[i] = urpc_queue_create(QUEUE_TRANS_MODE_JETTY, ctx->queue_cfg);
        CHKERR_JUMP(squeue_handles1[i] == URPC_INVALID_HANDLE, "urpc_queue_create", EXIT);
        sqh1[i] = ctx->queue_handles[i];
    }
    ctx->queue_num = CHANNEL_NUM;

    ret = recalloc_ctx_queue_handles(ctx, CHANNEL_NUM);
    CHKERR_JUMP(ret != TEST_SUCCESS, "recalloc_ctx_queue_handles", EXIT);
    for (uint32_t i = 0; i < CHANNEL_NUM / 2; i++) {
        ctx->queue_handles[i] = sqh1[i];
        ctx->queue_handles[CHANNEL_NUM / 2 + i] = squeue_handles1[i];
    }
    sync_time("--------------------------4");
    if (ctx->app_id == PROC_2) {
        ctx->channel_num = CHANNEL_NUM;
        for (uint32_t i = CHANNEL_NUM / 2; i < ctx->channel_num; i++) {
            ret = test_channel_server_refresh(ctx, ctx->channel_ids[i]);
            if (ret != TEST_SUCCESS) {
                return TEST_FAILED;
            }
        }
        for (uint32_t i = CHANNEL_NUM / 2; i < ctx->channel_num; i++) {
            ctx->channel_ops[i].flush_lqueue = true;
            ret = test_flush_channel_lqueue(&ctx->channel_ops[i]);
            if (ret != TEST_SUCCESS) {
                TEST_LOG_ERROR("test_flush_channel_lqueue channel_ops[%u] failed\n", i)
                return TEST_FAILED;
            }
            ret = test_channel_add_local_queue(&ctx->channel_ops[i]);
            if (ret != TEST_SUCCESS) {
                TEST_LOG_ERROR("test_channel_add_local_queue channel_ops[%u] failed\n", i)
                return TEST_FAILED;
            }
        }
        for (uint32_t i = CHANNEL_NUM / 2; i < ctx->channel_num; i++) {
            ctx->channel_ops[i].flush_rqueue = true;
            ret = test_flush_channel_rqueue(&ctx->channel_ops[i]);
            if (ret != TEST_SUCCESS) {
                TEST_LOG_ERROR("test_flush_channel_rqueue channel_ops[%u] failed\n", i)
                return TEST_FAILED;
            }
            ret = test_channel_add_remote_queue(&ctx->channel_ops[i]);
            if (ret != TEST_SUCCESS) {
                TEST_LOG_ERROR("test_channel_add_remote_queue channel_ops[%u] failed\n", i)
                return TEST_FAILED;
            }
        }
        for (uint32_t i = CHANNEL_NUM / 2; i < ctx->channel_num; i++) {
            if (ctx->channel_ids[i] == URPC_U32_FAIL) {
                continue;
            }
            memset(&qinfos, 0, sizeof(qinfos));
            ret = urpc_channel_queue_query(ctx->channel_ids[i], &qinfos);
            CHKERR_JUMP(ret != TEST_SUCCESS, "urpc_channel_queue_query", EXIT);
            for (uint32_t j = 0; j < ctx->channel_ops[i].rqueue_num; j++) {
                TEST_LOG_DEBUG("test round ss channel id=%u lqueue id=%u rqueue id=%u\n", i, j, j);
                if (qinfos.r_qinfo[j].status == QUEUE_STATUS_READY) {
                    ret = test_channel_queue_pair(ctx, ctx->channel_ids[i], ctx->channel_ops[i].lqueue_ops[j].qh, ctx->channel_ops[i].rqueue_ops[j].qh);
                    if (ret != TEST_SUCCESS) {
                        TEST_LOG_INFO("test round ss channel id=%u lqueue id=%u rqueue id=%u\n", i, j, j);
                        TEST_LOG_ERROR("test_channel_queue_pair %u lqh=%p \n", j, ctx->channel_ops[i].lqueue_ops[j].qh);
                        TEST_LOG_ERROR("test_channel_queue_pair %u rqh=%p \n", j, ctx->channel_ops[i].rqueue_ops[j].qh);
                    }
                    CHKERR_JUMP(ret != TEST_SUCCESS, "test_channel_queue_pair", EXIT);
                }
            }
        }
    }

    sync_time("--------------------------5");
    for (int i = CHANNEL_NUM / 2; i < ctx->queue_num; i++) {
        urpc_queue_cfg_get(ctx->queue_handles[i], &cfg);
        post_rx_num = cfg.rx_depth;
        rx_buf_size = cfg.rx_buf_size;
        for (int k =0; k < post_rx_num; k++) {
            if ((g_test_allocator.get(&sges, &sge_num, rx_buf_size, nullptr)) != 0) {
                TEST_LOG_ERROR("get sges failed\n");
                return TEST_FAILED;
            }
            if (urpc_queue_rx_post(ctx->queue_handles[i], sges, sge_num) != URPC_SUCCESS) {
                g_test_allocator.put(sges, sge_num, nullptr);
                return TEST_FAILED;
            }
        }
    }
    sync_time("--------------------------6");
    ret = test_rpc_send_read(ctx);
    TEST_LOG_INFO("test_rpc_send_read ret=%d\n", ret);
    CHKERR_JUMP(ret != TEST_SUCCESS, "test_rpc_send_read", EXIT);

    rc = TEST_SUCCESS;
EXIT:
    sync_time("--------------------------9");
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