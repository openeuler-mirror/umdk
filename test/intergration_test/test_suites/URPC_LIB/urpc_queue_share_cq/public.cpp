/*
 * SPDX-License-Identifier: MT
 * Copyright (c) Huawei Technologies Co., Ltd. 2024-2024. All rights reserved.
 * Description: urpclib example
 */

#include "public.h"

uint64_t create_share_queue(test_urpc_ctx_t *ctx, share_queue_cfg_t *share_cfg, urpc_queue_trans_mode_t trans_mode, urpc_qcfg_create_t *qcfg)
{
    int ret;
    urpc_qcfg_create_t q_cfg = {};
    (void)memset(&q_cfg, 0, sizeof(urpc_qcfg_create_t));
    if (qcfg == nullptr) {
        (void *)memcpy(&q_cfg, ctx->queue_cfg, sizeof(urpc_qcfg_create_t));
        if (share_cfg->create_flag == QCREATE_FLAG_QH_SHARE_TX_CQ) {
            q_cfg.urpc_qh_share_tx_cq = share_cfg->tx_cq_qh;
        } else if (share_cfg->create_flag == (QCREATE_FLAG_QH_SHARE_TX_CQ | QCREATE_FLAG_QH_SHARE_RQ)) {
            q_cfg.urpc_qh_share_tx_cq = share_cfg->tx_cq_qh;
            q_cfg.urpc_qh_share_rq = share_cfg->rq_qh;
            q_cfg.create_flag &= ~QCREATE_FLAG_RX_DEPTH;
        }  else if (share_cfg->create_flag == QCREATE_FLAG_QH_SHARE_RQ) {
            q_cfg.urpc_qh_share_rq = share_cfg->rq_qh;
            q_cfg.create_flag &= ~QCREATE_FLAG_RX_DEPTH;
        }
        q_cfg.create_flag |= share_cfg->create_flag;
    
    } else {
        (void *)memcpy(&q_cfg, qcfg, sizeof(urpc_qcfg_create_t));
    }
    uint64_t queue_handle = urpc_queue_create(trans_mode, &q_cfg);
    TEST_LOG_INFO("urpc_queue_create queue_handle=%lu\n", queue_handle);
    return queue_handle;
}

int recalloc_ctx_queue_handles(test_urpc_ctx_t *ctx, uint64_t queue_nums) 
{uint64_t qh0 = ctx->queue_handles[0];
    CHECK_FREE(ctx->queue_handles);

    ctx->queue_handles = (uint64_t *)calloc(queue_nums, sizeof(uint64_t));
    if (ctx->queue_handles == nullptr) {
        TEST_LOG_ERROR("queue_handles calloc failed\n");
        return TEST_FAILED;
    }

    ctx->queue_handles[0] = qh0;
    return TEST_SUCCESS;
}

int create_share_queue_by_q0(test_urpc_ctx_t *ctx, share_queue_cfg_t *share_cfg)
{
    int ret = recalloc_ctx_queue_handles(ctx, ctx->queue_num);
    CHKERR_JUMP(ret != TEST_SUCCESS, "recalloc_ctx_queue_handles", EXIT);
    for (int i = 1; i < ctx->queue_num; i++) {
        ctx->queue_handles[i] = create_share_queue(ctx, share_cfg);
        CHKERR_JUMP(ctx->queue_handles[i] == URPC_INVALID_HANDLE, "create_share_queue", EXIT);
    }
    return TEST_SUCCESS;
EXIT:
    return TEST_FAILED;
}
