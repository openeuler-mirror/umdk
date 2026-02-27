/*
 * SPDX-License-Identifier: MT
 * Copyright (c) Huawei Technologies Co., Ltd. 2024-2024. All rights reserved.
 * Description: urpclib example
 */

#ifndef PUBLIC_H
#define PUBLIC_H

#include "urpc_lib_atom.h"

typedef struct {
    uint32_t create_flag;
    uint64_t tx_cq_qh;
    uint64_t rx_cq_qh;
    uint64_t rq_qh;
} share_queue_cfg_t;

uint64_t create_share_queue(test_urpc_ctx_t *ctx, share_queue_cfg_t *share_cfg, urpc_queue_trans_mode_t trans_mode = QUEUE_TRANS_MODE_JETTY, urpc_qcfg_create_t *qcfg = nullptr);
int recalloc_ctx_queue_handles(test_urpc_ctx_t *ctx, uint64_t queue_nums);
int create_share_queue_by_q0(test_urpc_ctx_t *ctx, share_queue_cfg_t *share_cfg);

#endif