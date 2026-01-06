/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2025-2025. All rights reserved.
 * Description: flow control header file for UMQ
 * Create: 2025-12-22
 * Note:
 * History: 2025-12-22
 */

#ifndef UMQ_UB_FLOW_CONTROL_H
#define UMQ_UB_FLOW_CONTROL_H

#include "umq_ub_private.h"
#include "util_id_generator.h"

#ifdef __cplusplus
extern "C" {
#endif

int umq_ub_flow_control_init(ub_flow_control_t *fc, ub_queue_t *queue, uint32_t feature, umq_flow_control_cfg_t *cfg);
void umq_ub_flow_control_uninit(ub_flow_control_t *fc);
int umq_ub_window_init(ub_flow_control_t *fc, umq_ub_bind_info_t *info);
void umq_ub_window_read(ub_flow_control_t *fc, ub_queue_t *queue);
void umq_ub_rq_posted_notifier_update(ub_flow_control_t *fc, ub_queue_t *queue, uint16_t rx_posted);
void umq_ub_fill_tx_imm(ub_flow_control_t *fc, urma_jfs_wr_t *urma_wr, umq_buf_pro_t *buf_pro);
void umq_ub_recover_tx_imm(ub_queue_t *queue, urma_jfs_wr_t *urma_wr, uint16_t wr_index, umq_buf_t *bad);

static inline void umq_ub_window_inc(ub_flow_control_t *fc, uint16_t win)
{
    if (win == 0 || !fc->enabled) {
        return;
    }

    (void)fc->ops.remote_rx_window_inc(fc, win);
}

static inline uint16_t umq_ub_window_dec(ub_flow_control_t *fc, ub_queue_t *queue, uint16_t win)
{
    if (win == 0 || !fc->enabled) {
        return win;
    }

    if (!fc->remote_get) {
        umq_ub_window_read(fc, queue);
        return 0;
    }

    return fc->ops.remote_rx_window_dec(fc, win);
}

void umq_ub_rq_posted_notifier_inc(ub_flow_control_t *fc, uint16_t rx_posted);

#ifdef __cplusplus
}
#endif

#endif