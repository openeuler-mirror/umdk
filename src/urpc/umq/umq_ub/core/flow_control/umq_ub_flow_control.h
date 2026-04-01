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

#define UMQ_UB_CREDIT_PERCENT 10

typedef union umq_ub_fc_info {
    uint64_t value;
    struct {
        uint64_t local_window : 16;
        uint64_t local_rx_depth : 2;
        uint64_t local_rsvd0 : 6;
        uint64_t local_rsvd1 : 8;
        uint64_t remote_window : 16;
        uint64_t remote_rx_depth : 2;
        uint64_t remote_rsvd0 : 6;
        uint64_t remote_rsvd1 : 8;
    } fc;
} umq_ub_fc_info_t;

typedef union umq_ub_fc_user_ctx {
    uint64_t value;
    struct {
        uint64_t type : 5;
        uint64_t notify : 16;
        uint64_t rsvd0 : 11;
        uint64_t rsvd1 : 32;
    } bs;
} umq_ub_fc_user_ctx_t;

uint16_t umq_ub_fc_threashold_modify(uint16_t threashold, uint8_t ratio);
int umq_ub_flow_control_init(ub_flow_control_t *fc, ub_queue_t *queue, uint32_t feature, umq_flow_control_cfg_t *cfg);
void umq_ub_flow_control_uninit(ub_flow_control_t *fc);
int umq_ub_window_init(ub_flow_control_t *fc, umq_ub_bind_info_t *bind_info);
void umq_ub_window_read(ub_flow_control_t *fc, ub_queue_t *queue);
void umq_ub_fc_depth_exchange(ub_queue_t *queue, ub_flow_control_t *fc);
void umq_ub_rx_consumed_inc(bool lock_free, volatile uint64_t *var, uint64_t count);
uint64_t umq_ub_rx_consumed_exchange(bool lock_free, volatile uint64_t *var, uint64_t count);
int umq_ub_shared_credit_req_send(ub_queue_t *queue);
int umq_ub_shared_credit_req_handle(ub_queue_t *queue, umq_ub_imm_t *imm);
void umq_ub_shared_credit_resp_handle(ub_queue_t *queue, umq_ub_imm_t *imm);
int umq_ub_shared_credit_return_req_send(ub_queue_t *queue);
int umq_ub_shared_credit_return_req_handle(ub_queue_t *queue, umq_ub_imm_t *imm);
void umq_ub_credit_clean_up(ub_queue_t *queue);
void umq_ub_shared_credit_recharge(ub_queue_t *queue, uint16_t recharge_count);
void umq_ub_idle_credit_flush(ub_queue_t *queue, uint32_t cnt) ;

static inline void umq_ub_window_inc(ub_flow_control_t *fc, uint16_t win)
{
    if (win == 0 || !fc->enabled) {
        return;
    }

    (void)fc->ops.remote_rx_window_inc(fc, win, false);
}

static inline uint16_t umq_ub_window_dec(ub_flow_control_t *fc, ub_queue_t *queue, uint16_t win)
{
    if (win == 0 || !fc->enabled) {
        return win;
    }

    return fc->ops.remote_rx_window_dec(fc, win, false);
}

static ALWAYS_INLINE int umq_ub_credit_check_and_request_send(ub_flow_control_t *fc, ub_queue_t *queue)
{
    if (!fc->enabled) {
        return UMQ_SUCCESS;
    }
    if (queue->checker != NULL) {
        queue->checker->last_send = get_timestamp_us();
    }
    if (fc->ops.remote_rx_window_load(fc) <=
        umq_ub_fc_threashold_modify(fc->credit_request_threshold, fc->peer_ratio)) {
        return umq_ub_shared_credit_req_send(queue);
    }
    return UMQ_SUCCESS;
}

static ALWAYS_INLINE bool umq_ub_permission_acquire(struct ub_flow_control *fc)
{
    bool expected = false;
    bool desired = true;
    return __atomic_compare_exchange_n(&fc->is_credit_applying, &expected, desired, false,
        __ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE);
}

static ALWAYS_INLINE void umq_ub_permission_release(struct ub_flow_control *fc)
{
    __atomic_store_n(&fc->is_credit_applying, false, __ATOMIC_RELAXED);
}

static ALWAYS_INLINE void umq_ub_fc_packet_stats(ub_flow_control_t *fc, uint32_t cnt, ub_packet_stats_type_t type)
{
    fc->ops.packet_stats(fc, cnt, type);
}

#ifdef __cplusplus
}
#endif

#endif