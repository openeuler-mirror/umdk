/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2025-2025. All rights reserved.
 * Description: UMQ UB flow control
 * Create: 2025-12-22
 * Note:
 * History: 2025-12-22
 */

#include "umq_types.h"
#include "umq_pro_types.h"
#include "umq_ub_imm_data.h"
#include "umq_ub_flow_control.h"

#define UMQ_UB_FLOW_CONTROL_NOTIFY_THR 4

static ALWAYS_INLINE uint16_t remote_rx_window_inc_non_atomic(struct ub_flow_control *fc, uint16_t new_win)
{
    uint32_t win_sum = fc->remote_rx_window + new_win;
    if (URPC_UNLIKELY(win_sum > UINT16_MAX)) {
        UMQ_LIMIT_VLOG_WARN("receive remote win exceed UINT16_MAX, current win %d, new win %d, remote rx depth %d\n",
                            fc->remote_rx_window, new_win, fc->remote_rx_depth);
        fc->total_remote_rx_received_error += new_win;
        return fc->remote_rx_window;
    }

    if (URPC_UNLIKELY(win_sum > fc->remote_rx_depth)) {
        UMQ_LIMIT_VLOG_WARN("receive remote win exceed rx depth, current win %d, new win %d, remote rx depth %d\n",
                            fc->remote_rx_window, new_win, fc->remote_rx_depth);
    }

    fc->total_remote_rx_received += new_win;
    fc->remote_rx_window = (uint16_t)win_sum;
    return fc->remote_rx_window;
}

static ALWAYS_INLINE uint16_t remote_rx_window_exchange_non_atomic(struct ub_flow_control *fc)
{
    uint16_t win = fc->remote_rx_window;
    fc->total_remote_rx_consumed += win;
    fc->remote_rx_window = 0;
    return win;
}

static ALWAYS_INLINE uint16_t remote_rx_window_dec_non_atomic(struct ub_flow_control *fc, uint16_t required_win)
{
    if (URPC_LIKELY(fc->remote_rx_window >= required_win)) {
        fc->remote_rx_window -= required_win;
        fc->total_remote_rx_consumed += required_win;
        return required_win;
    } else {
        fc->total_flow_controlled_wr += (required_win - fc->remote_rx_window);
    }

    return remote_rx_window_exchange_non_atomic(fc);
}

static ALWAYS_INLINE uint16_t remote_rx_window_load_non_atomic(struct ub_flow_control *fc)
{
    return fc->remote_rx_window;
}

static ALWAYS_INLINE uint16_t local_rx_posted_inc_non_atomic(struct ub_flow_control *fc, uint16_t rx_posted)
{
    uint32_t rx_sum = fc->local_rx_posted + rx_posted;
    if (URPC_UNLIKELY(rx_sum > UINT16_MAX)) {
        UMQ_LIMIT_VLOG_WARN("rx posted exceed UINT16_MAX, current rx %d, new post %d, local rx depth %d\n",
                            fc->local_rx_posted, rx_posted, fc->local_rx_depth);
        fc->total_local_rx_posted_error += rx_posted;
        return fc->local_rx_posted;
    }

    if (URPC_UNLIKELY(rx_sum > fc->local_rx_depth)) {
        UMQ_LIMIT_VLOG_WARN("rx posted exceed rx depth, current win %d, new win %d, local rx depth %d\n",
                            fc->local_rx_posted, rx_posted, fc->local_rx_depth);
    }

    fc->total_local_rx_posted += rx_posted;
    fc->local_rx_posted = (uint16_t)rx_sum;
    return fc->local_rx_posted;
}

static ALWAYS_INLINE uint16_t local_rx_posted_exchange_non_atomic(struct ub_flow_control *fc)
{
    uint16_t posted = fc->local_rx_posted;
    fc->total_local_rx_notified += posted;
    fc->local_rx_posted = 0;
    return posted;
}

static ALWAYS_INLINE uint16_t local_rx_posted_load_non_atomic(struct ub_flow_control *fc)
{
    return fc->local_rx_posted;
}

static ALWAYS_INLINE void flow_control_stats_query_non_atomic(struct ub_flow_control *fc, umq_flow_control_stats_t *out)
{
    out->local_rx_posted = fc->local_rx_posted;
    out->remote_rx_window = fc->remote_rx_window;
    out->total_local_rx_posted = fc->total_local_rx_posted;
    out->total_local_rx_notified = fc->total_local_rx_notified;
    out->total_local_rx_posted_error = fc->total_local_rx_posted_error;
    out->total_remote_rx_received = fc->total_remote_rx_received;
    out->total_remote_rx_consumed = fc->total_remote_rx_consumed;
    out->total_remote_rx_received_error = fc->total_remote_rx_received_error;
    out->total_flow_controlled_wr = fc->total_flow_controlled_wr;
}

static ALWAYS_INLINE uint16_t remote_rx_window_inc_atomic(struct ub_flow_control *fc, uint16_t new_win)
{
    uint16_t after, before = __atomic_load_n(&fc->remote_rx_window, __ATOMIC_RELAXED);
    uint16_t ret = before;
    uint32_t win_sum;
    do {
        win_sum = before + new_win;
        if (URPC_UNLIKELY(win_sum > UINT16_MAX)) {
            UMQ_LIMIT_VLOG_WARN(
                "receive remote win exceed UINT16_MAX, current win %d, new win %d, remote rx depth %d\n",
                fc->remote_rx_window, new_win, fc->remote_rx_depth);
            ret = before;
            break;
        }

        if (URPC_UNLIKELY(win_sum > fc->remote_rx_depth)) {
            UMQ_LIMIT_VLOG_WARN(
                "receive remote win exceed rx depth, current win %d, new win %d, remote rx depth %d\n",
                fc->remote_rx_window, new_win, fc->remote_rx_depth);
        }

        after = (uint16_t)win_sum;
        ret = after;
    } while (
        !__atomic_compare_exchange_n(&fc->remote_rx_window, &before, after, true, __ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE));

    if (URPC_UNLIKELY(ret == before)) {
        (void)__atomic_add_fetch(&fc->total_remote_rx_received_error, new_win, __ATOMIC_RELAXED);
    } else {
        (void)__atomic_add_fetch(&fc->total_remote_rx_received, new_win, __ATOMIC_RELAXED);
    }

    return ret;
}

static ALWAYS_INLINE uint16_t remote_rx_window_exchange_atomic(struct ub_flow_control *fc)
{
    return __atomic_exchange_n(&fc->remote_rx_window, 0, __ATOMIC_RELAXED);
}

static ALWAYS_INLINE uint16_t remote_rx_window_dec_atomic(struct ub_flow_control *fc, uint16_t required_win)
{
    uint16_t after, before = __atomic_load_n(&fc->remote_rx_window, __ATOMIC_RELAXED);
    uint16_t ret = before;
    do {
        if (URPC_UNLIKELY(before == 0)) {
            ret = 0;
            break;
        }

        after = before > required_win ? before - required_win : 0;
        ret = before - after;
    } while (
        !__atomic_compare_exchange_n(&fc->remote_rx_window, &before, after, true, __ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE));

    if (URPC_UNLIKELY(ret < required_win)) {
        (void)__atomic_add_fetch(&fc->total_flow_controlled_wr, (required_win - ret), __ATOMIC_RELAXED);
    }

    if (URPC_LIKELY(ret > 0)) {
        (void)__atomic_add_fetch(&fc->total_remote_rx_consumed, ret, __ATOMIC_RELAXED);
    }

    return ret;
}

static ALWAYS_INLINE uint16_t remote_rx_window_load_atomic(struct ub_flow_control *fc)
{
    return __atomic_load_n(&fc->remote_rx_window, __ATOMIC_RELAXED);
}

static ALWAYS_INLINE uint16_t local_rx_posted_inc_atomic(struct ub_flow_control *fc, uint16_t rx_posted)
{
    uint16_t after, before = __atomic_load_n(&fc->local_rx_posted, __ATOMIC_RELAXED);
    uint16_t ret = before;
    uint32_t rx_sum;
    do {
        rx_sum = before + rx_posted;
        if (URPC_UNLIKELY(rx_sum > UINT16_MAX)) {
            UMQ_LIMIT_VLOG_WARN("rx posted exceed UINT16_MAX, current rx %d, new post %d, local rx depth %d\n",
                                before, rx_posted, fc->local_rx_depth);
            ret = before;
            break;
        }

        if (URPC_UNLIKELY(rx_sum > fc->local_rx_depth)) {
            UMQ_LIMIT_VLOG_WARN("rx posted exceed rx depth, current win %d, new win %d, local rx depth %d\n",
                                before, rx_posted, fc->local_rx_depth);
        }
        after = (uint16_t)rx_sum;
        ret = after;
    } while (
        !__atomic_compare_exchange_n(&fc->local_rx_posted, &before, after, true, __ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE));

    if (URPC_UNLIKELY(ret == before)) {
        (void)__atomic_add_fetch(&fc->total_local_rx_posted_error, rx_posted, __ATOMIC_RELAXED);
    } else {
        (void)__atomic_add_fetch(&fc->total_local_rx_posted, rx_posted, __ATOMIC_RELAXED);
    }

    return ret;
}

static ALWAYS_INLINE uint16_t local_rx_posted_exchange_atomic(struct ub_flow_control *fc)
{
    uint16_t posted = __atomic_exchange_n(&fc->local_rx_posted, 0, __ATOMIC_RELAXED);
    if (URPC_LIKELY(posted > 0)) {
        (void)__atomic_add_fetch(&fc->total_local_rx_notified, posted, __ATOMIC_RELAXED);
    }
    return posted;
}

static ALWAYS_INLINE uint16_t local_rx_posted_load_atomic(struct ub_flow_control *fc)
{
    return __atomic_load_n(&fc->local_rx_posted, __ATOMIC_RELAXED);
}

static ALWAYS_INLINE void flow_control_stats_query_atomic(struct ub_flow_control *fc, umq_flow_control_stats_t *out)
{
    out->local_rx_posted = __atomic_load_n(&fc->local_rx_posted, __ATOMIC_RELAXED);
    out->remote_rx_window = __atomic_load_n(&fc->remote_rx_window, __ATOMIC_RELAXED);
    out->total_local_rx_posted = __atomic_load_n(&fc->total_local_rx_posted, __ATOMIC_RELAXED);
    out->total_local_rx_notified = __atomic_load_n(&fc->total_local_rx_notified, __ATOMIC_RELAXED);
    out->total_local_rx_posted_error = __atomic_load_n(&fc->total_local_rx_posted_error, __ATOMIC_RELAXED);
    out->total_remote_rx_received = __atomic_load_n(&fc->total_remote_rx_received, __ATOMIC_RELAXED);
    out->total_remote_rx_consumed = __atomic_load_n(&fc->total_remote_rx_consumed, __ATOMIC_RELAXED);
    out->total_remote_rx_received_error = __atomic_load_n(&fc->total_remote_rx_received_error, __ATOMIC_RELAXED);
    out->total_flow_controlled_wr = __atomic_load_n(&fc->total_flow_controlled_wr, __ATOMIC_RELAXED);
}

int umq_ub_flow_control_init(ub_flow_control_t *fc, ub_queue_t *queue, uint32_t feature, umq_flow_control_cfg_t *cfg)
{
    memset(fc, 0, sizeof(ub_flow_control_t));
    fc->enabled = (feature & UMQ_FEATURE_ENABLE_FLOW_CONTROL) != 0;
    if (!fc->enabled) {
        return UMQ_SUCCESS;
    }

    fc->local_rx_depth = queue->rx_depth;
    fc->local_tx_depth = queue->tx_depth;
    fc->initial_window = cfg->initial_window;
    fc->notify_interval = cfg->notify_interval;
    if (cfg->initial_window == 0 || cfg->initial_window > queue->rx_depth) {
        fc->initial_window = fc->local_rx_depth >> 1;
    }
    if (fc->initial_window == 0) {
        fc->initial_window = 1;
    }
    if (cfg->notify_interval == 0 || cfg->notify_interval > queue->rx_depth) {
        fc->notify_interval = fc->local_rx_depth >> UMQ_UB_FLOW_CONTROL_NOTIFY_THR;
    }
    if (fc->notify_interval == 0) {
        fc->notify_interval = 1;
    }

    if (cfg->use_atomic_window) {
        fc->ops.remote_rx_window_inc = remote_rx_window_inc_atomic;
        fc->ops.remote_rx_window_dec = remote_rx_window_dec_atomic;
        fc->ops.remote_rx_window_exchange = remote_rx_window_exchange_atomic;
        fc->ops.remote_rx_window_load = remote_rx_window_load_atomic;

        fc->ops.local_rx_posted_inc = local_rx_posted_inc_atomic;
        fc->ops.local_rx_posted_load = local_rx_posted_load_atomic;
        fc->ops.local_rx_posted_exchange = local_rx_posted_exchange_atomic;

        fc->ops.stats_query = flow_control_stats_query_atomic;
    } else {
        fc->ops.remote_rx_window_inc = remote_rx_window_inc_non_atomic;
        fc->ops.remote_rx_window_dec = remote_rx_window_dec_non_atomic;
        fc->ops.remote_rx_window_exchange = remote_rx_window_exchange_non_atomic;
        fc->ops.remote_rx_window_load = remote_rx_window_load_non_atomic;

        fc->ops.local_rx_posted_inc = local_rx_posted_inc_non_atomic;
        fc->ops.local_rx_posted_load = local_rx_posted_load_non_atomic;
        fc->ops.local_rx_posted_exchange = local_rx_posted_exchange_non_atomic;

        fc->ops.stats_query = flow_control_stats_query_non_atomic;
    }

    UMQ_VLOG_INFO("umq flow control init success, use %s window\n", cfg->use_atomic_window ? "atomic" : "non-atomic");

    return UMQ_SUCCESS;
}

void umq_ub_flow_control_uninit(ub_flow_control_t *fc)
{
    if (!fc->enabled) {
        return;
    }

    UMQ_VLOG_INFO("umq flow control uninit success\n");
}

int umq_ub_window_init(ub_flow_control_t *fc, umq_ub_bind_info_t *info)
{
    if (!fc->enabled) {
        return UMQ_SUCCESS;
    }

    if (info->win_buf_addr == 0 || info->win_buf_len < sizeof(uint16_t)) {
        UMQ_VLOG_ERR("umq window init failed, remote flow control qbuf is empty\n");
        return UMQ_FAIL;
    }

    fc->remote_win_buf_addr = info->win_buf_addr;
    fc->remote_win_buf_len = info->win_buf_len;
    fc->remote_rx_depth = info->rx_depth;
    fc->remote_tx_depth = info->tx_depth;
    fc->remote_rx_window = 0; // remote window need to be updated after remote rx_posted

    return UMQ_SUCCESS;
}

void umq_ub_window_read(ub_flow_control_t *fc, ub_queue_t *queue)
{
    if (!fc->enabled || queue->bind_ctx == NULL) {
        return;
    }
    // post read remote window
    urma_jfs_wr_t *bad_wr = NULL;
    urma_sge_t src_sge = {
        .addr = fc->remote_win_buf_addr, .len = sizeof(uint16_t), .tseg = queue->imported_tseg_list[0]};
    urma_sge_t dst_sge = {.addr = umq_ub_notify_buf_addr_get(queue, OFFSET_FLOW_CONTROL) + sizeof(uint16_t),
                          .len = sizeof(uint16_t),
                          .tseg = queue->dev_ctx->tseg_list[0]};
    urma_jfs_wr_t urma_wr = {.rw = {.src = {.sge = &src_sge, .num_sge = 1}, .dst = {.sge = &dst_sge, .num_sge = 1}},
        .user_ctx = 0,
        .opcode = URMA_OPC_READ,
        .flag = {.bs = {.complete_enable = 1, .inline_flag = 0}},
        .tjetty = queue->bind_ctx->tjetty};
    urma_status_t status = urma_post_jetty_send_wr(queue->jetty, &urma_wr, &bad_wr);
    if (status == URMA_SUCCESS) {
        fc->remote_get = true;
        return;
    }

    UMQ_LIMIT_VLOG_ERR("umq ub flow control get remote window failed, error %d, local eid: " EID_FMT ", "
                       "local jetty_id: %u, remote eid: " EID_FMT ", remote jetty_id: %u\n", (int)status,
                       EID_ARGS(queue->jetty->jetty_id.eid), queue->jetty->jetty_id.id,
                       EID_ARGS(queue->bind_ctx->tjetty->id.eid), queue->bind_ctx->tjetty->id.id);
}

void umq_ub_rq_posted_notifier_inc(ub_flow_control_t *fc, uint16_t rx_posted)
{
    if (rx_posted == 0 || !fc->enabled) {
        return;
    }

    (void)fc->ops.local_rx_posted_inc(fc, rx_posted);
}

void umq_ub_rq_posted_notifier_update(ub_flow_control_t *fc, ub_queue_t *queue, uint16_t rx_posted)
{
    if (rx_posted == 0 || !fc->enabled) {
        return;
    }

    uint16_t notify = fc->ops.local_rx_posted_inc(fc, rx_posted);
    if (queue->bind_ctx == NULL) {
        return;
    }

    // if initial_window is not set, wait initial_window to be ready first
    if (!fc->local_set) {
        if (notify < fc->initial_window) {
            return;
        }

        notify = fc->ops.local_rx_posted_exchange(fc);
        if (notify == 0) {
            return;
        }

        uint16_t *remote_data = (uint16_t *)(uintptr_t)umq_ub_notify_buf_addr_get(queue, OFFSET_FLOW_CONTROL);
        *remote_data = notify;
        fc->local_set = true;

        if (!fc->remote_get) {
            umq_ub_window_read(fc, queue);
        }

        return;
    }

    if (notify < fc->notify_interval) {
        return;
    }

    if (umq_ub_window_dec(fc, queue, 1) != 1) {
        return;
    }

    notify = fc->ops.local_rx_posted_exchange(fc);
    if (notify == 0) {
        umq_ub_window_inc(fc, 1);
        return;
    }

    umq_ub_imm_t imm = {
        .flow_control = {
            .umq_private = UMQ_UB_IMM_PRIVATE, .type = IMM_TYPE_FLOW_CONTROL, .in_user_buf = 0, .window = notify}
        };
    // user_ctx used as notify for recovery on tx error
    urma_jfs_wr_t urma_wr = {.user_ctx = notify,
        .send = {.imm_data = imm.value},
        .flag = {.bs = {.complete_enable = 1, .inline_flag = 1}},
        .tjetty = queue->bind_ctx->tjetty,
        .opcode = URMA_OPC_SEND_IMM};
    urma_jfs_wr_t *bad_wr = NULL;
    urma_status_t status = urma_post_jetty_send_wr(queue->jetty, &urma_wr, &bad_wr);
    if (status == URMA_SUCCESS) {
        return;
    }

    UMQ_LIMIT_VLOG_ERR("flow control window send failed, status %d, local eid: " EID_FMT ", "
                       "local jetty_id: %u, remote eid: " EID_FMT ", remote jetty_id: %u\n", (int)status,
                       EID_ARGS(queue->jetty->jetty_id.eid), queue->jetty->jetty_id.id,
                       EID_ARGS(queue->bind_ctx->tjetty->id.eid), queue->bind_ctx->tjetty->id.id);
    umq_ub_window_inc(fc, 1);
    umq_ub_rq_posted_notifier_inc(fc, notify);
}

void umq_ub_fill_tx_imm(ub_flow_control_t *fc, urma_jfs_wr_t *urma_wr, umq_buf_pro_t *buf_pro)
{
    // user send wr can carry flow control
    if (!fc->enabled || urma_wr->opcode != URMA_OPC_SEND) {
        return;
    }

    uint16_t notify = fc->ops.local_rx_posted_load(fc);
    if (notify < fc->notify_interval) {
        return;
    }

    notify = fc->ops.local_rx_posted_exchange(fc);
    if (notify == 0) {
        return;
    }

    umq_ub_imm_t imm = {.flow_control = {
        .umq_private = UMQ_UB_IMM_PRIVATE,
        .type = IMM_TYPE_FLOW_CONTROL,
        .in_user_buf = UMQ_UB_IMM_IN_USER_BUF,
        .window = notify,
    }};
    urma_wr->opcode = URMA_OPC_SEND_IMM;
    urma_wr->send.imm_data = imm.value;
    buf_pro->opcode = UMQ_OPC_SEND_IMM;
    buf_pro->imm_data = imm.value;
}

void umq_ub_recover_tx_imm(ub_queue_t *queue, urma_jfs_wr_t *urma_wr, uint16_t wr_index, umq_buf_t *bad)
{
    if (!queue->flow_control.enabled) {
        return;
    }

    bool find = false;
    umq_buf_pro_t *buf_pro = NULL;
    umq_ub_imm_t imm;
    for (uint16_t i = 0; i < wr_index; i++) {
        if (urma_wr[i].user_ctx == (uint64_t)(uintptr_t)bad) {
            find = true;
        }

        if (find && urma_wr[i].opcode == URMA_OPC_SEND_IMM) {
            imm.value = urma_wr[i].send.imm_data;
            if (imm.bs.umq_private == 0 || imm.bs.type != IMM_TYPE_FLOW_CONTROL) {
                continue;
            }

            umq_ub_rq_posted_notifier_update(&queue->flow_control, queue, imm.flow_control.window);
            buf_pro = (umq_buf_pro_t *)(((umq_buf_t *)(uintptr_t)urma_wr[i].user_ctx)->qbuf_ext);
            buf_pro->opcode = UMQ_OPC_SEND;
            buf_pro->imm_data = 0;
        }
    }
}
