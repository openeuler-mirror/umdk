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
#include "umq_symbol_private.h"

#define UMQ_UB_FLOW_CONTROL_NOTIFY_THR 4
#define UMQ_UB_FLOW_CONTROL_LEAK_CREDIT_THR 3
#define UMQ_UB_CREDITS_PER_REQUEST 4
#define UMQ_UB_INITIAL_CREDITS_PER_UMQ 4
#define UMQ_UB_RETURN_CREDIT_RATIO 2
#define UMQ_UB_MIN_RESERVED_CREDIT 2
#define UMQ_UB_DEFAULT_CREDIT_MULTIPLE 2
#define UMQ_UB_DEFAULT_MAX_CREDITS_REQUEST 512
#define UMQ_UB_MIN_CREDITS_PER_REQUEST      2
#define UMQ_UB_FC_MAX_IMM_DATA 1023

static uint8_t g_umq_ub_credit_ratio[] = {1, 3, 5, 7};
#define UMQ_UB_CREDIT_RATIO_SIZE (sizeof(g_umq_ub_credit_ratio) / sizeof(uint8_t))

static uint8_t umq_ub_fc_raito_to_imm(uint16_t available, uint16_t total)
{
    if (available > total || total == 0) {
        return 0;
    }

    uint8_t i = 0;
    uint8_t ratio = (available * UMQ_UB_CREDIT_PERCENT) / total;
    for (i = 0; i < (uint8_t)UMQ_UB_CREDIT_RATIO_SIZE; i++) {
        if (ratio <= g_umq_ub_credit_ratio[i]) {
            return i;
        }
    }

    return (i - 1);
}

static uint8_t umq_ub_fc_imm_to_ratio(uint8_t ratio)
{
    if (ratio >= (uint8_t)UMQ_UB_CREDIT_RATIO_SIZE) {
        return g_umq_ub_credit_ratio[0];
    }

    return g_umq_ub_credit_ratio[ratio];
}

uint16_t umq_ub_fc_threashold_modify(uint16_t threashold, uint8_t ratio)
{
    uint16_t ret = threashold * umq_ub_fc_imm_to_ratio(ratio) / UMQ_UB_CREDIT_PERCENT;
    if (ret == 0) {
        ret = UMQ_UB_MIN_CREDITS_PER_REQUEST;
    }
    return ret;
}

static ALWAYS_INLINE uint64_t umq_ub_rx_consumed_load(bool lock_free, volatile uint64_t *var)
{
    if (lock_free) {
        return *var;
    } else {
        return __atomic_load_n(var, __ATOMIC_RELAXED);
    }
}

static ALWAYS_INLINE uint16_t counter_inc_atomic_u16(ub_credit_pool_t *pool, uint16_t count, ub_credit_stat_u16_t type,
    bool *success)
{
    volatile uint16_t *counter = &pool->stats_u16[type];
    uint16_t after, before = __atomic_load_n(counter, __ATOMIC_RELAXED);
    uint16_t ret = before;
    uint32_t sum;

    *success = true;

    do {
        sum = before + count;
        if (URPC_UNLIKELY(sum > UINT16_MAX)) {
            UMQ_LIMIT_VLOG_WARN(VLOG_UMQ, "counter type %d exceed UINT16_MAX, current %d, new add %d, capacity %d\n",
                                type, before, count, pool->capacity);

            *success = false;

            ret = before;
            break;
        }

        if (type == CREDIT_POOL_IDLE && URPC_UNLIKELY(sum > pool->capacity)) {
            UMQ_LIMIT_VLOG_WARN(VLOG_UMQ, "exceed capacity, current win %d, new add %d, capacity %d\n",
                before, count, pool->capacity);
        }
        after = (uint16_t)sum;
        ret = after;
    } while (!__atomic_compare_exchange_n(counter, &before, after, true, __ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE));

    return ret;
}

static ALWAYS_INLINE uint16_t counter_inc_atomic_u16_ignore_fail(ub_credit_pool_t *pool, uint16_t count,
    ub_credit_stat_u16_t type) {
    bool success = true;
    return counter_inc_atomic_u16(pool, count, type, &success);
}

static ALWAYS_INLINE uint16_t counter_dec_atomic_u16(ub_credit_pool_t *pool, uint16_t count, ub_credit_stat_u16_t type)
{
    volatile uint16_t *counter = &pool->stats_u16[type];
    uint16_t after, before = __atomic_load_n(counter, __ATOMIC_RELAXED);
    uint16_t ret = before;

    do {
        if (URPC_UNLIKELY(before == 0)) {
            ret = 0;
            break;
        }

        after = before > count ? before - count : 0;
        ret = before - after;
    } while (!__atomic_compare_exchange_n(counter, &before, after, true, __ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE));
    return ret;
}

static ALWAYS_INLINE uint16_t counter_dec_atomic_u64(volatile uint64_t *counter, uint16_t count)
{
    uint64_t after, before = __atomic_load_n(counter, __ATOMIC_RELAXED);
    uint64_t ret = before;

    do {
        if (URPC_UNLIKELY(before == 0)) {
            ret = 0;
            break;
        }

        after = before > count ? before - count : 0;
        ret = before - after;
    } while (!__atomic_compare_exchange_n(counter, &before, after, true, __ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE));
    return ret;
}

static ALWAYS_INLINE uint16_t counter_dec_non_atomic_u64(volatile uint64_t *counter, uint16_t count)
{
    if (URPC_LIKELY(*counter >= count)) {
       *counter -= count;
        return count;
    }
    uint16_t temp = (uint16_t)(*counter);
    *counter = 0;
    return temp;
}

static ALWAYS_INLINE uint64_t counter_inc_atomic_u64(volatile uint64_t *counter, uint16_t count)
{
    uint64_t after, before = __atomic_load_n(counter, __ATOMIC_RELAXED);
    uint64_t ret = before;
    do {
        after = before + count;
        ret = after;
    } while (!__atomic_compare_exchange_n(counter, &before, after, true, __ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE));
    return ret;
}

static ALWAYS_INLINE uint16_t counter_inc_non_atomic_u16(ub_credit_pool_t *pool, uint16_t count,
    ub_credit_stat_u16_t type)
{
    uint16_t before = pool->stats_u16[type];
    uint32_t sum = pool->stats_u16[type] + count;

    if (URPC_UNLIKELY(sum > UINT16_MAX)) {
        UMQ_LIMIT_VLOG_WARN(VLOG_UMQ, "type %d exceed UINT16_MAX, current %d, new add %d, capacity %d\n",
                            type, before, count, pool->capacity);
        return before;
    }

    if (type == CREDIT_POOL_IDLE && (URPC_UNLIKELY(sum > pool->capacity))) {
        UMQ_LIMIT_VLOG_WARN(VLOG_UMQ, "type %d exceed capacity, current %d, new add %d, capacity %d\n",
                            type, before, count, pool->capacity);
    }
    pool->stats_u16[type] = (uint16_t)sum;
    return pool->stats_u16[type];
}

static ALWAYS_INLINE uint16_t counter_dec_non_atomic_u16(ub_credit_pool_t *pool, uint16_t count,
    ub_credit_stat_u16_t type)
{
    uint16_t before = pool->stats_u16[type];

    if (before < count) {
        pool->stats_u16[type] = 0;
        return before;
    }
    pool->stats_u16[type] -= count;
    return count;
}

static ALWAYS_INLINE uint16_t remote_rx_window_inc_non_atomic(struct ub_flow_control *fc, uint16_t new_win,
    bool is_return_rollback)
{
    uint32_t win_sum = fc->remote_rx_window + new_win;
    if (URPC_UNLIKELY(win_sum > UINT16_MAX)) {
        UMQ_LIMIT_VLOG_WARN(VLOG_UMQ, "receive remote win exceed UINT16_MAX, current win %d, new win %d, "
            "remote rx depth %d\n", fc->remote_rx_window, new_win, fc->remote_rx_depth);
        if (!is_return_rollback) {
            fc->total_remote_rx_received_error += new_win;
        }
        return fc->remote_rx_window;
    }

    if (URPC_UNLIKELY(win_sum > fc->remote_rx_depth)) {
        UMQ_LIMIT_VLOG_WARN(VLOG_UMQ, "receive remote win exceed rx depth, current win %d, new win %d, "
            "remote rx depth %d\n", fc->remote_rx_window, new_win, fc->remote_rx_depth);
    }
    if (is_return_rollback) {
        fc->remote_rx_window = (uint16_t)win_sum;
        return fc->remote_rx_window;
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

static ALWAYS_INLINE uint16_t remote_rx_window_dec_non_atomic(struct ub_flow_control *fc, uint16_t required_win,
    bool is_return)
{
    if (is_return) {
        if (fc->remote_rx_window >= required_win) {
            fc->remote_rx_window -= required_win;
            return required_win;
        } else {
            uint16_t ret = fc->remote_rx_window;
            fc->remote_rx_window = 0;
            return ret;
        }
    }

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

static ALWAYS_INLINE uint64_t local_rx_allocated_inc_non_atomic(struct ub_flow_control *fc, uint16_t win)
{
    fc->stats_u64[ALLOCATED_SUCCESS] += win;
    fc->stats_u64[ALLOCATED_TOTAL] += win;
    return fc->stats_u64[ALLOCATED_SUCCESS];
}

static ALWAYS_INLINE uint16_t local_rx_allocated_dec_non_atomic(struct ub_flow_control *fc, uint16_t win)
{
    return counter_dec_non_atomic_u64(&fc->stats_u64[ALLOCATED_SUCCESS], win);
}

static ALWAYS_INLINE uint64_t local_rx_allocated_load_non_atomic(struct ub_flow_control *fc)
{
    return fc->stats_u64[ALLOCATED_SUCCESS];
}

static ALWAYS_INLINE void flow_control_stats_query_non_atomic(struct ub_flow_control *fc,
    struct ub_queue *queue, umq_flow_control_stats_t *out)
{
    umq_credit_private_stats_t *queue_credit = &out->queue_credit;
    queue_credit->queue_idle = fc->local_rx_posted;
    queue_credit->queue_be_allocated = fc->stats_u64[ALLOCATED_SUCCESS] -
        queue->dev_ctx->rx_consumed_jetty_table[queue->jetty[UB_QUEUE_JETTY_IO]->jetty_id.id];
    queue_credit->queue_acquired = fc->remote_rx_window;
    queue_credit->total_queue_idle = fc->total_local_rx_posted;
    queue_credit->total_queue_be_allocated = fc->stats_u64[ALLOCATED_TOTAL];
    queue_credit->total_queue_acquired = fc->total_remote_rx_received;
    queue_credit->total_queue_acquired_err = fc->total_remote_rx_received_error;
    queue_credit->total_queue_post_tx_success = fc->total_remote_rx_consumed;
    queue_credit->total_queue_post_tx_err = fc->total_flow_controlled_wr;

    umq_packet_stats_t *packet_stats = &out->packet_stats;
    packet_stats->send_cnt = fc->packet_stats[UB_PACKET_STATS_TYPE_SEND];
    packet_stats->send_success = fc->packet_stats[UB_PACKET_STATS_TYPE_SEND_SUCCESS];
    packet_stats->recv_cnt = fc->packet_stats[UB_PACKET_STATS_TYPE_RECV];
    packet_stats->send_eagain_cnt = fc->packet_stats[UB_PACKET_STATS_TYPE_SEND_EAGAIN];
    packet_stats->send_error_cnt = fc->packet_stats[UB_PACKET_STATS_TYPE_SEND_ERROR];
    packet_stats->recv_error_cnt = fc->packet_stats[UB_PACKET_STATS_TYPE_RECV_ERROR];
}

static ALWAYS_INLINE void flow_control_packet_stats_non_atomic(
    struct ub_flow_control *fc, uint32_t cnt, ub_packet_stats_type_t type)
{
    fc->packet_stats[type] += cnt;
}

static ALWAYS_INLINE void credit_pool_stats_query_non_atomic(ub_credit_pool_t *pool, umq_credit_pool_stats_t *out)
{
    out->pool_idle = pool->stats_u16[CREDIT_POOL_IDLE];
    out->pool_be_allocated = pool->stats_u16[CREDIT_POOL_ALLOCATED];
    out->total_pool_idle = pool->stats_u64[CREDIT_POOL_IDLE_TOTAL];
    out->total_pool_be_allocated = pool->stats_u64[CREDIT_POOL_ALLOCATED_TOTAL];
    out->total_pool_post_rx_err = pool->stats_u64[CREDIT_POOL_ERR_TOTAL];
}

static ALWAYS_INLINE void credit_pool_stats_query_atomic(ub_credit_pool_t *pool, umq_credit_pool_stats_t *out)
{
    out->pool_idle = __atomic_load_n(&pool->stats_u16[CREDIT_POOL_IDLE], __ATOMIC_RELAXED);
    out->pool_be_allocated = __atomic_load_n(&pool->stats_u16[CREDIT_POOL_ALLOCATED], __ATOMIC_RELAXED);
    out->total_pool_idle = __atomic_load_n(&pool->stats_u64[CREDIT_POOL_IDLE_TOTAL], __ATOMIC_RELAXED);
    out->total_pool_be_allocated = __atomic_load_n(&pool->stats_u64[CREDIT_POOL_ALLOCATED_TOTAL], __ATOMIC_RELAXED);
    out->total_pool_post_rx_err = __atomic_load_n(&pool->stats_u64[CREDIT_POOL_ERR_TOTAL], __ATOMIC_RELAXED);
}

static ALWAYS_INLINE uint16_t remote_rx_window_inc_atomic(struct ub_flow_control *fc, uint16_t new_win,
    bool is_return_rollback)
{
    uint16_t after, before = __atomic_load_n(&fc->remote_rx_window, __ATOMIC_RELAXED);
    uint16_t ret = before;
    uint32_t win_sum;
    do {
        win_sum = before + new_win;
        if (URPC_UNLIKELY(win_sum > UINT16_MAX)) {
            UMQ_LIMIT_VLOG_WARN(VLOG_UMQ, "receive remote win exceed UINT16_MAX, current win %d, new win %d, "
                "remote rx depth %d\n", fc->remote_rx_window, new_win, fc->remote_rx_depth);
            ret = before;
            break;
        }

        if (URPC_UNLIKELY(win_sum > fc->remote_rx_depth)) {
            UMQ_LIMIT_VLOG_WARN(VLOG_UMQ, "receive remote win exceed rx depth, current win %d, new win %d, "
                "remote rx depth %d\n", fc->remote_rx_window, new_win, fc->remote_rx_depth);
        }

        after = (uint16_t)win_sum;
        ret = after;
    } while (
        !__atomic_compare_exchange_n(&fc->remote_rx_window, &before, after, true, __ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE));
    if (is_return_rollback) {
        return ret;
    }
    if (URPC_UNLIKELY(ret == before)) {
        (void)__atomic_add_fetch(&fc->total_remote_rx_received_error, new_win, __ATOMIC_RELAXED);
    } else {
        (void)__atomic_add_fetch(&fc->total_remote_rx_received, new_win, __ATOMIC_RELAXED);
    }

    return ret;
}

static ALWAYS_INLINE uint16_t remote_rx_window_dec_atomic(struct ub_flow_control *fc, uint16_t required_win,
    bool is_return)
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

    if (is_return) {
        return ret;
    }
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

static ALWAYS_INLINE uint64_t local_rx_allocated_inc_atomic(struct ub_flow_control *fc, uint16_t win)
{
    (void)counter_inc_atomic_u64(&fc->stats_u64[ALLOCATED_TOTAL], win);
    return counter_inc_atomic_u64(&fc->stats_u64[ALLOCATED_SUCCESS], win);
}

static ALWAYS_INLINE uint16_t local_rx_allocated_dec_atomic(struct ub_flow_control *fc, uint16_t win)
{
    return counter_dec_atomic_u64(&fc->stats_u64[ALLOCATED_SUCCESS], win);
}

static ALWAYS_INLINE uint64_t local_rx_allocated_load_atomic(struct ub_flow_control *fc)
{
    return __atomic_load_n(&fc->stats_u64[ALLOCATED_SUCCESS], __ATOMIC_RELAXED);
}

static ALWAYS_INLINE void flow_control_stats_query_atomic(struct ub_flow_control *fc,
    struct ub_queue *queue, umq_flow_control_stats_t *out)
{
    umq_credit_private_stats_t *queue_credit = &out->queue_credit;
    queue_credit->queue_idle = __atomic_load_n(&fc->local_rx_posted, __ATOMIC_RELAXED);
    uint64_t consumed_credit = __atomic_load_n(
        &queue->dev_ctx->rx_consumed_jetty_table[queue->jetty[UB_QUEUE_JETTY_IO]->jetty_id.id], __ATOMIC_RELAXED);
    queue_credit->queue_be_allocated =
        __atomic_load_n(&fc->stats_u64[ALLOCATED_SUCCESS], __ATOMIC_RELAXED) - consumed_credit;
    queue_credit->queue_acquired = __atomic_load_n(&fc->remote_rx_window, __ATOMIC_RELAXED);
    queue_credit->total_queue_idle = __atomic_load_n(&fc->total_local_rx_posted, __ATOMIC_RELAXED);
    queue_credit->total_queue_acquired = __atomic_load_n(&fc->total_remote_rx_received, __ATOMIC_RELAXED);
    queue_credit->total_queue_acquired_err = __atomic_load_n(&fc->total_remote_rx_received_error, __ATOMIC_RELAXED);
    queue_credit->total_queue_be_allocated = __atomic_load_n(&fc->stats_u64[ALLOCATED_TOTAL], __ATOMIC_RELAXED);
    queue_credit->total_queue_post_tx_success = __atomic_load_n(&fc->total_remote_rx_consumed, __ATOMIC_RELAXED);
    queue_credit->total_queue_post_tx_err = __atomic_load_n(&fc->total_flow_controlled_wr, __ATOMIC_RELAXED);

    umq_packet_stats_t *packet_stats = &out->packet_stats;
    packet_stats->send_cnt = __atomic_load_n(&fc->packet_stats[UB_PACKET_STATS_TYPE_SEND], __ATOMIC_RELAXED);
    packet_stats->send_success =
        __atomic_load_n(&fc->packet_stats[UB_PACKET_STATS_TYPE_SEND_SUCCESS], __ATOMIC_RELAXED);
    packet_stats->recv_cnt = __atomic_load_n(&fc->packet_stats[UB_PACKET_STATS_TYPE_RECV], __ATOMIC_RELAXED);
    packet_stats->send_eagain_cnt =
        __atomic_load_n(&fc->packet_stats[UB_PACKET_STATS_TYPE_SEND_EAGAIN], __ATOMIC_RELAXED);
    packet_stats->send_error_cnt =
        __atomic_load_n(&fc->packet_stats[UB_PACKET_STATS_TYPE_SEND_ERROR], __ATOMIC_RELAXED);
    packet_stats->recv_error_cnt =
        __atomic_load_n(&fc->packet_stats[UB_PACKET_STATS_TYPE_RECV_ERROR], __ATOMIC_RELAXED);
}

static ALWAYS_INLINE void flow_control_packet_stats_atomic(
    struct ub_flow_control *fc, uint32_t cnt, ub_packet_stats_type_t type)
{
    (void)__atomic_add_fetch(&fc->packet_stats[type], cnt, __ATOMIC_RELAXED);
}

static ALWAYS_INLINE uint16_t available_credit_inc_atomic(ub_credit_pool_t *pool, uint16_t count)
{
    bool success = true;
    uint16_t ret = counter_inc_atomic_u16(pool, count, CREDIT_POOL_IDLE, &success);
    if (URPC_UNLIKELY(success == false)) {
        (void)__atomic_add_fetch(&pool->stats_u64[CREDIT_POOL_ERR_TOTAL], count, __ATOMIC_RELAXED);
    } else {
        (void)__atomic_add_fetch(&pool->stats_u64[CREDIT_POOL_IDLE_TOTAL], count, __ATOMIC_RELAXED);
    }
    return ret;
}

static ALWAYS_INLINE uint16_t available_credit_return_atomic(ub_credit_pool_t *pool, uint16_t count)
{
    (void)counter_dec_atomic_u16(pool, count, CREDIT_POOL_ALLOCATED);
    return counter_inc_atomic_u16_ignore_fail(pool, count, CREDIT_POOL_IDLE);
}

static ALWAYS_INLINE uint16_t available_credit_dec_atomic(ub_credit_pool_t *pool, uint16_t count)
{
    uint16_t actual_count = counter_dec_atomic_u16(pool, count, CREDIT_POOL_IDLE);
    (void)counter_inc_atomic_u16_ignore_fail(pool, actual_count, CREDIT_POOL_ALLOCATED);
    (void)__atomic_add_fetch(&pool->stats_u64[CREDIT_POOL_ALLOCATED_TOTAL], actual_count, __ATOMIC_RELAXED);
    return actual_count;
}

static ALWAYS_INLINE uint16_t allocated_credit_dec_atomic(ub_credit_pool_t *pool, uint16_t count)
{
    return counter_dec_atomic_u16(pool, count, CREDIT_POOL_ALLOCATED);
}

static ALWAYS_INLINE uint16_t available_credit_inc_non_atomic(ub_credit_pool_t *pool, uint16_t count)
{
    uint16_t before = pool->stats_u16[CREDIT_POOL_IDLE];
    uint16_t ret = counter_inc_non_atomic_u16(pool, count, CREDIT_POOL_IDLE);
    if (URPC_UNLIKELY(ret == before)) {
        pool->stats_u64[CREDIT_POOL_ERR_TOTAL] += count;
    } else {
        pool->stats_u64[CREDIT_POOL_IDLE_TOTAL] += count;
    }
    return ret;
}

static ALWAYS_INLINE uint16_t available_credit_dec_non_atomic(ub_credit_pool_t *pool, uint16_t count)
{
    uint16_t actual_count = counter_dec_non_atomic_u16(pool, count, CREDIT_POOL_IDLE);
    (void)counter_inc_non_atomic_u16(pool, actual_count, CREDIT_POOL_ALLOCATED);
    pool->stats_u64[CREDIT_POOL_ALLOCATED_TOTAL] += actual_count;
    return actual_count;
}

static ALWAYS_INLINE uint16_t available_credit_return_non_atomic(ub_credit_pool_t *pool, uint16_t count)
{
    (void)counter_dec_non_atomic_u16(pool, count, CREDIT_POOL_ALLOCATED);
    return counter_inc_non_atomic_u16(pool, count, CREDIT_POOL_IDLE);
}

static ALWAYS_INLINE uint16_t allocated_credit_dec_non_atomic(ub_credit_pool_t *pool, uint16_t count)
{
    return counter_dec_non_atomic_u16(pool, count, CREDIT_POOL_ALLOCATED);
}

static void umq_ub_credit_pool_init(ub_queue_t *queue, uint32_t feature, umq_flow_control_cfg_t *cfg)
{
    ub_credit_pool_t *pool = &queue->jfr_ctx[UB_QUEUE_JETTY_IO]->credit;
    memset(pool, 0, sizeof(ub_credit_pool_t));
    pool->capacity = queue->rx_depth;
    if (cfg->use_atomic_window) {
        pool->ops.available_credit_inc = available_credit_inc_atomic;
        pool->ops.available_credit_dec = available_credit_dec_atomic;
        pool->ops.available_credit_return = available_credit_return_atomic;
        pool->ops.allocated_credit_dec = allocated_credit_dec_atomic;
        pool->ops.stats_query = credit_pool_stats_query_atomic;
    } else {
        pool->ops.available_credit_inc = available_credit_inc_non_atomic;
        pool->ops.available_credit_dec = available_credit_dec_non_atomic;
        pool->ops.available_credit_return = available_credit_return_non_atomic;
        pool->ops.allocated_credit_dec = allocated_credit_dec_non_atomic;
        pool->ops.stats_query = credit_pool_stats_query_non_atomic;
    }
}

int umq_ub_flow_control_init(ub_flow_control_t *fc, ub_queue_t *queue, uint32_t feature, umq_flow_control_cfg_t *cfg)
{
    memset(fc, 0, sizeof(ub_flow_control_t));
    fc->enabled = (feature & UMQ_FEATURE_ENABLE_FLOW_CONTROL) != 0;
    if (!fc->enabled) {
        return UMQ_SUCCESS;
    }
    if ((queue->create_flag & UMQ_CREATE_FLAG_SUB_UMQ) == 0) {
        // main queue initializes credit pool
        umq_ub_credit_pool_init(queue, feature, cfg);
    }
    fc->local_rx_depth = queue->rx_depth;
    fc->local_tx_depth = queue->tx_depth;
    fc->initial_credit = cfg->initial_credit;
    fc->return_ratio = cfg->return_ratio;
    fc->min_reserved_credit = cfg->min_reserved_credit;
    fc->credit_multiple = cfg->credit_multiple;
    fc->max_credits_request = cfg->max_credits_request;

    if (cfg->return_ratio == 0 || cfg->return_ratio > queue->rx_depth) {
        fc->return_ratio = UMQ_UB_RETURN_CREDIT_RATIO;
    }
    if (cfg->min_reserved_credit == 0 || cfg->min_reserved_credit > queue->rx_depth) {
        fc->min_reserved_credit = UMQ_UB_MIN_RESERVED_CREDIT;
    }
    if (cfg->initial_credit == 0 || cfg->initial_credit > queue->rx_depth) {
        fc->initial_credit = fc->local_rx_depth >> UMQ_UB_INITIAL_CREDITS_PER_UMQ;
    }
    if (fc->initial_credit == 0) {
        fc->initial_credit = 1;
    }
    if (cfg->max_credits_request < UMQ_UB_MIN_CREDITS_PER_REQUEST ||
        cfg->max_credits_request > fc->local_rx_depth) {
        fc->max_credits_request = UMQ_UB_DEFAULT_MAX_CREDITS_REQUEST;
    }

    uint16_t temp = MIN(UMQ_UB_FC_MAX_IMM_DATA, fc->local_rx_depth);
    if (fc->max_credits_request > temp) {
        fc->max_credits_request = temp;
    }

    if (fc->initial_credit > UMQ_UB_FC_MAX_IMM_DATA) {
        fc->initial_credit = UMQ_UB_FC_MAX_IMM_DATA;
    }
    fc->credits_per_request = fc->initial_credit;
    fc->credit_request_threshold = fc->min_reserved_credit;
    if (cfg->credit_multiple < 1 || cfg->credit_multiple > ((float)queue->rx_depth / fc->initial_credit)) {
        fc->credit_multiple = UMQ_UB_DEFAULT_CREDIT_MULTIPLE;
    }

    if (cfg->use_atomic_window) {
        fc->ops.remote_rx_window_inc = remote_rx_window_inc_atomic;
        fc->ops.remote_rx_window_dec = remote_rx_window_dec_atomic;
        fc->ops.remote_rx_window_load = remote_rx_window_load_atomic;
        fc->ops.local_rx_allocated_inc = local_rx_allocated_inc_atomic;
        fc->ops.local_rx_allocated_dec = local_rx_allocated_dec_atomic;
        fc->ops.local_rx_allocated_load = local_rx_allocated_load_atomic;

        fc->ops.stats_query = flow_control_stats_query_atomic;
        fc->ops.packet_stats = flow_control_packet_stats_atomic;
    } else {
        fc->ops.remote_rx_window_inc = remote_rx_window_inc_non_atomic;
        fc->ops.remote_rx_window_dec = remote_rx_window_dec_non_atomic;
        fc->ops.remote_rx_window_load = remote_rx_window_load_non_atomic;
        fc->ops.local_rx_allocated_inc = local_rx_allocated_inc_non_atomic;
        fc->ops.local_rx_allocated_dec = local_rx_allocated_dec_non_atomic;
        fc->ops.local_rx_allocated_load = local_rx_allocated_load_non_atomic;

        fc->ops.stats_query = flow_control_stats_query_non_atomic;
        fc->ops.packet_stats = flow_control_packet_stats_non_atomic;
    }
    fc->timeout_us = umq_ub_timer_timeout_get();
    UMQ_VLOG_INFO(VLOG_UMQ, "umq flow control init success, use %s window\n",
        cfg->use_atomic_window ? "atomic" : "non-atomic");

    return UMQ_SUCCESS;
}

void umq_ub_flow_control_uninit(ub_flow_control_t *fc)
{
    if (!fc->enabled) {
        return;
    }

    UMQ_VLOG_INFO(VLOG_UMQ, "umq flow control uninit success\n");
}

int umq_ub_window_init(ub_flow_control_t *fc, umq_ub_bind_info_t *bind_info)
{
    if (!fc->enabled) {
        return UMQ_SUCCESS;
    }

    umq_ub_bind_fc_info_t *fc_info = (umq_ub_bind_fc_info_t *)(uintptr_t)bind_info->fc_info;
    umq_ub_bind_queue_info_t *queue_info = (umq_ub_bind_queue_info_t *)(uintptr_t)bind_info->queue_info;
    if (fc_info->win_buf_addr == 0 || fc_info->win_buf_len < sizeof(uint16_t)) {
        UMQ_VLOG_ERR(VLOG_UMQ, "remote eid: " EID_FMT ", remote jetty_id: %u, umq window init failed, remote flow "
            "control qbuf is empty\n", EID_ARGS(fc_info->jetty_id.eid), fc_info->jetty_id.id);
        return UMQ_FAIL;
    }

    fc->remote_win_buf_addr = fc_info->win_buf_addr;
    fc->remote_win_buf_len = fc_info->win_buf_len;
    fc->remote_rx_depth = queue_info->rx_depth;
    fc->remote_tx_depth = queue_info->tx_depth;
    fc->remote_rx_window = 0; // remote window need to be updated after remote rx_posted

    return UMQ_SUCCESS;
}

void umq_ub_shared_credit_recharge(ub_queue_t *queue, uint16_t recharge_count)
{
    ub_flow_control_t *fc = &queue->flow_control;

    if (recharge_count == 0 || !fc->enabled) {
        return;
    }

    ub_credit_pool_t *credit = &queue->jfr_ctx[UB_QUEUE_JETTY_IO]->credit;
    credit->ops.available_credit_inc(credit, recharge_count);
}

int umq_ub_shared_credit_req_send(ub_queue_t *queue)
{
    ub_flow_control_t *fc = &queue->flow_control;
    if (!fc->enabled || queue->bind_ctx == NULL) {
        return UMQ_SUCCESS;
    }

    int ret = umq_ub_poll_fc_tx(queue, NULL, 0);
    if (ret != UMQ_SUCCESS) {
        return ret;
    }

    if (!umq_ub_permission_acquire(fc)) {
        return UMQ_SUCCESS;
    }
    urma_jetty_t *jetty  = queue->jetty[UB_QUEUE_JETTY_FLOW_CONTROL];
    urma_target_jetty_t *tjetty = queue->bind_ctx->tjetty[UB_QUEUE_JETTY_FLOW_CONTROL];
    uint16_t credits_per_request = fc->credits_per_request;
    if (credits_per_request > UMQ_UB_FC_MAX_IMM_DATA) {
        credits_per_request = UMQ_UB_FC_MAX_IMM_DATA;
    }
    umq_ub_imm_t imm = {
        .flow_control = {
            .type = IMM_TYPE_FC_CREDIT_REQ,
            .window = credits_per_request}
        };

    umq_ub_fc_user_ctx_t obj = {
        .bs = {
            .type = IMM_TYPE_FC_CREDIT_REQ,
            .notify = credits_per_request,
            .rsvd0 = 0,
            .rsvd1 = 0
        }
    };
    urma_jfs_wr_t urma_wr = {.user_ctx = obj.value,
        .send = {.imm_data = imm.value},
        .flag = {.bs = {.complete_enable = 1, .inline_flag = 1}},
        .tjetty = tjetty,
        .opcode = URMA_OPC_SEND_IMM};
    urma_jfs_wr_t *bad_wr = NULL;
    urma_status_t status = umq_symbol_urma()->urma_post_jetty_send_wr(jetty, &urma_wr, &bad_wr);
    if (status == URMA_SUCCESS) {
        umq_ub_fc_packet_stats(&queue->flow_control, 1, UB_PACKET_STATS_TYPE_SEND);
        return UMQ_SUCCESS;
    }
    umq_ub_permission_release(fc);
    UMQ_LIMIT_VLOG_ERR(VLOG_UMQ_URMA_API, "local eid: " EID_FMT ", local jetty_id: %u, remote eid: " EID_FMT ", "
        "remote jetty_id: %u, urma_post_jetty_send_wr for send credit req failed, status: %d\n",
        EID_ARGS(jetty->jetty_id.eid), jetty->jetty_id.id, EID_ARGS(tjetty->id.eid), tjetty->id.id, (int)status);
    return -UMQ_ERR_EFLOWCTL;
}

static int umq_ub_shared_credit_resp_send(ub_queue_t *queue, uint16_t notify)
{
    if (queue->bind_ctx == NULL) {
        return -UMQ_ERR_EINVAL;
    }
    int ret = umq_ub_poll_fc_tx(queue, NULL, 0);
    if (ret != UMQ_SUCCESS) {
        return ret;
    }
    urma_jetty_t *jetty  = queue->jetty[UB_QUEUE_JETTY_FLOW_CONTROL];
    urma_target_jetty_t *tjetty = queue->bind_ctx->tjetty[UB_QUEUE_JETTY_FLOW_CONTROL];
    ub_credit_pool_t *pool = &queue->jfr_ctx[UB_QUEUE_JETTY_IO]->credit;
    uint16_t available = __atomic_load_n(&pool->stats_u16[CREDIT_POOL_IDLE], __ATOMIC_RELAXED);
    umq_ub_imm_t imm = {
        .flow_control = {
            .type = IMM_TYPE_FC_CREDIT_REP,
            .window = notify,
            .ratio = umq_ub_fc_raito_to_imm(available, queue->flow_control.local_rx_depth),
        }};
    umq_ub_fc_user_ctx_t obj = {
        .bs = {
            .type = IMM_TYPE_FC_CREDIT_REP,
            .notify = notify,
            .rsvd0 = 0,
            .rsvd1 = 0
        }
    };
    urma_jfs_wr_t urma_wr = {.user_ctx = obj.value,
        .send = {.imm_data = imm.value},
        .flag = {.bs = {.complete_enable = 1, .inline_flag = 1}},
        .tjetty = tjetty,
        .opcode = URMA_OPC_SEND_IMM};
    urma_jfs_wr_t *bad_wr = NULL;
    urma_status_t status = umq_symbol_urma()->urma_post_jetty_send_wr(jetty, &urma_wr, &bad_wr);
    if (status == URMA_SUCCESS) {
        umq_ub_fc_packet_stats(&queue->flow_control, 1, UB_PACKET_STATS_TYPE_SEND);
        return UMQ_SUCCESS;
    }

    UMQ_LIMIT_VLOG_ERR(VLOG_UMQ_URMA_API, "local eid: " EID_FMT ", local jetty_id: %u, remote eid: " EID_FMT ", "
        "remote jetty_id: %u, urma_post_jetty_send_wr for send credit req failed, status: %d\n",
        EID_ARGS(jetty->jetty_id.eid), jetty->jetty_id.id, EID_ARGS(tjetty->id.eid), tjetty->id.id, (int)status);
    return -UMQ_ERR_EFLOWCTL;
}

int umq_ub_shared_credit_req_handle(ub_queue_t *queue, umq_ub_imm_t *imm)
{
    ub_flow_control_t *fc = &queue->flow_control;
    ub_credit_pool_t *credit = &queue->jfr_ctx[UB_QUEUE_JETTY_IO]->credit;
    uint16_t credits_per_request = imm->flow_control.window;
    uint16_t allocated_count = credit->ops.available_credit_dec(credit, credits_per_request);
    (void)fc->ops.local_rx_allocated_inc(fc, allocated_count);
    int ret = umq_ub_shared_credit_resp_send(queue, allocated_count);
    if (ret != UMQ_SUCCESS) {
        (void)credit->ops.available_credit_return(credit, allocated_count);
        (void)fc->ops.local_rx_allocated_dec(fc, allocated_count);
        return ret;
    }
    return UMQ_SUCCESS;
}

void umq_ub_shared_credit_resp_handle(ub_queue_t *queue, umq_ub_imm_t *imm)
{
    ub_flow_control_t *fc = &queue->flow_control;
    uint16_t reply_credits = imm->flow_control.window;
    uint16_t credits_per_request = fc->credits_per_request;
    fc->peer_ratio = imm->flow_control.ratio;
    uint32_t new_request;
    if (reply_credits < credits_per_request) {
        new_request = (uint32_t)(credits_per_request / fc->credit_multiple);
    } else {
        new_request = (uint32_t)(credits_per_request * fc->credit_multiple);
        if (new_request > fc->max_credits_request) {
            new_request = fc->max_credits_request;
        }
    }
    /*
    * Prevent the current credit from being 2. If after doubling and multiplying by the idle ratio,
    * the rounded result is still 2, the credit count will remain permanently at 2.
    * Therefore, an increment of 1 is required.
    */
    fc->credits_per_request = umq_ub_fc_threashold_modify((uint16_t)new_request, fc->peer_ratio) + 1;
    umq_ub_window_inc(fc, reply_credits);
    return;
}

int umq_ub_shared_credit_return_req_send(ub_queue_t *queue)
{
    ub_flow_control_t *fc = &queue->flow_control;
    if (!fc->enabled || queue->bind_ctx == NULL) {
        return UMQ_SUCCESS;
    }
    uint64_t timestamp = get_timestamp_us();
    if ((queue->checker == NULL) || (timestamp < queue->checker->last_send)) {
        return UMQ_SUCCESS;
    }
    uint64_t diff = timestamp - queue->checker->last_send;
    uint16_t remote_credit = fc->ops.remote_rx_window_load(fc);
    uint16_t return_threshold = 0;
    if (fc->peer_ratio == 0) {
        return_threshold = 0;
    } else {
        return_threshold = umq_ub_fc_threashold_modify((uint16_t)fc->min_reserved_credit, fc->peer_ratio);
    }
    if (diff < queue->flow_control.timeout_us || remote_credit <= return_threshold) {
        return UMQ_SUCCESS;
    }
    if (!umq_ub_permission_acquire(fc)) {
        return UMQ_SUCCESS;
    }
    int ret = umq_ub_poll_fc_tx(queue, NULL, 0);
    if (ret != UMQ_SUCCESS) {
        umq_ub_permission_release(fc);
        return ret;
    }
    uint16_t return_credit;
    uint16_t new_request;
    new_request = (uint16_t)(fc->credits_per_request / fc->credit_multiple);
    if (new_request == 0) {
        new_request = 1;
    }
    fc->credits_per_request = new_request;
    return_credit = remote_credit / fc->return_ratio;
    if (return_credit == 0) {
        return_credit = 1;
    }
    if (remote_credit - return_credit <= return_threshold) {
        return_credit = remote_credit - return_threshold;
    }
    urma_jetty_t *jetty  = queue->jetty[UB_QUEUE_JETTY_FLOW_CONTROL];
    urma_target_jetty_t *tjetty = queue->bind_ctx->tjetty[UB_QUEUE_JETTY_FLOW_CONTROL];
    if (return_credit > UMQ_UB_FC_MAX_IMM_DATA) {
        return_credit = UMQ_UB_FC_MAX_IMM_DATA;
    }
    return_credit = fc->ops.remote_rx_window_dec(fc, return_credit, true);
    umq_ub_imm_t imm = {
        .flow_control = {
            .type = IMM_TYPE_FC_CREDIT_RETURN_REQ,
            .window = return_credit}
        };

    umq_ub_fc_user_ctx_t obj = {
        .bs = {
            .type = IMM_TYPE_FC_CREDIT_RETURN_REQ,
            .notify = return_credit,
            .rsvd0 = 0,
            .rsvd1 = 0
        }
    };

    urma_jfs_wr_t urma_wr = {.user_ctx = obj.value,
        .send = {.imm_data = imm.value},
        .flag = {.bs = {.complete_enable = 1, .inline_flag = 1}},
        .tjetty = tjetty,
        .opcode = URMA_OPC_SEND_IMM};
    urma_jfs_wr_t *bad_wr = NULL;
    urma_status_t status = umq_symbol_urma()->urma_post_jetty_send_wr(jetty, &urma_wr, &bad_wr);
    if (status == URMA_SUCCESS) {
        umq_ub_fc_packet_stats(&queue->flow_control, 1, UB_PACKET_STATS_TYPE_SEND);
        return UMQ_SUCCESS;
    }
    umq_ub_permission_release(fc);
    UMQ_LIMIT_VLOG_ERR(VLOG_UMQ_URMA_API, "local eid: " EID_FMT ", local jetty_id: %u, remote eid: " EID_FMT ", "
        "remote jetty_id: %u, urma_post_jetty_send_wr for return credit req failed, status: %d\n",
        EID_ARGS(jetty->jetty_id.eid), jetty->jetty_id.id, EID_ARGS(tjetty->id.eid), tjetty->id.id, (int)status);
    fc->ops.remote_rx_window_inc(fc, return_credit, true);
    return -UMQ_ERR_EFLOWCTL;
}

static int umq_ub_shared_credit_return_ack(ub_queue_t *queue, uint16_t return_credit)
{
    ub_flow_control_t *fc = &queue->flow_control;
    if (!fc->enabled || queue->bind_ctx == NULL) {
        return UMQ_SUCCESS;
    }
    int ret = umq_ub_poll_fc_tx(queue, NULL, 0);
    if (ret != UMQ_SUCCESS) {
        return ret;
    }
    urma_jetty_t *jetty  = queue->jetty[UB_QUEUE_JETTY_FLOW_CONTROL];
    urma_target_jetty_t *tjetty = queue->bind_ctx->tjetty[UB_QUEUE_JETTY_FLOW_CONTROL];
    ub_credit_pool_t *pool = &queue->jfr_ctx[UB_QUEUE_JETTY_IO]->credit;
    uint16_t available = __atomic_load_n(&pool->stats_u16[CREDIT_POOL_IDLE], __ATOMIC_RELAXED);
    umq_ub_imm_t imm = {
        .flow_control = {
            .type = IMM_TYPE_FC_CREDIT_RETURN_ACK,
            .window = return_credit,
            .ratio = umq_ub_fc_raito_to_imm(available, queue->flow_control.local_rx_depth)
            }
        };

    umq_ub_fc_user_ctx_t obj = {
        .bs = {
            .type = IMM_TYPE_FC_CREDIT_RETURN_ACK,
            .notify = return_credit,
            .rsvd0 = 0,
            .rsvd1 = 0
        }
    };
    urma_jfs_wr_t urma_wr = {.user_ctx = obj.value,
        .send = {.imm_data = imm.value},
        .flag = {.bs = {.complete_enable = 1, .inline_flag = 1}},
        .tjetty = tjetty,
        .opcode = URMA_OPC_SEND_IMM};
    urma_jfs_wr_t *bad_wr = NULL;
    urma_status_t status = umq_symbol_urma()->urma_post_jetty_send_wr(jetty, &urma_wr, &bad_wr);
    if (status == URMA_SUCCESS) {
        umq_ub_fc_packet_stats(&queue->flow_control, 1, UB_PACKET_STATS_TYPE_SEND);
        return UMQ_SUCCESS;
    }
    UMQ_LIMIT_VLOG_ERR(VLOG_UMQ_URMA_API, "local eid: " EID_FMT ", local jetty_id: %u, remote eid: " EID_FMT ", "
        "remote jetty_id: %u, urma_post_jetty_send_wr for send return ack failed, status: %d\n",
        EID_ARGS(jetty->jetty_id.eid), jetty->jetty_id.id, EID_ARGS(tjetty->id.eid), tjetty->id.id, (int)status);
    return -UMQ_ERR_EFLOWCTL;
}

int umq_ub_shared_credit_return_req_handle(ub_queue_t *queue, umq_ub_imm_t *imm)
{
    ub_flow_control_t *fc = &queue->flow_control;
    ub_credit_pool_t *credit = &queue->jfr_ctx[UB_QUEUE_JETTY_IO]->credit;
    uint16_t return_credit = imm->flow_control.window;
    uint64_t consumed_credit = umq_ub_rx_consumed_load(queue->dev_ctx->io_lock_free,
        &queue->dev_ctx->rx_consumed_jetty_table[queue->jetty[UB_QUEUE_JETTY_IO]->jetty_id.id]);
    uint64_t allocated_credit = fc->ops.local_rx_allocated_load(fc);
    if (allocated_credit < consumed_credit) {
        UMQ_LIMIT_VLOG_ERR(VLOG_UMQ_URMA_API, "local eid: " EID_FMT ", local jetty_id: %u, "
            "allocated_credit less than consumed credit\n",
            EID_ARGS(queue->jetty[UB_QUEUE_JETTY_FLOW_CONTROL]->jetty_id.eid),
            queue->jetty[UB_QUEUE_JETTY_FLOW_CONTROL]->jetty_id.id);
        return umq_ub_shared_credit_return_ack(queue, 0);
    }
    uint64_t unconsumed = allocated_credit - consumed_credit;
    if (return_credit > unconsumed) {
        UMQ_LIMIT_VLOG_ERR(VLOG_UMQ_URMA_API, "local eid: " EID_FMT ", local jetty_id: %u, "
            "return credit: %u > unconsumed credit: %u\n",
            EID_ARGS(queue->jetty[UB_QUEUE_JETTY_FLOW_CONTROL]->jetty_id.eid),
            queue->jetty[UB_QUEUE_JETTY_FLOW_CONTROL]->jetty_id.id, return_credit, (uint32_t)unconsumed);
        return_credit = unconsumed;
    }

    credit->ops.available_credit_return(credit, return_credit);
    (void)fc->ops.local_rx_allocated_dec(fc, return_credit);
    return umq_ub_shared_credit_return_ack(queue, return_credit);
}

void umq_ub_rx_consumed_inc(bool lock_free, volatile uint64_t *var, uint64_t count)
{
    if (lock_free) {
        *var = *var + count;
    } else {
        (void)__atomic_fetch_add(var, count, __ATOMIC_RELAXED);
    }
}

uint64_t umq_ub_rx_consumed_exchange(bool lock_free, volatile uint64_t *var, uint64_t count)
{
    if (lock_free) {
        uint64_t temp = *var;
        *var = 0;
        return temp;
    } else {
        return __atomic_exchange_n(var, 0, __ATOMIC_RELAXED);
    }
}

void umq_ub_credit_clean_up(ub_queue_t *queue)
{
    ub_flow_control_t *fc = &queue->flow_control;
    ub_credit_pool_t *credit = &queue->jfr_ctx[UB_QUEUE_JETTY_IO]->credit;
    uint16_t actual_return_credit = __atomic_exchange_n(&fc->local_rx_posted, 0, __ATOMIC_RELAXED);
    uint64_t consumed_credit = umq_ub_rx_consumed_load(queue->dev_ctx->io_lock_free,
        &queue->dev_ctx->rx_consumed_jetty_table[queue->jetty[UB_QUEUE_JETTY_IO]->jetty_id.id]);
    uint64_t allocated_credit = fc->ops.local_rx_allocated_load(fc);
    uint64_t unconsumed = allocated_credit - consumed_credit;
    if (unconsumed > UINT16_MAX) {
        UMQ_LIMIT_VLOG_WARN(VLOG_UMQ, "eid: " EID_FMT ", jetty_id: %u, unconsumed credit exceed UINT16_MAX, "
            "unconsumed credit %llu, capacity %d\n", EID_ARGS(queue->jetty[UB_QUEUE_JETTY_FLOW_CONTROL]->jetty_id.eid),
            queue->jetty[UB_QUEUE_JETTY_FLOW_CONTROL]->jetty_id.id, unconsumed, credit->capacity);
        return;
    }
    (void)credit->ops.available_credit_return(credit, actual_return_credit + unconsumed);
    (void)fc->ops.local_rx_allocated_dec(fc, unconsumed);
}

void umq_ub_idle_credit_flush(ub_queue_t *queue, uint32_t cnt)
{
    ub_flow_control_t *fc = &queue->flow_control;
    if (cnt != 0 && fc->enabled) {
        ub_credit_pool_t *credit = &queue->jfr_ctx[UB_QUEUE_JETTY_IO]->credit;
        bool use_atomic_window = queue->dev_ctx->flow_control.use_atomic_window;
        if (use_atomic_window) {
            (void)counter_dec_atomic_u16(credit, cnt, CREDIT_POOL_IDLE);
        } else {
            (void)counter_dec_non_atomic_u16(credit, cnt, CREDIT_POOL_IDLE);
        }
    }
}