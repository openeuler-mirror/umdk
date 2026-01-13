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
#define UMQ_UB_FLOW_CONTROL_LEAK_CREDIT_THR 3

static ALWAYS_INLINE uint16_t counter_inc_atomic_u16(ub_credit_pool_t *pool, uint16_t count,
    ub_credit_stat_u16_t type) {
    volatile uint16_t *counter = &pool->stats_u16[type];
    uint16_t after, before = __atomic_load_n(counter, __ATOMIC_RELAXED);
    uint16_t ret = before;
    uint32_t sum;

    do {
        sum = before + count;
        if (URPC_UNLIKELY(sum > UINT16_MAX)) {
            UMQ_LIMIT_VLOG_WARN("counter type %d exceed UINT16_MAX, current %d, new add %d, capacity %d\n",
                                type, before, count, pool->capacity);
            ret = before;
            break;
        }

        if (type == IDLE_CREDIT_COUNT && URPC_UNLIKELY(sum > pool->capacity)) {
            UMQ_LIMIT_VLOG_WARN("exceed capacity, current win %d, new add %d, capacity %d\n",
                before, count, pool->capacity);
        }
        after = (uint16_t)sum;
        ret = after;
    } while (
        !__atomic_compare_exchange_n(counter, &before, after, true, __ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE));

    return ret;
}

static ALWAYS_INLINE uint16_t counter_dec_atomic_u16(ub_credit_pool_t *pool, uint16_t count,
    ub_credit_stat_u16_t type) {
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
    } while (
        !__atomic_compare_exchange_n(counter, &before, after, true, __ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE));
    return ret;
}

static ALWAYS_INLINE uint16_t counter_dec_atomic_u64(volatile uint64_t *counter, uint16_t count) {
    uint64_t after, before = __atomic_load_n(counter, __ATOMIC_RELAXED);
    uint64_t ret = before;

    do {
        if (URPC_UNLIKELY(before == 0)) {
            ret = 0;
            break;
        }

        after = before > count ? before - count : 0;
        ret = before - after;
    } while (
        !__atomic_compare_exchange_n(counter, &before, after, true, __ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE));
    return ret;
}

static ALWAYS_INLINE uint16_t counter_dec_non_atomic_u64(volatile uint64_t *counter, uint16_t count) {
    if (URPC_LIKELY(*counter >= count)) {
       *counter -= count;
        return count;
    }
    uint16_t temp = (uint16_t)(*counter);
    *counter = 0;
    return temp;
}

static ALWAYS_INLINE uint64_t counter_inc_atomic_u64(volatile uint64_t *counter, uint16_t count) {
    uint64_t after, before = __atomic_load_n(counter, __ATOMIC_RELAXED);
    uint64_t ret = before;
    do {
        after = before + count;
        ret = after;
    } while (
        !__atomic_compare_exchange_n(&counter, &before, after, true, __ATOMIC_ACQ_REL,
            __ATOMIC_ACQUIRE));
    return ret;
}

static ALWAYS_INLINE uint16_t counter_inc_non_atomic_u16(ub_credit_pool_t *pool, uint16_t count,
    ub_credit_stat_u16_t type) {
    uint16_t before = pool->stats_u16[type];
    uint32_t sum = pool->stats_u16[type] + count;

    if (URPC_UNLIKELY(sum > UINT16_MAX)) {
        UMQ_LIMIT_VLOG_WARN("type %d exceed UINT16_MAX, current %d, new add %d, capacity %d\n",
                            type, before, count, pool->capacity);
        return before;
    }

    if (type == IDLE_CREDIT_COUNT && (URPC_UNLIKELY(sum > pool->capacity))) {
        UMQ_LIMIT_VLOG_WARN("type %d exceed capacity, current %d, new add %d, capacity %d\n",
                            type, before, count, pool->capacity);
    }
    pool->stats_u16[type] = (uint16_t)sum;
    return pool->stats_u16[type];
}

static ALWAYS_INLINE uint16_t counter_dec_non_atomic_u16(ub_credit_pool_t *pool, uint16_t count,
    ub_credit_stat_u16_t type) {
    uint16_t before = pool->stats_u16[type];

    if (before < count) {
        pool->stats_u16[type] = 0;
        return before;
    }
    pool->stats_u16[type] -= count;
    return count;
}

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

static ALWAYS_INLINE uint64_t local_rx_allocted_inc_non_atomic(struct ub_flow_control *fc, uint16_t win)
{
    fc->stats_u64[ALLOCATED_RX_TOTAL] += win;
    return fc->stats_u64[ALLOCATED_RX_TOTAL];
}

static ALWAYS_INLINE uint16_t local_rx_allocted_dec_non_atomic(struct ub_flow_control *fc, uint16_t win)
{
    return counter_dec_non_atomic_u64(&fc->stats_u64[ALLOCATED_RX_TOTAL], win);
}

static ALWAYS_INLINE uint64_t local_rx_allocted_load_non_atomic(struct ub_flow_control *fc)
{
    return fc->stats_u64[ALLOCATED_RX_TOTAL];
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

static ALWAYS_INLINE uint64_t local_rx_allocted_inc_atomic(struct ub_flow_control *fc, uint16_t win)
{
    return counter_inc_atomic_u64(&fc->stats_u64[ALLOCATED_RX_TOTAL], win);
}

static ALWAYS_INLINE uint16_t local_rx_allocted_dec_atomic(struct ub_flow_control *fc, uint16_t win)
{
    return counter_dec_atomic_u64(&fc->stats_u64[ALLOCATED_RX_TOTAL], win);
}

static ALWAYS_INLINE uint64_t local_rx_allocted_load_atomic(struct ub_flow_control *fc)
{
    return __atomic_load_n(&fc->stats_u64[ALLOCATED_RX_TOTAL], __ATOMIC_RELAXED);
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

static ALWAYS_INLINE uint16_t available_credit_inc_atomic(ub_credit_pool_t *pool, uint16_t count)
{
    uint16_t before = __atomic_load_n(&pool->stats_u16[IDLE_CREDIT_COUNT], __ATOMIC_RELAXED);
    uint16_t ret = counter_inc_atomic_u16(pool, count, IDLE_CREDIT_COUNT);
    if (URPC_UNLIKELY(ret == before)) {
        (void)__atomic_add_fetch(&pool->stats_u64[CREDIT_ERR_TOTAL], count, __ATOMIC_RELAXED);
    } else {
        (void)__atomic_add_fetch(&pool->stats_u64[CREDIT_TOTAL], count, __ATOMIC_RELAXED);
    }
    return ret;
}

static ALWAYS_INLINE uint16_t leak_credit_load_atomic(ub_credit_pool_t *pool)
{
    return __atomic_load_n(&pool->stats_u16[LEAKED_CREDIT_COUNT], __ATOMIC_RELAXED);
}

static ALWAYS_INLINE uint16_t leak_credit_inc_atomic(ub_credit_pool_t *pool, uint16_t count)
{
    return counter_inc_atomic_u16(pool, count, LEAKED_CREDIT_COUNT);
}

static ALWAYS_INLINE uint16_t available_credit_return_atomic(ub_credit_pool_t *pool, uint16_t count)
{
    return counter_inc_atomic_u16(pool, count, IDLE_CREDIT_COUNT);
}

static ALWAYS_INLINE uint16_t leak_credit_recycle_atomic(ub_credit_pool_t *pool, uint16_t count)
{
    uint16_t ret = counter_dec_atomic_u16(pool, count, LEAKED_CREDIT_COUNT);
    (void)counter_inc_atomic_u16(pool, count, IDLE_CREDIT_COUNT);
    return ret;
}

static ALWAYS_INLINE uint16_t available_credit_dec_atomic(ub_credit_pool_t *pool, uint16_t count)
{
    uint16_t leak_count = leak_credit_load_atomic(pool);
    if (leak_count > pool->leak_threshold) {
        leak_credit_recycle_atomic(pool, leak_count);
    }
    return counter_dec_atomic_u16(pool, count, IDLE_CREDIT_COUNT);
}

static ALWAYS_INLINE uint16_t available_credit_load_atomic(ub_credit_pool_t *pool)
{
    return __atomic_load_n(&pool->stats_u16[LEAKED_CREDIT_COUNT], __ATOMIC_RELAXED);
}

static ALWAYS_INLINE uint16_t available_credit_inc_non_atomic(ub_credit_pool_t *pool, uint16_t count)
{
    uint16_t before = pool->stats_u16[IDLE_CREDIT_COUNT];
    uint16_t ret = counter_inc_non_atomic_u16(pool, count, IDLE_CREDIT_COUNT);
    if (URPC_UNLIKELY(ret == before)) {
        pool->stats_u16[CREDIT_ERR_TOTAL] += count;
    } else {
        pool->stats_u16[CREDIT_TOTAL] += count;
    }
    return ret;
}

static ALWAYS_INLINE uint16_t leak_credit_recycle_non_atomic(ub_credit_pool_t *pool, uint16_t count)
{
    uint16_t recycle_count = counter_dec_non_atomic_u16(pool, count, LEAKED_CREDIT_COUNT);
    (void)counter_inc_atomic_u16(pool, recycle_count, IDLE_CREDIT_COUNT);
    return recycle_count;
}

static ALWAYS_INLINE uint16_t available_credit_dec_non_atomic(ub_credit_pool_t *pool, uint16_t count)
{
    if (pool->stats_u16[LEAKED_CREDIT_COUNT] > pool->leak_threshold) {
        leak_credit_recycle_non_atomic(pool, pool->stats_u16[LEAKED_CREDIT_COUNT]);
    }
    return counter_dec_non_atomic_u16(pool, count, IDLE_CREDIT_COUNT);
}

static ALWAYS_INLINE uint16_t available_credit_load_non_atomic(ub_credit_pool_t *pool)
{
    return pool->stats_u16[IDLE_CREDIT_COUNT];
}

static ALWAYS_INLINE uint16_t available_credit_return_non_atomic(ub_credit_pool_t *pool, uint16_t count)
{
    return counter_inc_non_atomic_u16(pool, count, IDLE_CREDIT_COUNT);
}

static ALWAYS_INLINE uint16_t leak_credit_load_non_atomic(ub_credit_pool_t *pool)
{
    return pool->stats_u16[LEAKED_CREDIT_COUNT];
}

static ALWAYS_INLINE uint16_t leak_credit_inc_non_atomic(ub_credit_pool_t *pool, uint16_t count)
{
    return counter_inc_non_atomic_u16(pool, count, LEAKED_CREDIT_COUNT);
}

__attribute__((unused)) static void umq_ub_cerdit_pool_init(ub_queue_t *queue, uint32_t feature,
    umq_flow_control_cfg_t *cfg)
{
    ub_credit_pool_t *pool = &queue->jfr_ctx[UB_QUEUE_JETTY_IO]->credit;
    memset(pool, 0, sizeof(ub_credit_pool_t));
    pool->capacity = queue->rx_depth;
    pool->leak_threshold = pool->capacity >> UMQ_UB_FLOW_CONTROL_LEAK_CREDIT_THR;
    if (pool->leak_threshold == 0) {
        pool->leak_threshold = 1;
    }

    if (cfg->use_atomic_window) {
        pool->ops.available_credit_inc = available_credit_inc_atomic;
        pool->ops.available_credit_dec = available_credit_dec_atomic;
        pool->ops.available_credit_load = available_credit_load_atomic;
        pool->ops.available_credit_return = available_credit_return_atomic;
        pool->ops.leak_credit_inc = leak_credit_inc_atomic;
        pool->ops.leak_credit_recycle = leak_credit_recycle_atomic;
    } else {
        pool->ops.available_credit_inc = available_credit_inc_non_atomic;
        pool->ops.available_credit_dec = available_credit_dec_non_atomic;
        pool->ops.available_credit_load = available_credit_load_non_atomic;
        pool->ops.available_credit_return = available_credit_return_non_atomic;
        pool->ops.leak_credit_inc = leak_credit_inc_non_atomic;
        pool->ops.leak_credit_recycle = leak_credit_recycle_non_atomic;
    }
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
        .tjetty = queue->bind_ctx->tjetty[UB_QUEUE_JETTY_IO]};
    urma_status_t status = urma_post_jetty_send_wr(queue->jetty[UB_QUEUE_JETTY_IO], &urma_wr, &bad_wr);
    if (status == URMA_SUCCESS) {
        fc->remote_get = true;
        return;
    }

    UMQ_LIMIT_VLOG_ERR("umq ub flow control get remote window failed, error %d, local eid: " EID_FMT ", "
                       "local jetty_id: %u, remote eid: " EID_FMT ", remote jetty_id: %u\n", (int)status,
                       EID_ARGS(queue->jetty[UB_QUEUE_JETTY_IO]->jetty_id.eid),
                       queue->jetty[UB_QUEUE_JETTY_IO]->jetty_id.id,
                       EID_ARGS(queue->bind_ctx->tjetty[UB_QUEUE_JETTY_IO]->id.eid),
                       queue->bind_ctx->tjetty[UB_QUEUE_JETTY_IO]->id.id);
}

void umq_ub_rq_posted_notifier_inc(ub_flow_control_t *fc, uint16_t rx_posted)
{
    if (rx_posted == 0 || !fc->enabled) {
        return;
    }

    (void)fc->ops.local_rx_posted_inc(fc, rx_posted);
}

void umq_ub_shared_credit_recharge(ub_queue_t *queue, uint16_t recharge_count) {
    ub_flow_control_t *fc = &queue->flow_control;

    if (recharge_count == 0 || !fc->enabled) {
        return;
    }

    ub_credit_pool_t *credit = &queue->jfr_ctx[UB_QUEUE_JETTY_IO]->credit;
    credit->ops.available_credit_inc(credit, recharge_count);
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
        .tjetty = queue->bind_ctx->tjetty[UB_QUEUE_JETTY_IO],
        .opcode = URMA_OPC_SEND_IMM};
    urma_jfs_wr_t *bad_wr = NULL;
    urma_status_t status = urma_post_jetty_send_wr(queue->jetty[UB_QUEUE_JETTY_IO], &urma_wr, &bad_wr);
    if (status == URMA_SUCCESS) {
        return;
    }

    UMQ_LIMIT_VLOG_ERR("flow control window send failed, status %d, local eid: " EID_FMT ", "
                       "local jetty_id: %u, remote eid: " EID_FMT ", remote jetty_id: %u\n", (int)status,
                       EID_ARGS(queue->jetty[UB_QUEUE_JETTY_IO]->jetty_id.eid),
                       queue->jetty[UB_QUEUE_JETTY_IO]->jetty_id.id,
                       EID_ARGS(queue->bind_ctx->tjetty[UB_QUEUE_JETTY_IO]->id.eid),
                       queue->bind_ctx->tjetty[UB_QUEUE_JETTY_IO]->id.id);
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

void umq_ub_default_credit_allocate(ub_queue_t *queue, ub_flow_control_t *fc) {
    ub_credit_pool_t *credit = &queue->jfr_ctx[UB_QUEUE_JETTY_IO]->credit;
    uint16_t initial_credit = queue->dev_ctx->flow_control.initial_credit;
    uint16_t allocted_count = credit->ops.available_credit_dec(credit, initial_credit);
    uint16_t notify = fc->ops.local_rx_posted_inc(fc, allocted_count);

    if (!fc->local_set) {
        notify = fc->ops.local_rx_posted_exchange(fc);
        (void)fc->ops.local_rx_allocted_inc(fc, notify);
        umq_ub_fc_info_t *local_data =
            (umq_ub_fc_info_t *)(uintptr_t)umq_ub_notify_buf_addr_get(queue, OFFSET_FLOW_CONTROL);
        local_data->fc.local_window = notify;
        local_data->fc.local_rx_depth = UMQ_UB_FLOW_CONTORL_JETTY_DEPTH;
        fc->local_set = true;
        if (!fc->remote_get) {
            umq_ub_window_read(fc, queue);
        }
        return;
    }
}

static ALWAYS_INLINE bool umq_ub_sending_permission_acquire(struct ub_flow_control *fc) {
    bool expected = false;
    bool desired = true;
    return __atomic_compare_exchange_n(&fc->is_credit_applying, &expected, desired, false,
        __ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE);
}

static ALWAYS_INLINE void umq_ub_sending_permission_release(struct ub_flow_control *fc) {
    __atomic_store_n(&fc->is_credit_applying, false, __ATOMIC_RELAXED);
}

void umq_ub_shared_credit_req_send(ub_queue_t *queue)
{
    uint16_t credits_per_request = queue->dev_ctx->flow_control.credits_per_request;
    urma_jetty_t *jetty  = queue->jetty[UB_QUEUE_JETTY_FLOW_CONTROL];
    urma_target_jetty_t *tjetty = queue->bind_ctx->tjetty[UB_QUEUE_JETTY_FLOW_CONTROL];
    ub_flow_control_t *fc = &queue->flow_control;
    umq_ub_imm_t imm = {
        .flow_control = {
            .umq_private = UMQ_UB_IMM_PRIVATE,
            .type = IMM_TYPE_FLOW_CONTROL,
            .sub_type = IMM_TYPE_FC_CREDIT_REQ,
            .in_user_buf = 0,
            .window = credits_per_request}
        };

    umq_ub_fc_user_ctx_t obj = {
        .operator = {
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

    if (!umq_ub_sending_permission_acquire(fc)) {
        UMQ_LIMIT_VLOG_WARN("umq credit req already send\n");
        return;
    }
    urma_status_t status = urma_post_jetty_send_wr(jetty, &urma_wr, &bad_wr);
    if (status == URMA_SUCCESS) {
        return;
    }

    UMQ_LIMIT_VLOG_ERR("send credit req failed, status %d, local eid: " EID_FMT ", "
                       "local jetty_id: %u, remote eid: " EID_FMT ", remote jetty_id: %u\n", (int)status,
                       EID_ARGS(jetty->jetty_id.eid), jetty->jetty_id.id,
                       EID_ARGS(tjetty->id.eid), tjetty->id.id);
}

static void umq_ub_shared_credit_resp_send(ub_queue_t *queue, uint16_t notify)
{
    urma_jetty_t *jetty  = queue->jetty[UB_QUEUE_JETTY_FLOW_CONTROL];
    urma_target_jetty_t *tjetty = queue->bind_ctx->tjetty[UB_QUEUE_JETTY_FLOW_CONTROL];
    ub_flow_control_t *fc = &queue->flow_control;

    umq_ub_imm_t imm = {
        .flow_control = {
            .umq_private = UMQ_UB_IMM_PRIVATE,
            .type = IMM_TYPE_FLOW_CONTROL,
            .sub_type = IMM_TYPE_FC_CREDIT_REP,
            .in_user_buf = 0,
            .window = notify}
        };
    umq_ub_fc_user_ctx_t obj = {
        .operator = {
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
    urma_status_t status = urma_post_jetty_send_wr(jetty, &urma_wr, &bad_wr);
    if (status == URMA_SUCCESS) {
        return;
    }

    UMQ_LIMIT_VLOG_ERR("send credit req failed, status %d, local eid: " EID_FMT ", "
                       "local jetty_id: %u, remote eid: " EID_FMT ", remote jetty_id: %u\n", (int)status,
                       EID_ARGS(jetty->jetty_id.eid), jetty->jetty_id.id,
                       EID_ARGS(tjetty->id.eid), tjetty->id.id);
    umq_ub_rq_posted_notifier_inc(fc, notify);
    (void)fc->ops.local_rx_allocted_dec(fc, notify);
}

void umq_ub_shared_credit_req_handle(ub_queue_t *queue, umq_ub_imm_t *imm)
{
    ub_flow_control_t *fc = &queue->flow_control;
    ub_credit_pool_t *credit = &queue->jfr_ctx[UB_QUEUE_JETTY_IO]->credit;
    uint16_t credits_per_request = imm->flow_control.window;
    uint16_t notify;

    if (fc->ops.local_rx_posted_load(fc) < credits_per_request) {
        uint16_t allocted_count = credit->ops.available_credit_dec(credit, credits_per_request);
        notify = fc->ops.local_rx_posted_inc(fc, allocted_count);
    }
    notify = fc->ops.local_rx_posted_exchange(fc);
    (void)fc->ops.local_rx_allocted_inc(fc, notify);
    umq_ub_shared_credit_resp_send(queue, notify);
}

void umq_ub_shared_credit_resp_handle(ub_queue_t *queue, umq_ub_imm_t *imm) {
    ub_flow_control_t *fc = &queue->flow_control;
    uint16_t reply_credits = imm->flow_control.window;
    umq_ub_sending_permission_release(fc);
    umq_ub_window_inc(fc, reply_credits);
    return;
}

void umq_ub_leak_credit_recycle(ub_queue_t *queue, uint16_t count)
{
    ub_credit_pool_t *credit = &queue->jfr_ctx[UB_QUEUE_JETTY_IO]->credit;
    credit->ops.leak_credit_recycle(credit, count);
}

void umq_ub_rx_consumed_inc(bool lock_free, volatile uint64_t *var, uint64_t count)
{
    if (lock_free) {
        *var = *var + count;
    } else {
        (void)__sync_fetch_and_add(var, count);
    }
}

static ALWAYS_INLINE uint64_t umq_ub_rx_consumed_load(bool lock_free, volatile uint64_t *var)
{
    if (lock_free) {
        return *var;
    } else {
        return __atomic_load_n(var, __ATOMIC_RELAXED);
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

    credit->ops.available_credit_return(credit, actual_return_credit);
    uint64_t consumed_credit = umq_ub_rx_consumed_load(queue->dev_ctx->io_lock_free,
        &queue->dev_ctx->rx_consumed_jetty_table[queue->jetty[UB_QUEUE_JETTY_IO]->jetty_id.id]);
    uint64_t allocted_credit = fc->ops.local_rx_allocted_load(fc);
    uint64_t leak = allocted_credit - consumed_credit;
    if (leak > UINT16_MAX) {
        UMQ_LIMIT_VLOG_WARN("leak credit exceed UINT16_MAX, leak credit %llu, capacity %d\n", leak, credit->capacity);
        return;
    }
    credit->ops.leak_credit_inc(credit, leak);
}