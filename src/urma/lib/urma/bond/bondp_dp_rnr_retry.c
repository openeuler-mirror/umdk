/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2026-2026. All rights reserved.
 * Description: Bond RNR retry helpers.
 */

#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <threads.h>
#include <time.h>
#include <unistd.h>

#include "bondp_datapath.h"
#include "bondp_types.h"
#include "bondp_worker.h"
#include "urma_log.h"

#include "bondp_dp_rnr_retry.h"

#define BONDP_RATIO_PERCENT 100

typedef struct bondp_rnr_retry_async_arg {
    bondp_comp_t *bdp_comp;
    uint32_t send_idx;
} bondp_rnr_retry_async_arg_t;

static uint64_t get_rnr_retry_jitter_rand(void)
{
    static thread_local struct random_data rand_data;
    static thread_local char rand_state[32] = {0};
    static thread_local bool rand_inited = false;
    int32_t rand_val = 0;

    if (!rand_inited) {
        struct timespec ts = {0};
        unsigned int seed = (unsigned int)getpid();

        if (clock_gettime(CLOCK_MONOTONIC, &ts) == 0) {
            seed ^= (unsigned int)ts.tv_nsec ^ (unsigned int)ts.tv_sec;
        }
        seed ^= (unsigned int)(uintptr_t)&rand_data;
        (void)memset(&rand_data, 0, sizeof(rand_data));
        (void)initstate_r(seed, rand_state, sizeof(rand_state), &rand_data);
        rand_inited = true;
    }

    if (random_r(&rand_data, &rand_val) != 0) {
        return 0;
    }
    return (uint64_t)(uint32_t)rand_val;
}

static uint64_t add_rnr_retry_jitter(uint64_t sleep_ms, uint32_t jitter_ratio)
{
    if (jitter_ratio == 0) {
        return sleep_ms;
    }

    uint64_t jitter_ms = (sleep_ms / BONDP_RATIO_PERCENT) * jitter_ratio +
                         ((sleep_ms % BONDP_RATIO_PERCENT) * jitter_ratio) / BONDP_RATIO_PERCENT;
    if (jitter_ms == 0) {
        return sleep_ms;
    }
    uint64_t rand_val = get_rnr_retry_jitter_rand();
    uint64_t jitter = (jitter_ms == UINT64_MAX) ? rand_val : rand_val % (jitter_ms + 1);
    if (UINT64_MAX - sleep_ms < jitter) {
        return UINT64_MAX;
    }
    return sleep_ms + jitter;
}

static uint64_t bondp_rnr_retry_delay_ms(const bondp_context_t *bdp_ctx, uint32_t retry_cnt)
{
    uint64_t delay_ms = bdp_ctx->rnr_retry_sleep_ms;

    if (retry_cnt > 1) {
        uint32_t backoff_cnt = retry_cnt - 1;
        for (uint32_t i = 0; i < backoff_cnt; i++) {
            if (delay_ms > UINT64_MAX / 2) {
                delay_ms = UINT64_MAX;
                break;
            }
            delay_ms <<= 1;
        }
    }
    return delay_ms == UINT64_MAX ? delay_ms :
        add_rnr_retry_jitter(delay_ms, bdp_ctx->rnr_retry_jitter_ratio);
}

static void resend_rnr_retry_wrs_async(bondp_worker_task_reason_t reason, void *arg)
{
    bondp_rnr_retry_async_arg_t *async_arg = arg;

    if (async_arg == NULL) {
        return;
    }
    bondp_comp_t *bdp_comp = async_arg->bdp_comp;
    uint32_t send_idx = async_arg->send_idx;

    (void)pthread_spin_lock(&bdp_comp->send_lock);
    if (send_idx < URMA_UBAGG_DEV_MAX_NUM) {
        bdp_comp->rnr_retry_tasks[send_idx].task_id = 0;
        bdp_comp->rnr_retry_tasks[send_idx].task_pending = false;
    }
    if (reason == BONDP_WORKER_TASK_EXECUTED && !atomic_load(&bdp_comp->deleting)) {
        for (uint32_t i = 0; i < bdp_comp->send_wr_buf.max_wr_num; i++) {
            jfs_wr_entry_t *wr_entry = __wr_buf_idx(&bdp_comp->send_wr_buf, i);
            if (wr_entry->entry_type != WR_BUF_ENTRY_JFS ||
                wr_entry->bdp_comp != bdp_comp || wr_entry->send_idx != send_idx ||
                !wr_entry->rnr_retry_pending) {
                continue;
            }

            uint64_t wr_id = wr_entry->wr_id;
            if (bondp_resend_jfs_wr(bdp_comp, wr_entry, wr_entry->send_idx, wr_entry->target_idx) != 0) {
                URMA_LOG_ERR("Failed to resend rnr retry jfs wr asynchronously, wr_id=%lu\n", wr_id);
            }
        }
    }
    atomic_fetch_sub(&bdp_comp->use_cnt.atomic_cnt, 1);
    (void)pthread_spin_unlock(&bdp_comp->send_lock);

    free(async_arg);
}

int bondp_rnr_retry_schedule(bondp_comp_t *bdp_comp, uint32_t send_idx,
                             uint32_t retry_cnt, bool *new_task)
{
    *new_task = false;
    if (send_idx >= URMA_UBAGG_DEV_MAX_NUM) {
        return -EINVAL;
    }
    if (atomic_load(&bdp_comp->deleting)) {
        return -ECANCELED;
    }
    bondp_rnr_retry_task_t *task = &bdp_comp->rnr_retry_tasks[send_idx];
    if (task->task_pending) {
        return 0;
    }

    bondp_rnr_retry_async_arg_t *async_arg = calloc(1, sizeof(*async_arg));
    if (async_arg == NULL) {
        return -ENOMEM;
    }
    async_arg->bdp_comp = bdp_comp;
    async_arg->send_idx = send_idx;

    task->task_pending = true;
    atomic_fetch_add(&bdp_comp->use_cnt.atomic_cnt, 1);
    uint64_t delay_ms = bondp_rnr_retry_delay_ms(bdp_comp->bondp_ctx, retry_cnt);
    int ret = bondp_worker_schedule(delay_ms, resend_rnr_retry_wrs_async, async_arg, &task->task_id);
    if (ret != 0) {
        atomic_fetch_sub(&bdp_comp->use_cnt.atomic_cnt, 1);
        task->task_id = 0;
        task->task_pending = false;
        free(async_arg);
    } else {
        *new_task = true;
    }
    return ret;
}

uint32_t bondp_rnr_retry_pending_task_num(bondp_comp_t *bdp_comp)
{
    uint32_t task_num = 0;

    (void)pthread_spin_lock(&bdp_comp->send_lock);
    for (uint32_t i = 0; i < URMA_UBAGG_DEV_MAX_NUM; i++) {
        if (bdp_comp->rnr_retry_tasks[i].task_pending) {
            task_num++;
        }
    }
    (void)pthread_spin_unlock(&bdp_comp->send_lock);
    return task_num;
}

int bondp_rnr_retry_cancel_all(bondp_comp_t *bdp_comp)
{
    bondp_worker_task_id_t task_ids[URMA_UBAGG_DEV_MAX_NUM];
    size_t task_num = 0;

    (void)pthread_spin_lock(&bdp_comp->send_lock);
    for (uint32_t i = 0; i < URMA_UBAGG_DEV_MAX_NUM; i++) {
        bondp_rnr_retry_task_t *task = &bdp_comp->rnr_retry_tasks[i];
        if (task->task_pending && task->task_id != 0) {
            task_ids[task_num++] = task->task_id;
        }
    }
    (void)pthread_spin_unlock(&bdp_comp->send_lock);

    return task_num == 0 ? 0 : bondp_worker_cancel_batch(task_ids, task_num);
}
