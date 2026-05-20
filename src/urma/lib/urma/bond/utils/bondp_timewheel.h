/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2026-2026. All rights reserved.
 * Description: Timing wheel internal header
 */

#ifndef BONDP_TIMEWHEEL_H
#define BONDP_TIMEWHEEL_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define TW_DEFAULT_TICK_MS  (10U)
#define TW_DEFAULT_SLOT_NUM (512U)

typedef uint64_t tw_task_id_t;

typedef void (*tw_task_fn_t)(void *arg);

typedef struct tw tw_t;

typedef struct tw_cfg {
    uint32_t tick_ms;
    uint32_t slot_num;
} tw_cfg_t;

/**
 * @brief Create a timing wheel instance.
 * @param[in] cfg timing wheel configuration. Default values will be
 * used when one field is 0.
 * @return Timing wheel instance pointer on success, NULL on error.
 */
tw_t *tw_create(const tw_cfg_t *cfg);

/**
 * @brief Destroy the timing wheel instance.
 * @param[in] tw timing wheel instance.
 * @note The caller must ensure no thread is concurrently calling
 * tw_schedule(), tw_cancel(), tw_advance(), or tw_destroy() on the same
 * timing wheel. Destroy is only valid after all external users have stopped
 * accessing the instance.
 */
void tw_destroy(tw_t *tw);

/**
 * @brief Schedule a task on the timing wheel.
 * @param[in] tw timing wheel instance.
 * @param[in] delay_ms task delay in milliseconds. The minimum effective delay
 * is one tick.
 * @param[in] fn task callback function.
 * @param[in] arg user private data passed to callback.
 * @param[out] task_id returned task id used for later cancellation.
 * @return 0 on success, negative errno on error.
 */
int tw_schedule(tw_t *tw, uint64_t delay_ms, tw_task_fn_t fn, void *arg, tw_task_id_t *task_id);

/**
 * @brief Cancel a scheduled task.
 * @param[in] tw timing wheel instance.
 * @param[in] task_id task id returned by tw_schedule().
 * @return 0 on success, negative errno on error.
 */
int tw_cancel(tw_t *tw, tw_task_id_t task_id);

/**
 * @brief Get the tick interval of the timing wheel.
 * @param[in] tw timing wheel instance.
 * @return Tick interval in milliseconds, 0 when tw is NULL.
 */
uint32_t tw_get_tick_ms(const tw_t *tw);

/**
 * @brief Advance the timing wheel by a specified tick count.
 * @param[in] tw timing wheel instance.
 * @param[in] tick_cnt number of ticks to advance.
 */
void tw_advance(tw_t *tw, uint64_t tick_cnt);

#ifdef __cplusplus
}
#endif

#endif // BONDP_TIMEWHEEL_H
