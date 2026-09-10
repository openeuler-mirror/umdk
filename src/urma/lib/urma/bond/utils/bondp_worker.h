/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2026-2026. All rights reserved.
 * Description: Bond worker thread header
 */

#ifndef BONDP_WORKER_H
#define BONDP_WORKER_H

#include <stddef.h>
#include <stdint.h>

#include "bondp_timewheel.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef uint64_t bondp_worker_task_id_t;

typedef tw_task_reason_t bondp_worker_task_reason_t;

#define BONDP_WORKER_TASK_EXECUTED TW_TASK_EXECUTED
#define BONDP_WORKER_TASK_CANCELED TW_TASK_CANCELED

typedef void (*bondp_worker_task_fn_t)(bondp_worker_task_reason_t reason, void *arg);
typedef void (*bondp_worker_event_fn_t)(void *arg);

/**
 * @brief Create the bond worker instance.
 * @note The caller must serialize create/destroy against all other bond worker
 * APIs.
 * @return 0 on success, negative errno on error.
 */
int bondp_worker_create(void);

/**
 * @brief Destroy the bond worker instance.
 * @note The caller must serialize create/destroy against all other bond worker
 * APIs.
 */
void bondp_worker_destroy(void);

/**
 * @brief Schedule a task on the bond worker timing wheel.
 * @param[in] delay_ms task delay in milliseconds. The minimum effective delay
 * is one tick.
 * @param[in] fn task callback function.
 * @param[in] arg user private data passed to callback.
 * @param[out] task_id returned task id used for later cancellation.
 * @return 0 on success, negative errno on error.
 * @note Once successfully scheduled, fn is called exactly once, with either
 * BONDP_WORKER_TASK_EXECUTED when the delay expires or
 * BONDP_WORKER_TASK_CANCELED when canceled or during worker destruction.
 */
int bondp_worker_schedule(uint64_t delay_ms, bondp_worker_task_fn_t fn, void *arg, bondp_worker_task_id_t *task_id);

/**
 * @brief Cancel a scheduled bond worker task.
 * @param[in] task_id task id returned by bondp_worker_schedule().
 * @return 0 on success, negative errno on error.
 * @note The cancellation is processed by the worker thread. On success, the
 * task callback has been invoked with BONDP_WORKER_TASK_CANCELED before this
 * function returns.
 */
int bondp_worker_cancel(bondp_worker_task_id_t task_id);

/**
 * @brief Cancel multiple scheduled bond worker tasks in one worker command.
 * @param[in] task_ids task ids returned by bondp_worker_schedule().
 * @param[in] task_num number of task ids.
 * @return 0 when all tasks were canceled or had already executed, otherwise
 * the first cancellation error.
 * @note The cancellation is processed by the worker thread. Before this
 * function returns, every listed task has either completed execution or had
 * its cancellation callback invoked.
 */
int bondp_worker_cancel_batch(const bondp_worker_task_id_t *task_ids, size_t task_num);

/**
 * @brief Register an fd on the bond worker epoll instance.
 * @param[in] fd file descriptor to monitor.
 * @param[in] handler callback function invoked when the fd becomes readable.
 * @param[in] arg user private data passed to callback.
 * @return 0 on success, negative errno on error.
 */
int bondp_worker_add_fd(int fd, bondp_worker_event_fn_t handler, void *arg);

/**
 * @brief Unregister an fd from the bond worker epoll instance.
 * @param[in] fd file descriptor to remove.
 * @return 0 on success, negative errno on error.
 */
int bondp_worker_del_fd(int fd);

#ifdef __cplusplus
}
#endif

#endif // BONDP_WORKER_H
