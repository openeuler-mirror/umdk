/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2026-2026. All rights reserved.
 * Description: Bond worker thread header
 */

#ifndef BONDP_WORKER_H
#define BONDP_WORKER_H

#include <stdbool.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef uint64_t bondp_worker_task_id_t;

typedef void (*bondp_worker_task_fn_t)(void *arg);
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
 */
int bondp_worker_schedule(uint64_t delay_ms, bondp_worker_task_fn_t fn, void *arg, bondp_worker_task_id_t *task_id);

/**
 * @brief Cancel a scheduled bond worker task.
 * @param[in] task_id task id returned by bondp_worker_schedule().
 * @return 0 on success, negative errno on error.
 */
int bondp_worker_cancel(bondp_worker_task_id_t task_id);

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
