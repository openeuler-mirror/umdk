/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2025-2025. All rights reserved.
 * Description: urpc command queue
 * Create: 2025-02-25
 */

#ifndef URPC_URPC_CMD_QUEUE_H
#define URPC_URPC_CMD_QUEUE_H

#include <pthread.h>
#include <stdint.h>
#include <sys/queue.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef void (*urpc_cmd_process_t)(void *args);
typedef void (*urpc_cmd_exception_t)(void *args);

typedef struct urpc_cmd {
    urpc_cmd_process_t process;
    urpc_cmd_exception_t exception;
    void *args;
    STAILQ_ENTRY(urpc_cmd) node;
} urpc_cmd_t;
typedef STAILQ_HEAD(urpc_cmd_head, urpc_cmd) urpc_cmd_head_t;

/* Applicable to multi-producer but consumer models. */
typedef struct urpc_cmd_queue {
    urpc_cmd_head_t head;
    pthread_spinlock_t lock;
    uint32_t count;
} urpc_cmd_queue_t;

void urpc_cmd_queue_init(urpc_cmd_queue_t *cmd_queue);
int urpc_cmd_queue_insert(
    urpc_cmd_queue_t *cmd_queue, urpc_cmd_process_t process, urpc_cmd_exception_t exception, void *args);
urpc_cmd_t *urpc_cmd_queue_pop(urpc_cmd_queue_t *cmd_queue);
void urpc_cmd_queue_process(urpc_cmd_queue_t *cmd_queue);
void urpc_cmd_queue_flush(urpc_cmd_queue_t *cmd_queue);

#ifdef __cplusplus
}
#endif

#endif
