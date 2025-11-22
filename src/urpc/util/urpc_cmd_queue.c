/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2025-2025. All rights reserved.
 * Description: urpc command queue
 * Create: 2025-02-25
 */
#include "urpc_cmd_queue.h"
#include "urpc_dbuf_stat.h"
#include "util_log.h"
#include "urpc_framework_errno.h"

#include "urpc_cmd_queue.h"

void urpc_cmd_queue_init(urpc_cmd_queue_t *cmd_queue)
{
    STAILQ_INIT(&cmd_queue->head);
    (void)pthread_spin_init(&cmd_queue->lock, PTHREAD_PROCESS_PRIVATE);
    cmd_queue->count = 0;
}

int urpc_cmd_queue_insert(
    urpc_cmd_queue_t *cmd_queue, urpc_cmd_process_t process, urpc_cmd_exception_t exception, void *args)
{
    if (process == NULL || exception == NULL) {
        UTIL_LOG_ERR("invalid command\n");
        return URPC_FAIL;
    }

    urpc_cmd_t *cmd = (urpc_cmd_t *)urpc_dbuf_calloc(URPC_DBUF_TYPE_CP, 1, sizeof(urpc_cmd_t));
    if (cmd == NULL) {
        UTIL_LOG_ERR("calloc command buffer failed\n");
        return URPC_FAIL;
    }
    cmd->process = process;
    cmd->exception = exception;
    cmd->args = args;

    (void)pthread_spin_lock(&cmd_queue->lock);
    STAILQ_INSERT_TAIL(&cmd_queue->head, cmd, node);
    cmd_queue->count++;
    (void)pthread_spin_unlock(&cmd_queue->lock);

    return URPC_SUCCESS;
}

urpc_cmd_t *urpc_cmd_queue_pop(urpc_cmd_queue_t *cmd_queue)
{
    urpc_cmd_t *cmd = NULL;
    (void)pthread_spin_lock(&cmd_queue->lock);
    if (STAILQ_EMPTY(&cmd_queue->head)) {
        (void)pthread_spin_unlock(&cmd_queue->lock);
        return cmd;
    }

    cmd = STAILQ_FIRST(&cmd_queue->head);
    STAILQ_REMOVE_HEAD(&cmd_queue->head, node);
    cmd_queue->count--;
    (void)pthread_spin_unlock(&cmd_queue->lock);

    return cmd;
}

void urpc_cmd_queue_process(urpc_cmd_queue_t *cmd_queue)
{
    urpc_cmd_t *cmd = urpc_cmd_queue_pop(cmd_queue);
    if (cmd == NULL) {
        return;
    }

    if (cmd->process != NULL) {
        cmd->process(cmd->args);
    }

    urpc_dbuf_free(cmd);
}

void urpc_cmd_queue_flush(urpc_cmd_queue_t *cmd_queue)
{
    urpc_cmd_t *cmd = NULL;
    while (!STAILQ_EMPTY(&cmd_queue->head)) {
        cmd = STAILQ_FIRST(&cmd_queue->head);
        STAILQ_REMOVE_HEAD(&cmd_queue->head, node);
        cmd_queue->count--;

        if (cmd->exception != NULL) {
            cmd->exception(cmd->args);
        }

        urpc_dbuf_free(cmd);
    }
    (void)pthread_spin_destroy(&cmd_queue->lock);
}