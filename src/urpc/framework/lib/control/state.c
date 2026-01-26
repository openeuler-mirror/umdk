/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2024-2024. All rights reserved.
 * Description: state machine for uRPC
 * Create: 2024-04-03
 */

#include "state.h"
#include "pthread.h"
#include "urpc_framework_errno.h"

typedef struct state_ctx {
    volatile urpc_state_t state;
    state_callback_t cb;
    pthread_mutex_t lock;
} state_ctx_t;

static state_ctx_t g_urpc_state_ctx = {
    .lock = PTHREAD_MUTEX_INITIALIZER,
};

int urpc_state_set_callback(state_callback_t *cb)
{
    if (g_urpc_state_ctx.state != URPC_STATE_UNINIT) {
        return -URPC_ERR_EPERM;
    }

    g_urpc_state_ctx.cb = *cb;

    return URPC_SUCCESS;
}

int urpc_state_update(urpc_state_t state)
{
    (void)pthread_mutex_lock(&g_urpc_state_ctx.lock);
    urpc_state_t cur_state = g_urpc_state_ctx.state;
    /* The urpc state changes from ready to init, and the service is ready to stop.
     * In order to prevent the conflicts between control path and data path, call service_end_callback. */
    if (cur_state == URPC_STATE_INIT && state < URPC_STATE_INIT &&
        g_urpc_state_ctx.cb.service_end_callback != NULL) {
        g_urpc_state_ctx.cb.service_end_callback();
    }

    /* The urpc state changes from init to ready, and the service is ready to start.
     * In order to prevent the conflicts between control path and data path, call service_start_callback. */
    int ret = URPC_SUCCESS;
    if (state == URPC_STATE_INIT && cur_state < URPC_STATE_INIT &&
        g_urpc_state_ctx.cb.service_start_callback != NULL) {
        // In R2C mode, state should be set to ready before thread pre_job create queues in service_start_callback()
        g_urpc_state_ctx.state = state;
        ret = g_urpc_state_ctx.cb.service_start_callback();
    }

    // when dp_start failed, rollback ctx.state to origin cur_state
    g_urpc_state_ctx.state = (ret == URPC_SUCCESS) ? state : cur_state;
    (void)pthread_mutex_unlock(&g_urpc_state_ctx.lock);

    return ret;
}

urpc_state_t urpc_state_get(void)
{
    return g_urpc_state_ctx.state;
}

/* For UT */
void urpc_state_set(urpc_state_t state)
{
    g_urpc_state_ctx.state = state;
}
