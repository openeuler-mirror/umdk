/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2024-2024. All rights reserved.
 * Description: state machine for uRPC
 * Create: 2024-04-03
 */

#ifndef STATE_H
#define STATE_H

#include "urpc_framework_types.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef enum urpc_state {
    URPC_STATE_UNINIT,          // default state, this level means urpc is not initialized
    URPC_STATE_INIT,            // urpc is initialized
} urpc_state_t;

typedef struct state_callback {
    int (*service_start_callback)(void);
    void (*service_end_callback)(void);
} state_callback_t;

int urpc_state_set_callback(state_callback_t *cb);
int urpc_state_update(urpc_state_t state);
urpc_state_t urpc_state_get(void);

/* For UT */
void urpc_state_set(urpc_state_t state);

#ifdef __cplusplus
}
#endif

#endif