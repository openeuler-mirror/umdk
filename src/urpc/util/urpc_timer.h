/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2024-2024. All rights reserved.
 * Description: urpc timing wheel
 * Create: 2024-11-07
 */

#ifndef URPC_TIMER_H
#define URPC_TIMER_H

#include "urpc_list.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef enum urpc_timer_status {
    URPC_TIMER_STAT_INVALID,
    URPC_TIMER_STAT_INITED,
    URPC_TIMER_STAT_PENDING,
    URPC_TIMER_STAT_RUNNING,
    URPC_TIMER_STAT_FINISH,
} urpc_timer_status_t;

typedef enum urpc_timer_stats_type {
    TIMER_ENTRY_TOTAL_NUM = 0,
    TIMER_ENTRY_FREE_NUM,
    TIMER_STATS_TYPE_MAX
} urpc_timer_stats_type_t;

struct urpc_timer;
typedef struct urpc_timer urpc_timer_t;

int urpc_timing_wheel_init(void);
void urpc_timing_wheel_uninit(void);

bool is_urpc_timer_running(urpc_timer_t *timer);

urpc_timer_t *urpc_timer_create(uint32_t chid, bool is_server);
int urpc_timer_start(urpc_timer_t *timer, uint32_t timeout_ms, void (*func)(void *), void *args, bool periodic);
int urpc_timer_restart(urpc_timer_t *timer);
void urpc_timer_destroy(urpc_timer_t *timer);

int urpc_timer_pool_add(uint32_t chid, uint32_t num, bool is_server);
void urpc_timer_pool_delete(uint32_t chid, bool is_server);

void urpc_query_timer_info(uint32_t chid, bool is_server, uint64_t *stats, int stats_len);

#ifdef __cplusplus
}
#endif

#endif
