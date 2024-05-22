/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2024-2024. All rights reserved.
 * Description: set and execute uvs event cb
 * Author: Liwenhao
 * Create: 2024-2-20
 * Note:
 * History:
 */
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include "tpsa_log.h"
#include "uvs_event.h"

struct uvs_event_cb_entry {
    bool is_valid;
    uvs_event_cb_t cb_func;
    void *cb_arg;
};

struct uvs_event_cb_entry g_event_cb_entry;

int uvs_event_set_cb(uvs_event_cb_t cb_func, void *cb_arg)
{
    /* When all input parameters are NULL, unregister event cb */
    if (cb_func == NULL && cb_arg == NULL) {
        TPSA_LOG_INFO("unregister event cb.\n");
        g_event_cb_entry.cb_func = cb_func;
        g_event_cb_entry.cb_arg = cb_arg;
        g_event_cb_entry.is_valid = false;
        return 0;
    }

    if (g_event_cb_entry.is_valid) {
        TPSA_LOG_ERR("The event cb is already registered.\n");
        return -1;
    }

    g_event_cb_entry.cb_func = cb_func;
    g_event_cb_entry.cb_arg = cb_arg;
    g_event_cb_entry.is_valid = true;
    return 0;
}

int uvs_event_execute_cb(struct uvs_event *event)
{
    if (event == NULL || event->type >= UVS_EVENT_MAX) {
        TPSA_LOG_ERR("Invalid argument.\n");
        return -1;
    }

    if (!g_event_cb_entry.is_valid) {
        TPSA_LOG_WARN("Invalid event cb entry.\n");
        return -1;
    }

    g_event_cb_entry.cb_func(event, g_event_cb_entry.cb_arg);
    return 0;
}