/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2024-2024. All rights reserved.
 * Description: realize resource release timeout list
 * Create: 2024-9-3
 */

#include <pthread.h>

#include "channel.h"
#include "urpc_framework_errno.h"
#include "urpc_lib_log.h"
#include "urpc_util.h"
#include "urpc_timer.h"
#include "urpc_dbuf_stat.h"

#include "resource_release.h"

#define URPC_RESOURCE_RELEASE_MAX_NUM (1024U)
#define URPC_RESOURCE_RELEASE_TIMEOUT (1000)      // ms

static struct {
    urpc_timer_t *timer; // use 1 default timer
    urpc_list_t list;
    pthread_mutex_t lock;
    uint32_t task_id; // 0 is reserved
} g_urpc_resource_release_ctx = {
    .lock = PTHREAD_MUTEX_INITIALIZER,
};

static void urpc_resource_release_process(void *args);

static void urpc_resource_release_timer_start(void)
{
    g_urpc_resource_release_ctx.timer = urpc_timer_create(URPC_INVALID_ID_U32, false);
    if (URPC_UNLIKELY(g_urpc_resource_release_ctx.timer == NULL)) {
        URPC_LIB_LOG_ERR("resource release timer create failed\n");
        return;
    }

    int ret = urpc_timer_start(
        g_urpc_resource_release_ctx.timer, URPC_RESOURCE_RELEASE_TIMEOUT, urpc_resource_release_process, NULL, true);
    if (ret != URPC_SUCCESS) {
        urpc_timer_destroy(g_urpc_resource_release_ctx.timer);
        g_urpc_resource_release_ctx.timer = NULL;
        URPC_LIB_LOG_ERR("resource release timer start failed\n");
        return;
    }

    URPC_LIB_LOG_DEBUG("resource release timer create success\n");
}

static void urpc_resource_release_entry_insert(urpc_resource_release_entry_t *entry)
{
    urpc_resource_release_entry_t *cur = NULL;
    // find correct location to insert
    URPC_LIST_FOR_EACH(cur, node, &g_urpc_resource_release_ctx.list) {
        if (cur->timestamp > entry->timestamp) {
            break;
        }
    }

    if (cur != NULL) {
        urpc_list_insert_before(&cur->node, &entry->node);
    } else {
        // cur is head or entry, never goes into this branch
        urpc_list_push_front(&g_urpc_resource_release_ctx.list, &entry->node);
    }
}

static inline uint32_t urpc_resource_release_id(void)
{
    g_urpc_resource_release_ctx.task_id++;
    if (g_urpc_resource_release_ctx.task_id == 0) {
        g_urpc_resource_release_ctx.task_id++;
    }

    return g_urpc_resource_release_ctx.task_id;
}

// timestamp is entry timeout in seconds from now on
int urpc_resource_release_entry_add(release_callback_t cb, void *args, uint32_t timeout, uint32_t *id)
{
    if (cb == NULL || timeout == 0) {
        URPC_LIB_LOG_ERR("invalid param\n");
        return -1;
    }

    urpc_resource_release_entry_t *entry = (urpc_resource_release_entry_t *)urpc_dbuf_malloc(URPC_DBUF_TYPE_CP,
        sizeof(urpc_resource_release_entry_t));
    if (entry == NULL) {
        URPC_LIB_LOG_ERR("malloc resource release entry failed, errno %d\n", errno);
        return -1;
    }

    entry->cb = cb;
    entry->args = args;
    entry->timeout = timeout;
    entry->timestamp = get_timestamp() + timeout;

    entry->task_id = urpc_resource_release_id();
    *id = entry->task_id;
    urpc_resource_release_entry_insert(entry);
    if (g_urpc_resource_release_ctx.timer == NULL) {
        urpc_resource_release_timer_start();
    }

    URPC_LIB_LOG_DEBUG("resource release entry add success\n");

    return 0;
}

bool urpc_resource_release_entry_delete(uint32_t id)
{
    bool find = false;
    urpc_resource_release_entry_t *cur = NULL;
    urpc_resource_release_entry_t *next = NULL;

    URPC_LIST_FOR_EACH_SAFE(cur, next, node, &g_urpc_resource_release_ctx.list) {
        if (cur->task_id == id) {
            find = true;
            urpc_list_remove(&cur->node);
            urpc_dbuf_free(cur->args);
            urpc_dbuf_free(cur);
            URPC_LIB_LOG_DEBUG("resource release entry delete success\n");
            break;
        }
    }

    return find;
}

// clear before all modules uninit to make sure cb can be executed safely
void urpc_resource_release_clear(void)
{
    urpc_resource_release_entry_t *cur = NULL;
    urpc_resource_release_entry_t *next = NULL;

    URPC_LIB_LOG_DEBUG("forced to clear resource release entry\n");
    (void)pthread_mutex_lock(&g_urpc_resource_release_ctx.lock);
    URPC_LIST_FOR_EACH_SAFE(cur, next, node, &g_urpc_resource_release_ctx.list) {
        urpc_list_remove(&cur->node);
        cur->cb(cur->args, true);
        urpc_dbuf_free(cur);
    }

    if (g_urpc_resource_release_ctx.timer != NULL) {
        urpc_timer_destroy(g_urpc_resource_release_ctx.timer);
        g_urpc_resource_release_ctx.timer = NULL;
    }

    (void)pthread_mutex_unlock(&g_urpc_resource_release_ctx.lock);
}

// timeout callback is protected by g_urpc_resource_release_ctx.lock
static void urpc_resource_release_process(void *args __attribute__((unused)))
{
    uint32_t cnt = 0;
    uint32_t now = get_timestamp();
    int ret;
    urpc_list_t head;
    urpc_list_init(&head);

    urpc_resource_release_entry_t *cur = NULL;
    urpc_resource_release_entry_t *next = NULL;

    (void)pthread_mutex_lock(&g_urpc_resource_release_ctx.lock);
    URPC_LIST_FOR_EACH_SAFE(cur, next, node, &g_urpc_resource_release_ctx.list) {
        if (cur->timestamp > now) {
            break;
        }

        if (cnt++ > URPC_RESOURCE_RELEASE_MAX_NUM) {
            URPC_LIB_LOG_WARN("urpc resource release entry exceed %u at a time\n", URPC_RESOURCE_RELEASE_MAX_NUM);
            break;
        }

        urpc_list_remove(&cur->node);
        ret = cur->cb(cur->args, false);
        if (ret == URPC_RESOURCE_RELEASE_AGAIN) {
            // update timeout timestamp
            cur->timestamp = cur->timeout + now;
            urpc_list_push_front(&head, &cur->node);
        } else {
            urpc_dbuf_free(cur);
        }

        URPC_LIB_LOG_DEBUG("resource release entry process success\n");
    }

    // move eagain list to global
    if (!urpc_list_is_empty(&head)) {
        URPC_LIST_FOR_EACH_SAFE(cur, next, node, &head) {
            urpc_list_remove(&cur->node);
            urpc_resource_release_entry_insert(cur);
        }
    }

    // only restart timer if resource list is not empty
    if (urpc_list_is_empty(&g_urpc_resource_release_ctx.list)) {
        if (g_urpc_resource_release_ctx.timer != NULL) {
            urpc_timer_destroy(g_urpc_resource_release_ctx.timer);
            g_urpc_resource_release_ctx.timer = NULL;
        }

        URPC_LIB_LOG_DEBUG("resource release entry is empty now\n");
    }

    (void)pthread_mutex_unlock(&g_urpc_resource_release_ctx.lock);
}

int urpc_resource_release_init(void)
{
    urpc_list_init(&g_urpc_resource_release_ctx.list);
    return 0;
}

void urpc_resource_release_uninit(void)
{}

// Ensure the locking order. Acquire the "release_ctx_lock" lock first,
// then acquiring the "g_urpc_server_manage_channel_ctx.lock".
void urpc_resource_release_ctx_lock(void)
{
    (void)pthread_mutex_lock(&g_urpc_resource_release_ctx.lock);
}

void urpc_resource_release_ctx_unlock(void)
{
    (void)pthread_mutex_unlock(&g_urpc_resource_release_ctx.lock);
}