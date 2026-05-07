/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2025-2025. All rights reserved.
 * Description: realize task manager function
 */

#include <stdatomic.h>

#include "async_event.h"
#include "channel.h"
#include "transport.h"
#include "urpc_hash.h"
#include "urpc_lib_log.h"
#include "urpc_manage.h"
#include "urpc_util.h"

#include "task_manager.h"

#define MAX_TASK_COUNT 8192
#define TIMEOUT_CHECK_CYCLE_MS 1

static urpc_task_table_t g_urpc_client_task_hamp = {.running_cnt = ATOMIC_VAR_INIT(0)};
static urpc_task_table_t g_urpc_server_task_hamp = {.running_cnt = ATOMIC_VAR_INIT(0)};
static urpc_task_activation_manager_t g_urpc_task_activation_manager;
static urpc_task_timeout_manager_t g_urpc_task_timeout_manager;
static int g_urpc_task_manager_id = 0;

// in g_urpc_task_timeout_manager.lock
static inline int task_manager_id_alloc(void)
{
    if (g_urpc_task_manager_id == INT_MAX) {
        g_urpc_task_manager_id = 0;
    }

    return ++g_urpc_task_manager_id;
}

static void task_on_activing(uint32_t events, urpc_epoll_event_t *lev);
static void task_manager_timeout_check(void *args);

void task_manager_timeout_manager_remove(urpc_async_task_ctx_t *entry)
{
    if (!g_urpc_task_timeout_manager.is_outer_lock) {
        (void)pthread_mutex_lock(&g_urpc_task_timeout_manager.lock);
    }
    urpc_list_remove(&entry->node);
    g_urpc_task_timeout_manager.total_cnt--;
    if (!g_urpc_task_timeout_manager.is_outer_lock) {
        (void)pthread_mutex_unlock(&g_urpc_task_timeout_manager.lock);
    }
    if (entry->ref_cnt > 0) {
        entry->ref_cnt--;
    }
}

urpc_async_task_ctx_t *task_manager_server_task_get(task_instance_key_t *key)
{
    uint32_t hash = urpc_hash_bytes(key, sizeof(task_instance_key_t), 0);
    urpc_async_task_ctx_t *entry = NULL;
    URPC_HMAP_FOR_EACH_WITH_HASH(entry, task_hash_node, hash, &g_urpc_server_task_hamp.hmap) {
        if (memcmp(key, &entry->key, sizeof(task_instance_key_t)) == 0) {
            return entry;
        }
    }
    return NULL;
}

urpc_async_task_ctx_t *task_manager_client_task_get(int task_id)
{
    task_instance_key_t key = {.task_id = task_id};
    uint32_t hash = urpc_hash_bytes(&key, sizeof(task_instance_key_t), 0);
    urpc_async_task_ctx_t *entry = NULL;
    URPC_HMAP_FOR_EACH_WITH_HASH(entry, task_hash_node, hash, &g_urpc_client_task_hamp.hmap) {
        if (entry->key.task_id == task_id) {
            return entry;
        }
    }
    return NULL;
}

void task_manager_server_task_insert(urpc_async_task_ctx_t *entry)
{
    // a task is created, there is no multithreaded operation on the task's reference count.
    entry->ref_cnt++;
    uint32_t hash = urpc_hash_bytes(&entry->key, sizeof(task_instance_key_t), 0);
    // server single-threaded processing, and does not require locking
    urpc_hmap_insert(&g_urpc_server_task_hamp.hmap, &entry->task_hash_node, hash);
}

void task_manager_client_task_insert(urpc_async_task_ctx_t *entry)
{
    // a task is created, there is no multithreaded operation on the task's reference count.
    entry->ref_cnt++;
    task_instance_key_t key = {.task_id = entry->key.task_id};
    uint32_t hash = urpc_hash_bytes(&key, sizeof(task_instance_key_t), 0);
    (void)pthread_rwlock_wrlock(&g_urpc_client_task_hamp.rw_lock);
    urpc_hmap_insert(&g_urpc_client_task_hamp.hmap, &entry->task_hash_node, hash);
    (void)pthread_rwlock_unlock(&g_urpc_client_task_hamp.rw_lock);
}

void task_manager_client_task_remove(urpc_async_task_ctx_t *entry)
{
    (void)pthread_rwlock_wrlock(&g_urpc_client_task_hamp.rw_lock);
    urpc_hmap_remove(&g_urpc_client_task_hamp.hmap, &entry->task_hash_node);
    (void)pthread_rwlock_unlock(&g_urpc_client_task_hamp.rw_lock);
    if (entry->ref_cnt > 0) {
        entry->ref_cnt--;
    }
}

void task_manager_server_task_remove(urpc_async_task_ctx_t *entry)
{
    // server single-threaded processing, and does not require locking
    if (entry->ref_cnt > 0) {
        entry->ref_cnt--;
    }
    urpc_hmap_remove(&g_urpc_server_task_hamp.hmap, &entry->task_hash_node);
}

void task_manager_running_task_activate(void)
{
    urpc_async_task_ctx_t *task_entry = NULL;
    uint64_t count = 0;
    int activate_task_fd = async_event_activation_fd_get();
    if (eventfd_read(activate_task_fd, &count) == -1) {
        URPC_LIB_LOG_WARN("read activate_task_fd failed, err:%s\n", strerror(errno));
    }

    while (count != 0 && !urpc_list_is_empty(&g_urpc_task_activation_manager.list)) {
        (void)pthread_mutex_lock(&g_urpc_task_activation_manager.lock);
        urpc_list_t *node_ptr = urpc_list_pop_front(&g_urpc_task_activation_manager.list);
        (void)pthread_mutex_unlock(&g_urpc_task_activation_manager.lock);
        ASSIGN_CONTAINER_PTR(task_entry, node_ptr, flow_node);
        task_entry->list_type = TASK_LIST_TYPE_UNKNOWN;
        if (task_entry->ref_cnt > 0) {
            task_entry->ref_cnt--;
        }
        task_engine_task_process(false, NULL, NULL, task_entry);
        count--;
    }
}

void task_manager_activation_manager_insert(urpc_async_task_ctx_t *task_entry)
{
    // after insert task to g_urpc_task_running_manager, write activate_task_fd
    uint64_t value = 1;
    (void)pthread_mutex_lock(&g_urpc_task_activation_manager.lock);
    atomic_fetch_add(&g_urpc_client_task_hamp.running_cnt, (uint32_t)1);
    // there is no multithreaded operation on the task's reference count.
    task_entry->ref_cnt++;
    task_entry->list_type = TASK_LIST_TYPE_ACTIVE;
    urpc_list_push_back(&g_urpc_task_activation_manager.list, &task_entry->flow_node);
    (void)pthread_mutex_unlock(&g_urpc_task_activation_manager.lock);

    if (eventfd_write(async_event_activation_fd_get(), value) == -1) {
        URPC_LIB_LOG_ERR("write event failed, err:%s\n", strerror(errno));
    }
}

void task_manager_ready_queue_insert(urpc_async_task_ctx_t *task_entry, urpc_channel_info_t *channel)
{
    // a task is created, there is no multithreaded operation on the task's reference count.
    task_entry->list_type = TASK_LIST_TYPE_READY;
    task_entry->ref_cnt++;
    // the function caller locks
    urpc_list_push_back(&channel->task_ready_list, &task_entry->flow_node);
}

urpc_async_task_ctx_t *task_manager_ready_queue_pop(urpc_channel_info_t *channel)
{
    urpc_async_task_ctx_t *task = NULL;
    urpc_list_t *node_ptr = NULL;

    (void)pthread_rwlock_wrlock(&channel->rw_lock);
    if (urpc_list_is_empty(&channel->task_ready_list)) {
        channel->stats[CHANNEL_TASK_RUNNING_NUM] = 0;
        channel->handshaking = false;
        (void)pthread_rwlock_unlock(&channel->rw_lock);
        return NULL;
    }
    channel->stats[CHANNEL_TASK_RUNNING_NUM] = 1;
    node_ptr = urpc_list_pop_front(&channel->task_ready_list);
    ASSIGN_CONTAINER_PTR(task, node_ptr, flow_node);
    task->list_type = TASK_LIST_TYPE_UNKNOWN;
    task->ref_cnt--;
    (void)pthread_rwlock_unlock(&channel->rw_lock);
    return task;
}

void task_manager_timeout_manager_insert(urpc_async_task_ctx_t *entry)
{
    if (urpc_list_is_in_list(&entry->node)) {
        return;
    }
    entry->ref_cnt++;
    if (entry->timestamp == UINT64_MAX) {
        g_urpc_task_timeout_manager.total_cnt++;
        urpc_list_push_back(&g_urpc_task_timeout_manager.list, &entry->node);
        return;
    }
    urpc_async_task_ctx_t *cur = NULL;
    // find correct location to insert
    bool is_find = false;
    URPC_LIST_FOR_EACH(cur, node, &g_urpc_task_timeout_manager.list)
    {
        if (cur->timestamp > entry->timestamp) {
            is_find = true;
            break;
        }
    }

    g_urpc_task_timeout_manager.total_cnt++;
    if (!is_find && cur != NULL) {
        urpc_list_insert_after(&cur->node, &entry->node);
        return;
    }

    if (cur != NULL) {
        urpc_list_insert_before(&cur->node, &entry->node);
    } else {
        // cur is head or entry, never goes into this branch
        urpc_list_push_front(&g_urpc_task_timeout_manager.list, &entry->node);
    }
}

int task_manager_client_task_create(urpc_channel_info_t *channel, task_init_params_t *params)
{
    urpc_async_task_ctx_t *task = NULL;
    int task_id = 0;

    (void)pthread_mutex_lock(&g_urpc_task_timeout_manager.lock);
    if (!task_manager_task_num_validate()) {
        (void)pthread_mutex_unlock(&g_urpc_task_timeout_manager.lock);
        URPC_LIB_LIMIT_LOG_ERR("the length of the linked list exceeds the maximum value:%u.\n", MAX_TASK_COUNT);
        return -URPC_ERR_EBUSY;
    }

    task_id = task_manager_id_alloc();
    // in most unlikely case, task_id is already used
    (void)pthread_rwlock_rdlock(&g_urpc_client_task_hamp.rw_lock);
    task = task_manager_client_task_get(task_id);
    (void)pthread_rwlock_unlock(&g_urpc_client_task_hamp.rw_lock);
    if (task != NULL) {
        (void)pthread_mutex_unlock(&g_urpc_task_timeout_manager.lock);
        URPC_LIB_LIMIT_LOG_ERR("async task id %d is occupied by other task\n", task_id);
        return -URPC_ERR_EBUSY;
    }
    if ((params->type == WORKFLOW_TYPE_CHANNEL_PAIR_QUEUE || params->type == WORKFLOW_TYPE_CHANNEL_UNPAIR_QUEUE)) {
        task = task_engine_bind_new(params);
    } else if (params->type == WORKFLOW_TYPE_CLIENT_ATTACH_SERVER ||
               params->type == WORKFLOW_TYPE_CLIENT_DETACH_SERVER ||
               params->type == WORKFLOW_TYPE_CLIENT_REFRESH_SERVER) {
        task = task_engine_client_handshaker_new(params);
    } else {
        task = task_engine_queue_handshaker_new(params);
    }
    if (task == NULL) {
        (void)pthread_mutex_unlock(&g_urpc_task_timeout_manager.lock);
        return -URPC_ERR_EINVAL;
    }
    if (params->tcp_addr != NULL) {
        task->tcp_addr = *(params->tcp_addr);
    }
    task->key.task_id = task_id;
    task_manager_client_task_insert(task);
    (void)pthread_rwlock_wrlock(&channel->rw_lock);
    task_manager_timeout_manager_insert(task);
    channel->stats[CHANNEL_TASK_TOTAL_NUM]++;
    if (urpc_list_is_empty(&channel->task_ready_list)) {
        if (channel->handshaking == true) {
            task_manager_ready_queue_insert(task, channel);
            (void)pthread_rwlock_unlock(&channel->rw_lock);
        } else {
            channel->stats[CHANNEL_TASK_RUNNING_NUM] = 1;
            channel->handshaking = true;
            (void)pthread_rwlock_unlock(&channel->rw_lock);
            task_manager_activation_manager_insert(task);
        }
    } else {
        task_manager_ready_queue_insert(task, channel);
        (void)pthread_rwlock_unlock(&channel->rw_lock);
    }
    (void)pthread_mutex_unlock(&g_urpc_task_timeout_manager.lock);
    // the task may have already been completed, the task ctx is free, cannot use task resource
    return task_id;
}

int task_manager_task_cancel(int task_id)
{
    (void)pthread_mutex_lock(&g_urpc_client_task_hamp.workflow_lock);
    (void)pthread_rwlock_rdlock(&g_urpc_client_task_hamp.rw_lock);
    urpc_async_task_ctx_t *task = task_manager_client_task_get(task_id);
    if (task == NULL) {
        (void)pthread_rwlock_unlock(&g_urpc_client_task_hamp.rw_lock);
        (void)pthread_mutex_unlock(&g_urpc_client_task_hamp.workflow_lock);
        return -URPC_ERR_EINVAL;
    }
    task->is_user_canceled = URPC_TRUE;
    (void)pthread_rwlock_unlock(&g_urpc_client_task_hamp.rw_lock);
    (void)pthread_mutex_unlock(&g_urpc_client_task_hamp.workflow_lock);
    return URPC_SUCCESS;
}

static int server_task_table_init(void)
{
    if (urpc_hmap_init(&g_urpc_server_task_hamp.hmap, MAX_TASK_COUNT) != URPC_SUCCESS) {
        URPC_LIB_LOG_ERR("init server task table failed\n");
        return URPC_FAIL;
    }
    (void)pthread_rwlock_init(&g_urpc_server_task_hamp.rw_lock, NULL);
    return URPC_SUCCESS;
}

static void server_task_table_uninit(void)
{
    urpc_async_task_ctx_t *cur, *next;
    URPC_HMAP_FOR_EACH_SAFE(cur, next, task_hash_node, &g_urpc_server_task_hamp.hmap) {
        task_manager_server_task_remove(cur);
    }
    urpc_hmap_uninit(&g_urpc_server_task_hamp.hmap);
    (void)pthread_rwlock_destroy(&g_urpc_server_task_hamp.rw_lock);
}

static int client_task_table_init(void)
{
    if (urpc_hmap_init(&g_urpc_client_task_hamp.hmap, MAX_TASK_COUNT) != URPC_SUCCESS) {
        URPC_LIB_LOG_ERR("init client task table failed\n");
        return URPC_FAIL;
    }

    (void)pthread_rwlock_init(&g_urpc_client_task_hamp.rw_lock, NULL);
    (void)pthread_mutex_init(&g_urpc_client_task_hamp.workflow_lock, NULL);
    return URPC_SUCCESS;
}

static void client_task_table_uninit(void)
{
    urpc_async_task_ctx_t *cur, *next;
    URPC_HMAP_FOR_EACH_SAFE(cur, next, task_hash_node, &g_urpc_client_task_hamp.hmap)
    {
        task_manager_client_task_remove(cur);
    }
    urpc_hmap_uninit(&g_urpc_client_task_hamp.hmap);
    (void)pthread_rwlock_destroy(&g_urpc_client_task_hamp.rw_lock);
    (void)pthread_mutex_destroy(&g_urpc_client_task_hamp.workflow_lock);
}

static int task_activation_manager_init(void)
{
    urpc_list_init(&g_urpc_task_activation_manager.list);
    (void)pthread_mutex_init(&g_urpc_task_activation_manager.lock, NULL);
    return URPC_SUCCESS;
}

static void task_activation_manager_uninit(void)
{
    urpc_async_task_ctx_t *cur, *next;
    // called after the thread is destroyed, not ready, user interface cannot be inserted.
    URPC_LIST_FOR_EACH_SAFE(cur, next, flow_node, &g_urpc_task_activation_manager.list)
    {
        urpc_list_remove(&cur->flow_node);
        cur->list_type = TASK_LIST_TYPE_UNKNOWN;
        cur->ref_cnt--;
    }
    pthread_mutex_destroy(&g_urpc_task_activation_manager.lock);
}

static int task_timeout_manager_init(void)
{
    urpc_list_init(&g_urpc_task_timeout_manager.list);
    (void)pthread_mutex_init(&g_urpc_task_timeout_manager.lock, NULL);
    urpc_manage_job_register(URPC_MANAGE_JOB_TYPE_LISTEN, task_manager_timeout_check, NULL, TIMEOUT_CHECK_CYCLE_MS);
    return URPC_SUCCESS;
}

static void task_timeout_manager_uninit(void)
{
    urpc_async_task_ctx_t *cur, *next;
    // called after the thread is destroyed, not ready, user interface cannot be inserted.
    URPC_LIST_FOR_EACH_SAFE(cur, next, node, &g_urpc_task_timeout_manager.list)
    {
        cur->result = URPC_ERR_FORCE_EXIT;
        cur->is_notify = URPC_FALSE;
        task_engine_task_process(false, NULL, NULL, cur);
    }
    pthread_mutex_destroy(&g_urpc_task_timeout_manager.lock);
}

int task_manager_init(void)
{
    if (server_task_table_init() != URPC_SUCCESS) {
        return URPC_FAIL;
    }

    if (client_task_table_init() != URPC_SUCCESS) {
        goto SERVER_TASK_TABLE_UNINIT;
    }

    if (task_activation_manager_init() != URPC_SUCCESS) {
        goto CLIENT_TASK_TABLE_UNINIT;
    }

    if (task_timeout_manager_init() != URPC_SUCCESS) {
        goto ACTIVATION_MANAGER_UNINIT;
    }

    // register activate task event
    urpc_epoll_event_t *event = async_event_activation_event_get();
    event->fd = async_event_activation_fd_get();
    event->args = NULL;
    event->func = task_on_activing;
    event->events = EPOLLIN;
    if (urpc_epoll_event_add(urpc_manage_get_epoll_fd(URPC_MANAGE_JOB_TYPE_LISTEN), event) != URPC_SUCCESS) {
        goto TIMEOUT_MANAGER_UNINIT;
    }
    return URPC_SUCCESS;

TIMEOUT_MANAGER_UNINIT:
    task_timeout_manager_uninit();

ACTIVATION_MANAGER_UNINIT:
    task_activation_manager_uninit();

CLIENT_TASK_TABLE_UNINIT:
    client_task_table_uninit();

SERVER_TASK_TABLE_UNINIT:
    server_task_table_uninit();
    return URPC_FAIL;
}

void task_manager_uninit(void)
{
    urpc_epoll_event_t *event = async_event_activation_event_get();
    urpc_epoll_event_delete(urpc_manage_get_epoll_fd(URPC_MANAGE_JOB_TYPE_LISTEN), event);
    task_activation_manager_uninit();
    // timeout uninit must be placed before the hash table uninit
    task_timeout_manager_uninit();
    server_task_table_uninit();
    client_task_table_uninit();
}

static void task_on_activing(uint32_t events, urpc_epoll_event_t *lev)
{
    task_manager_running_task_activate();
}

static void task_manager_timeout_check(void *args)
{
    uint64_t timestamp = get_timestamp_ms();
    urpc_async_task_ctx_t *cur = NULL;
    urpc_async_task_ctx_t *next = NULL;
    g_urpc_task_timeout_manager.is_outer_lock = true;
    (void)pthread_mutex_lock(&g_urpc_task_timeout_manager.lock);
    URPC_LIST_FOR_EACH_SAFE(cur, next, node, &g_urpc_task_timeout_manager.list)
    {
        if (timestamp <= cur->timestamp) {
            break;
        }
        URPC_LIB_LOG_DEBUG("check task timeout, %s task id:%d, timeout timestamp:%llu, timeout:%d\n",
            cur->is_server ? "server" : "client", cur->key.task_id, cur->timestamp, cur->timeout);
        // resource clean up
        if (cur->workflow_type == WORKFLOW_TYPE_RELEASE_RESOURCE) {
            task_engine_task_process(false, NULL, NULL, cur);
        } else if (cur->workflow_type == WORKFLOW_TYPE_CONNECT_TIMER) {
            transport_connect_timer_destroy(cur);
            transport_acception_shutdown((urpc_server_accept_entry_t *)cur->transport_handle, true, false);
        } else {
            cur->result = URPC_ERR_TIMEOUT;
            if (task_can_stop_immediately(cur)) {
                task_engine_task_process(false, NULL, NULL, cur);
            }
        }
    }
    (void)pthread_mutex_unlock(&g_urpc_task_timeout_manager.lock);
    g_urpc_task_timeout_manager.is_outer_lock = false;
}

void task_manager_summary_info_get(system_task_statistics_t *info)
{
    (void)pthread_rwlock_rdlock(&g_urpc_client_task_hamp.rw_lock);
    info->client.running_tasks = atomic_load(&g_urpc_client_task_hamp.running_cnt);
    info->client.total_tasks = urpc_hmap_count(&g_urpc_client_task_hamp.hmap);
    (void)pthread_rwlock_unlock(&g_urpc_client_task_hamp.rw_lock);
    info->server.running_tasks = urpc_hmap_count(&g_urpc_server_task_hamp.hmap);
    info->server.total_tasks = info->server.running_tasks;
}

int task_manager_task_info_get(uint32_t channel_id, uint32_t task_id, char **output, uint32_t *output_size)
{
    (void)pthread_rwlock_rdlock(&g_urpc_client_task_hamp.rw_lock);
    urpc_async_task_ctx_t *task = task_manager_client_task_get(task_id);
    if (task == NULL) {
        (void)pthread_rwlock_unlock(&g_urpc_client_task_hamp.rw_lock);
        return -URPC_ERR_EEXIST;
    }
    task_query_info_t *task_info =
        (task_query_info_t *)urpc_dbuf_calloc(URPC_DBUF_TYPE_DFX, 1, sizeof(task_query_info_t));
    if (task_info == NULL) {
        (void)pthread_rwlock_unlock(&g_urpc_client_task_hamp.rw_lock);
        URPC_LIB_LOG_ERR("failed to malloc, errno: %d\n", errno);
        return -URPC_ERR_ENOMEM;
    }
    task_info->task_id = task->key.task_id;
    task_info->state = task->task_state;
    task_info->step = task->outer_step;
    task_info->channel_id = task->channel_id;
    task_info->workflow_type = task->workflow_type;
    (void)pthread_rwlock_unlock(&g_urpc_client_task_hamp.rw_lock);
    *output = (char *)task_info;
    *output_size = (uint32_t)sizeof(task_query_info_t);
    return URPC_SUCCESS;
}

static void task_completed_stats_update(uint32_t urpc_chid, int result)
{
    urpc_channel_info_t *channel = channel_get(urpc_chid);
    if (channel == NULL) {
        URPC_LIB_LOG_ERR("failed to get channel[%u]\n", urpc_chid);
        return;
    }
    (void)pthread_rwlock_wrlock(&channel->rw_lock);
    if (result != URPC_SUCCESS) {
        channel->stats[CHANNEL_TASK_FAILED_NUM]++;
    } else {
        channel->stats[CHANNEL_TASK_SUCCEEDED_NUM]++;
    }
    (void)pthread_rwlock_unlock(&channel->rw_lock);
}

static void next_task_activate(uint32_t channel_id)
{
    urpc_channel_info_t *channel = channel_get(channel_id);
    if (channel == NULL) {
        URPC_LIB_LOG_ERR("get channel failed\n");
        return;
    }
    urpc_async_task_ctx_t *task = task_manager_ready_queue_pop(channel);
    if (task != NULL) {
        task_manager_activation_manager_insert(task);
    }
}

void task_manager_client_task_clear(urpc_async_task_ctx_t *task)
{
    bool is_runnning = true;
    if (task->list_type == TASK_LIST_TYPE_READY) {
        // task is not in the channel cache queue
        is_runnning = false;
    }
    transport_client_task_unregister(task, (urpc_client_connect_entry_t *)task->transport_handle);
    task_manager_client_task_remove(task);
    task_manager_timeout_manager_remove(task);
    task_completed_stats_update(task->channel_id, task->result);
    if (is_runnning) {
        atomic_fetch_sub(&g_urpc_client_task_hamp.running_cnt, (uint32_t)1);
        next_task_activate(task->channel_id);
    }
    // next_task_activate update channel->handshaking to false, then report user event
    if (task->func != NULL) {
        task->func(task->ctx, task->result);
    }
}

void task_manager_timeout_manager_lock(void)
{
    (void)pthread_mutex_lock(&g_urpc_task_timeout_manager.lock);
}

void task_manager_timeout_manager_unlock(void)
{
    (void)pthread_mutex_unlock(&g_urpc_task_timeout_manager.lock);
}

void task_manager_workflow_lock(void)
{
    (void)pthread_mutex_lock(&g_urpc_client_task_hamp.workflow_lock);
}

void task_manager_workflow_unlock(void)
{
    (void)pthread_mutex_unlock(&g_urpc_client_task_hamp.workflow_lock);
}

bool task_manager_task_num_validate(void)
{
    return g_urpc_task_timeout_manager.total_cnt < MAX_TASK_COUNT;
}