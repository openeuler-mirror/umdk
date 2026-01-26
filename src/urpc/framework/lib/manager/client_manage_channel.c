/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2024-2024. All rights reserved.
 * Description: realize client manage channel id maintainer, one client to one server maintains one manage channel
 * Create: 2024-8-28
 */

#include "channel.h"
#include "cp.h"
#include "keepalive.h"
#include "resource_release.h"
#include "urpc_framework_api.h"
#include "urpc_hash.h"
#include "urpc_hmap.h"
#include "urpc_lib_log.h"
#include "urpc_dbuf_stat.h"

#include "client_manage_channel.h"

#define CLIENT_MANAGE_CHANNEL_SIZE (1 << 13)

// only after all client channel to this server detached, entry can be deleted
typedef struct client_manage_channel_entry {
    struct urpc_hmap_node node;
    urpc_host_info_inner_t server;
    uint32_t channel_id;
    uint32_t ref_cnt;
    uint32_t delayed_task_id; // 0 is reserved as initial value
} client_manage_channel_entry_t;

static struct client_manage_channel_ctx {
    pthread_mutex_t lock;
    struct urpc_hmap hmap;  // key: urpc_host_info_inner_t, value: client_manage_channel_entry_t
} g_urpc_client_manage_channel_ctx = {
    .lock = PTHREAD_MUTEX_INITIALIZER,
};

typedef struct client_manage_channel_release_args {
    urpc_host_info_t server;
    uint32_t manage_chid;
    bool  is_async;
} client_manage_channel_release_args_t;

static int client_manage_channel_delayed_release_callback(void *args, bool force)
{
    client_manage_channel_release_args_t *arg = (client_manage_channel_release_args_t *)args;
    if (arg == NULL) {
        return URPC_RESOURCE_RELEASE_DONE;
    }

    URPC_LIB_LOG_DEBUG("client manage channel[%u] delayed release\n", arg->manage_chid);

    (void)client_manage_channel_put(&arg->server, arg->manage_chid, false, arg->is_async);
    urpc_dbuf_free(arg);

    return URPC_RESOURCE_RELEASE_DONE;
}

static int client_manage_channel_delayed_release(
    urpc_host_info_t *server, uint32_t manage_chid, uint32_t *task_id, bool is_async)
{
    client_manage_channel_release_args_t *args = (client_manage_channel_release_args_t *)
        urpc_dbuf_malloc(URPC_DBUF_TYPE_CP, sizeof(client_manage_channel_release_args_t));
    if (args == NULL) {
        URPC_LIB_LOG_ERR("malloc channel delayed release args failed\n");
        return -1;
    }

    args->server = *server;
    args->manage_chid = manage_chid;
    args->is_async = is_async;
    int ret = urpc_resource_release_entry_add(
        client_manage_channel_delayed_release_callback, args, urpc_keepalive_release_time_get(), task_id);
    if (ret != 0) {
        urpc_dbuf_free(args);
        URPC_LIB_LOG_ERR("add resource release entry failed, manage chid[%u], task id[%u]\n", manage_chid, *task_id);
        return -1;
    }

    return 0;
}

int client_manage_channel_init(void)
{
    if (!is_feature_enable(URPC_MANAGE_FEATURE_FLAG)) {
        return 0;
    }

    if (urpc_hmap_init(&g_urpc_client_manage_channel_ctx.hmap, CLIENT_MANAGE_CHANNEL_SIZE) != URPC_SUCCESS) {
        URPC_LIB_LOG_ERR("client manage_channel_ctx init failed\n");
        return -1;
    }

    return 0;
}

void client_manage_channel_uninit(void)
{
    if (!is_feature_enable(URPC_MANAGE_FEATURE_FLAG)) {
        return;
    }

    if (g_urpc_client_manage_channel_ctx.hmap.count == 0) {
        urpc_hmap_uninit(&g_urpc_client_manage_channel_ctx.hmap);
        return;
    }

    client_manage_channel_entry_t *cur, *next;
    URPC_HMAP_FOR_EACH_SAFE(cur, next, node, &g_urpc_client_manage_channel_ctx.hmap) {
        urpc_hmap_remove(&g_urpc_client_manage_channel_ctx.hmap, &cur->node);
        urpc_dbuf_free(cur);
    }

    urpc_hmap_uninit(&g_urpc_client_manage_channel_ctx.hmap);
}

static client_manage_channel_entry_t *client_manage_channel_id_lookup_inner(urpc_host_info_t *server)
{
    urpc_host_info_inner_t server_inner = {0};
    urpc_server_info_convert(server, &server_inner);
    uint32_t hash = urpc_hash_bytes(&server_inner, sizeof(urpc_host_info_inner_t), 0);
    client_manage_channel_entry_t *entry = NULL;

    URPC_HMAP_FOR_EACH_WITH_HASH(entry, node, hash, &g_urpc_client_manage_channel_ctx.hmap) {
        if (memcmp(&server_inner, &entry->server, sizeof(urpc_host_info_inner_t)) == 0) {
            return entry;
        }
    }

    return NULL;
}

static uint32_t client_manage_channel_id_get(urpc_host_info_t *server)
{
    uint32_t channel_id = URPC_INVALID_ID_U32;
    client_manage_channel_entry_t *entry = NULL;

    entry = client_manage_channel_id_lookup_inner(server);
    if (entry != NULL) {
        channel_id = entry->channel_id;
        entry->ref_cnt++;
    }

    return channel_id;
}

static uint32_t client_manage_channel_id_put(urpc_host_info_t *server)
{
    uint32_t ref_cnt = 0;
    client_manage_channel_entry_t *entry = NULL;

    entry = client_manage_channel_id_lookup_inner(server);
    if (entry != NULL && entry->ref_cnt > 0) {
        entry->ref_cnt--;
        ref_cnt = entry->ref_cnt;

        if (ref_cnt == 0) {
            urpc_hmap_remove(&g_urpc_client_manage_channel_ctx.hmap, &entry->node);
            URPC_LIB_LOG_DEBUG("free client manage channel entry, manage chid[%u]\n", entry->channel_id);
            urpc_dbuf_free(entry);
        }
    }

    return ref_cnt;
}

server_node_t *manage_channel_get_server_node(urpc_channel_info_t *channel)
{
    server_node_t *cur_server_node = NULL;
    URPC_LIST_FOR_EACH(cur_server_node, node, &channel->server_nodes_list) {
        return cur_server_node;
    }

    return NULL;
}

uint32_t client_manage_channel_ref_get(urpc_host_info_t *server)
{
    uint32_t ref_cnt = 0;
    (void)pthread_mutex_lock(&g_urpc_client_manage_channel_ctx.lock);
    client_manage_channel_entry_t *entry = client_manage_channel_id_lookup_inner(server);
    if (entry != NULL) {
        ref_cnt = entry->ref_cnt;
    }
    (void)pthread_mutex_unlock(&g_urpc_client_manage_channel_ctx.lock);
    return ref_cnt;
}

// for example channel 0, channel 1 get manage channel 2
// 1. channel 0 attach, get manage channel 2, ref_cnt is 1 (in create)
// 2. channel 1 attach, get manage channel 2, ref_cnt is 2 (add ref_cnt)
// 3. channel 0 detach, ref_cnt put to 1, don't stop keepalive and not delayed release manage channel 2
// 4. channel 1 detach, ref_cnt put to 1 (because of delayed release), stop keepalive
uint32_t client_manage_channel_put(urpc_host_info_t *server, uint32_t channel_id, bool delayed, bool is_async)
{
    urpc_channel_info_t *channel_info = channel_get(channel_id);
    if (channel_info == NULL || channel_info->attr != URPC_ATTR_MANAGE) {
        URPC_LIB_LOG_ERR("manage channel[%u] get attr failed\n", channel_id);
        return 0;
    }

    uint32_t ref_cnt = 0;
    urpc_instance_key_t key = {0};
    urpc_keepalive_task_info_t info = {
        .server_chid = URPC_INVALID_ID_U32, .client_chid = channel_id, .is_server = URPC_FALSE};

    delayed ? urpc_resource_release_ctx_lock() : 0;
    (void)pthread_mutex_lock(&g_urpc_client_manage_channel_ctx.lock);
    server_node_t *server_node = manage_channel_get_server_node(channel_info);
    if (URPC_UNLIKELY(server_node == NULL)) {
        URPC_LIB_LOG_ERR("find server node of channel[%u] failed\n", channel_id);
    } else {
        info.server_chid = server_node->server_chid;
        memcpy(&key, &server_node->instance_key, sizeof(urpc_instance_key_t));
    }

    // ref_cnt > 0 means other client channel still use this manage channel
    client_manage_channel_entry_t *entry = client_manage_channel_id_lookup_inner(server);
    if (delayed && entry != NULL && entry->ref_cnt == 1) {
        (void)client_manage_channel_id_get(server); // add ref if need delayed release
        // start delayed release
        if (client_manage_channel_delayed_release(server, channel_id, &entry->delayed_task_id, is_async) != 0) {
            (void)client_manage_channel_id_put(server);
        } else if (is_feature_enable(URPC_FEATURE_KEEPALIVE)) {
            (void)keepalive_task_stop(&key, &info);
        }
    }
    delayed ? urpc_resource_release_ctx_unlock() : 0;

    ref_cnt = client_manage_channel_id_put(server);
    // if user channel has already detached, we need to destroy keepalive task
    if (ref_cnt == 0 && is_feature_enable(URPC_FEATURE_KEEPALIVE)) {
        urpc_keepalive_task_delete(&key, &info);
    }

    if (ref_cnt > 0) {
        (void)pthread_mutex_unlock(&g_urpc_client_manage_channel_ctx.lock);
        URPC_LIB_LOG_DEBUG("client manage channel[%u] is still in use, refcnt %u\n", channel_id, ref_cnt);
        return ref_cnt;
    }

    urpc_channel_qinfos_t *qinfo =
        (urpc_channel_qinfos_t *)urpc_dbuf_malloc(URPC_DBUF_TYPE_CP, sizeof(urpc_channel_qinfos_t));
    if (qinfo == NULL) {
        URPC_LIB_LOG_ERR("malloc failed\n");
        goto EXIT;
    }

    channel_queue_query(channel_info, qinfo);

    (void)pthread_rwlock_wrlock(&channel_info->rw_lock);
    // remove remote queue
    for (uint16_t i = 0; i < qinfo->r_qnum; i++) {
        (void)channel_remove_remote_queue(channel_info, (queue_t *)(uintptr_t)qinfo->r_qinfo[i].urpc_qh);
    }
    // remove local queue
    for (uint16_t i = 0; i < qinfo->l_qnum; i++) {
        channel_remove_local_queue(channel_info, (queue_t *)(uintptr_t)qinfo->l_qinfo[i].urpc_qh);
    }
    (void)pthread_rwlock_unlock(&channel_info->rw_lock);

    urpc_dbuf_free(qinfo);

EXIT:
    (void)channel_free(channel_id);
    (void)pthread_mutex_unlock(&g_urpc_client_manage_channel_ctx.lock);
    URPC_LIB_LOG_INFO("urpc manage channel[%u] put success\n", channel_id);

    return 0;
}

void client_manage_channel_delayed_reset(urpc_host_info_t *server, urpc_instance_key_t *key, uint32_t server_chid,
                                         uint32_t client_chid)
{
    bool restart_keepalive = false;
    urpc_resource_release_ctx_lock();
    (void)pthread_mutex_lock(&g_urpc_client_manage_channel_ctx.lock);
    client_manage_channel_entry_t *entry = client_manage_channel_id_lookup_inner(server);
    if (entry != NULL && entry->delayed_task_id != 0) {
        if (urpc_resource_release_entry_delete(entry->delayed_task_id)) {
            // delete success means manage channel not delayed yet, put ref_cnt here
            entry->delayed_task_id = 0;
            (void)client_manage_channel_id_put(server);
            restart_keepalive = true;
        }
        URPC_LIB_LOG_DEBUG("client manage channel[%u] resource release entry delete %s\n",
            entry->channel_id, entry->delayed_task_id == 0 ? "success" : "failed");
    }
    (void)pthread_mutex_unlock(&g_urpc_client_manage_channel_ctx.lock);
    urpc_resource_release_ctx_unlock();

    if (!restart_keepalive || !is_feature_enable(URPC_FEATURE_KEEPALIVE)) {
        return;
    }

    urpc_keepalive_task_info_t info = {
        .server_chid = server_chid, .client_chid = client_chid, .is_server = URPC_FALSE};
    (void)keepalive_task_restart(key, &info);
}

void urpc_client_manage_channel_ctx_lock()
{
    (void)pthread_mutex_lock(&g_urpc_client_manage_channel_ctx.lock);
}

void urpc_client_manage_channel_ctx_unlock()
{
    (void)pthread_mutex_unlock(&g_urpc_client_manage_channel_ctx.lock);
}