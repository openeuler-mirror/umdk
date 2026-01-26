/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2024-2024. All rights reserved.
 * Description: realize server manage channel, one client to one server maintains one manage channel
 * Create: 2024-8-29
 */

#include "channel.h"
#include "cp.h"
#include "keepalive.h"
#include "queue.h"
#include "resource_release.h"
#include "urpc_hmap.h"
#include "urpc_lib_log.h"
#include "urpc_dbuf_stat.h"

#include "server_manage_channel.h"

#define SERVER_MANAGE_CHANNEL_SIZE (1 << 13)

// only after all client channel to this server detached, entry can be deleted
typedef struct server_manage_channel_entry {
    struct urpc_hmap_node node;
    urpc_instance_key_t client;
    uint32_t client_chid;
    uint32_t channel_id;
    uint32_t mapped_id;
    uint32_t ref_cnt;
    uint32_t delayed_task_id; // 0 is reserved as initial value
} server_manage_channel_entry_t;

static struct server_manage_channel_ctx {
    pthread_mutex_t lock;
    struct urpc_hmap hmap;  // key: urpc_instance_key_t, val: server_manage_channel_entry_t
} g_urpc_server_manage_channel_ctx = {
    .lock = PTHREAD_MUTEX_INITIALIZER,
};

typedef struct server_manage_channel_release_args {
    urpc_instance_key_t client;
    uint32_t manage_chid;
} server_manage_channel_release_args_t;

static int server_manage_channel_delayed_release_callback(void *args, bool force)
{
    server_manage_channel_release_args_t *arg = (server_manage_channel_release_args_t *)args;
    if (arg == NULL) {
        return URPC_RESOURCE_RELEASE_DONE;
    }

    URPC_LIB_LOG_DEBUG("server manage channel[%u] delayed release\n", arg->manage_chid);

    uint32_t ref_cnt = server_manage_channel_put(&arg->client, false, false);
    if (ref_cnt == 0) {
        (void)server_channel_free(arg->manage_chid, false);
    }
    urpc_dbuf_free(arg);

    return URPC_RESOURCE_RELEASE_DONE;
}

static int server_manage_channel_delayed_release(urpc_instance_key_t *client, uint32_t manage_chid, uint32_t *task_id)
{
    server_manage_channel_release_args_t *args = (server_manage_channel_release_args_t *)
        urpc_dbuf_malloc(URPC_DBUF_TYPE_CP, sizeof(server_manage_channel_release_args_t));
    if (args == NULL) {
        URPC_LIB_LOG_ERR("malloc channel delayed release args failed\n");
        return -1;
    }

    args->client = *client;
    args->manage_chid = manage_chid;

    int ret = urpc_resource_release_entry_add(
        server_manage_channel_delayed_release_callback, args, urpc_keepalive_release_time_get(), task_id);
    if (ret != 0) {
        urpc_dbuf_free(args);
        return -1;
    }

    return 0;
}

void server_manage_channel_uninit(void)
{
    if (!is_feature_enable(URPC_MANAGE_FEATURE_FLAG)) {
        return;
    }

    if (g_urpc_server_manage_channel_ctx.hmap.count == 0) {
        urpc_hmap_uninit(&g_urpc_server_manage_channel_ctx.hmap);
        return;
    }

    server_manage_channel_entry_t *cur, *next;
    URPC_HMAP_FOR_EACH_SAFE(cur, next, node, &g_urpc_server_manage_channel_ctx.hmap) {
        urpc_hmap_remove(&g_urpc_server_manage_channel_ctx.hmap, &cur->node);
        urpc_dbuf_free(cur);
    }

    urpc_hmap_uninit(&g_urpc_server_manage_channel_ctx.hmap);
}

static server_manage_channel_entry_t *server_manage_channel_id_lookup_inner(urpc_instance_key_t *client)
{
    uint32_t hash = urpc_instance_key_hash(client);
    server_manage_channel_entry_t *entry;

    URPC_HMAP_FOR_EACH_WITH_HASH(entry, node, hash, &g_urpc_server_manage_channel_ctx.hmap) {
        if (urpc_instance_key_cmp(client, &entry->client)) {
            return entry;
        }
    }

    return NULL;
}

static int server_manage_channel_id_add(
    urpc_instance_key_t *client, uint32_t client_manage_chid, uint32_t channel_id, uint32_t mapped_id)
{
    server_manage_channel_entry_t *entry = (server_manage_channel_entry_t *)urpc_dbuf_calloc(URPC_DBUF_TYPE_CP,
        1, sizeof(server_manage_channel_entry_t));
    if (entry == NULL) {
        URPC_LIB_LOG_ERR("malloc server manage_channel_entry failed\n");
        return -1;
    }

    entry->ref_cnt = 1;
    entry->channel_id = channel_id;
    entry->client.eid = client->eid;
    entry->client.pid = client->pid;
    entry->client_chid = client_manage_chid;
    entry->mapped_id = mapped_id;

    uint32_t hash = urpc_instance_key_hash(client);
    urpc_hmap_insert(&g_urpc_server_manage_channel_ctx.hmap, &entry->node, hash);

    return 0;
}

static int server_manage_channel_id_get(urpc_instance_key_t *client, uint32_t *chid, uint32_t *mapped_chid)
{
    server_manage_channel_entry_t *entry = server_manage_channel_id_lookup_inner(client);
    if (entry != NULL) {
        *chid = entry->channel_id;
        *mapped_chid = entry->mapped_id;
        entry->ref_cnt++;

        return URPC_SUCCESS;
    }

    return URPC_FAIL;
}

static uint32_t server_manage_channel_id_put(urpc_instance_key_t *client)
{
    uint32_t ref_cnt = 0;
    server_manage_channel_entry_t *entry;

    entry = server_manage_channel_id_lookup_inner(client);
    if (entry != NULL && entry->ref_cnt > 0) {
        entry->ref_cnt--;
        ref_cnt = entry->ref_cnt;

        if (ref_cnt == 0) {
            urpc_hmap_remove(&g_urpc_server_manage_channel_ctx.hmap, &entry->node);
            urpc_dbuf_free(entry);
        }
    }

    return ref_cnt;
}

int server_manage_channel_get(urpc_instance_key_t *client, uint32_t client_manage_chid, uint64_t user_ctx,
    uint32_t *mange_chid, uint32_t *mapped_id)
{
    uint32_t channel_chid = URPC_INVALID_ID_U32;
    uint32_t mapped_chid = URPC_INVALID_ID_U32;

    (void)pthread_mutex_lock(&g_urpc_server_manage_channel_ctx.lock);

    if (server_manage_channel_id_get(client, mange_chid, mapped_id) == URPC_SUCCESS) {
        channel_chid = *mange_chid;
        // restart keepalive check
        urpc_keepalive_id_t id = {.client_chid = client_manage_chid, .server_chid = channel_chid};
        urpc_keepalive_task_timestamp_update(&id, true);
        // manage channel of this client already existed
        (void)pthread_mutex_unlock(&g_urpc_server_manage_channel_ctx.lock);
        URPC_LIB_LOG_DEBUG("server manage channel[%u] get success\n", channel_chid);
        return URPC_SUCCESS;
    }

    urpc_server_channel_info_t *manage_channel = server_channel_alloc(client, user_ctx);
    if (manage_channel == NULL) {
        URPC_LIB_LOG_ERR("malloc server manage channel failed, eid: " EID_FMT ", pid: %u\n",
            EID_ARGS(client->eid), client->pid);
        goto UNLOCK;
    }
    manage_channel->attr = URPC_ATTR_MANAGE;
    manage_channel->client_chid[0] = client_manage_chid;
    channel_chid = manage_channel->id;
    mapped_chid = manage_channel->mapped_id;
    (void)pthread_rwlock_unlock(&manage_channel->rw_lock);

    if (server_manage_channel_id_add(client, client_manage_chid, channel_chid, mapped_chid) != 0) {
        URPC_LIB_LOG_ERR("add server manage channel failed\n");
        goto FREE_CHANNEL;
    }

    (void)pthread_mutex_unlock(&g_urpc_server_manage_channel_ctx.lock);

    URPC_LIB_LOG_DEBUG("urpc server manage channel[%u] create success\n", channel_chid);

    *mange_chid = channel_chid;
    *mapped_id = mapped_chid;

    return URPC_SUCCESS;

FREE_CHANNEL:
    (void)server_channel_free(channel_chid, true);

UNLOCK:
    (void)pthread_mutex_unlock(&g_urpc_server_manage_channel_ctx.lock);

    return URPC_FAIL;
}

uint32_t server_manage_channel_put(urpc_instance_key_t *client, bool delayed, bool skip_ka_task_delete)
{
    uint32_t chid = 0, mapped_id = 0, ref_cnt = 0;
    urpc_keepalive_task_info_t info = {.is_server = URPC_TRUE};

    (void)pthread_mutex_lock(&g_urpc_server_manage_channel_ctx.lock);
    server_manage_channel_entry_t *entry = server_manage_channel_id_lookup_inner(client);
    if (URPC_LIKELY(entry != NULL)) {
        chid = entry->channel_id;
        info.server_chid = chid;
        info.client_chid = entry->client_chid;
    } else {
        chid = URPC_INVALID_ID_U32;
        info.server_chid = URPC_INVALID_ID_U32;
        info.client_chid = URPC_INVALID_ID_U32;
    }

    if (delayed && entry != NULL && entry->ref_cnt == 1) {
        (void)server_manage_channel_id_get(client, &chid, &mapped_id); // add ref if need delayed release
        if (server_manage_channel_delayed_release(client, entry->channel_id, &entry->delayed_task_id) != 0) {
            (void)server_manage_channel_id_put(client);
        } else if (is_feature_enable(URPC_FEATURE_KEEPALIVE)) {
            // set server keepalive entry to delayed, and not check keepalive status
            keepalive_task_stop(client, &info);
        }
    }
    // ref_cnt > 0 means other server channel still use this manage channel
    ref_cnt = server_manage_channel_id_put(client);
    (void)pthread_mutex_unlock(&g_urpc_server_manage_channel_ctx.lock);
    if (ref_cnt > 0) {
        URPC_LIB_LOG_DEBUG("server manage channel[%u] is still in use, refcnt %u\n", chid, ref_cnt);
        return ref_cnt;
    }

    if (!skip_ka_task_delete && is_feature_enable(URPC_FEATURE_KEEPALIVE)) {
        urpc_keepalive_task_delete(client, &info);
    }

    return 0;
}

void server_mange_channel_delayed_reset(urpc_instance_key_t *client, uint32_t server_chid, uint32_t client_chid)
{
    bool restart_keepalive = false;
    urpc_resource_release_ctx_lock();
    (void)pthread_mutex_lock(&g_urpc_server_manage_channel_ctx.lock);
    server_manage_channel_entry_t *entry = server_manage_channel_id_lookup_inner(client);
    if (entry != NULL && entry->delayed_task_id != 0) {
        if (urpc_resource_release_entry_delete(entry->delayed_task_id)) {
            // delete success means manage channel not delayed yet, put ref_cnt here
            entry->delayed_task_id = 0;
            (void)server_manage_channel_id_put(client);
            restart_keepalive = true;
        }
    }
    (void)pthread_mutex_unlock(&g_urpc_server_manage_channel_ctx.lock);
    urpc_resource_release_ctx_unlock();

    if (!restart_keepalive || !is_feature_enable(URPC_FEATURE_KEEPALIVE)) {
        return;
    }

    urpc_keepalive_task_info_t info = {
        .server_chid = server_chid, .client_chid = client_chid, .is_server = URPC_TRUE};
    (void)keepalive_task_restart(client, &info);
}
