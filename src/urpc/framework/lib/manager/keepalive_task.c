/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2024-2024. All rights reserved.
 * Description: define keepalive task management
 * Create: 2024-11-14
 */

#include "cp.h"
#include "crypto.h"
#include "server_manage_channel.h"
#include "state.h"
#include "urpc_dbuf_stat.h"
#include "urpc_hash.h"
#include "urpc_lib_log.h"
#include "urpc_manage.h"
#include "urpc_util.h"

#include "keepalive.h"

#define URPC_KEEPALIVE_TASK_NUM (8192)

static struct {
    pthread_rwlock_t lock;           // when insert/remove entry, use wr_lock, otherwise, use rd_lock
    struct urpc_hmap client_id_map;  // key: manage chid, value: entry. to prevent timer and mange thread concurrency
    struct urpc_hmap server_id_map;  // key: manage chid, value: entry. to prevent timer and mange thread concurrency
    struct urpc_hmap task_map;       // key: remote urpc_instance_key_t, value: entry
    struct urpc_hmap server_info_map;  // key: urpc_server_info_inner_t, value: entry. used when insert input msg
    urpc_list_t reachable_list;        // logic server update its timestamp
} g_urpc_keepalive_mgmt = {
    .lock = PTHREAD_RWLOCK_INITIALIZER,
};

static inline void urpc_keepalive_id_fill(urpc_keepalive_id_t *id, uint32_t client_chid, uint32_t server_chid)
{
    id->client_chid = client_chid;
    id->server_chid = server_chid;
}

static inline bool is_urpc_keepalive_id_same(urpc_keepalive_id_t *id1, urpc_keepalive_id_t *id2)
{
    return ((id1->client_chid == id2->client_chid) && (id1->server_chid == id2->server_chid));
}

int urpc_keepalive_task_init(void)
{
    int ret;

    urpc_list_init(&g_urpc_keepalive_mgmt.reachable_list);
    ret = urpc_hmap_init(&g_urpc_keepalive_mgmt.client_id_map, URPC_KEEPALIVE_TASK_NUM);
    if (ret != URPC_SUCCESS) {
        URPC_LIB_LOG_ERR("keepalive client id hmap init failed\n");
        return URPC_FAIL;
    }

    ret = urpc_hmap_init(&g_urpc_keepalive_mgmt.server_id_map, URPC_KEEPALIVE_TASK_NUM);
    if (ret != URPC_SUCCESS) {
        URPC_LIB_LOG_ERR("keepalive server id hmap init failed\n");
        goto UNINIT_CLIENT_ID_MAP;
    }

    ret = urpc_hmap_init(&g_urpc_keepalive_mgmt.task_map, URPC_KEEPALIVE_TASK_NUM);
    if (ret != URPC_SUCCESS) {
        URPC_LIB_LOG_ERR("keepalive task hmap init failed\n");
        goto UNINIT_SERVER_ID_MAP;
    }

    ret = urpc_hmap_init(&g_urpc_keepalive_mgmt.server_info_map, URPC_KEEPALIVE_TASK_NUM);
    if (ret != URPC_SUCCESS) {
        URPC_LIB_LOG_ERR("keepalive server info hmap init failed\n");
        goto UNINIT_TASK_MAP;
    }

    return URPC_SUCCESS;

UNINIT_TASK_MAP:
    urpc_hmap_uninit(&g_urpc_keepalive_mgmt.task_map);

UNINIT_SERVER_ID_MAP:
    urpc_hmap_uninit(&g_urpc_keepalive_mgmt.server_id_map);

UNINIT_CLIENT_ID_MAP:
    urpc_hmap_uninit(&g_urpc_keepalive_mgmt.client_id_map);

    return URPC_FAIL;
}

static void urpc_keepalive_task_free(urpc_keepalive_task_entry_t *entry)
{
    (void)pthread_spin_lock(&entry->lock);
    // delete timer
    if (entry->timer != NULL) {
        urpc_timer_destroy(entry->timer);
        entry->timer = NULL;
    }

    // remove from id_map, server_info map and task_map
    if (entry->has_client == URPC_TRUE) {
        urpc_hmap_remove(&g_urpc_keepalive_mgmt.client_id_map, &entry->client_id_node);
        urpc_hmap_remove(&g_urpc_keepalive_mgmt.server_info_map, &entry->server_info_node);
    }
    if (entry->has_server == URPC_TRUE) {
        urpc_hmap_remove(&g_urpc_keepalive_mgmt.server_id_map, &entry->server_id_node);
    }
    urpc_hmap_remove(&g_urpc_keepalive_mgmt.task_map, &entry->task_node);

    // remove from reachable list
    if (URPC_LIKELY(urpc_list_is_in_list(&entry->list))) {
        urpc_list_remove(&entry->list);
    }

    (void)pthread_spin_unlock(&entry->lock);

    pthread_spin_destroy(&entry->lock);
    urpc_dbuf_free(entry);
}

void urpc_keepalive_task_uninit(void)
{
    (void)pthread_rwlock_wrlock(&g_urpc_keepalive_mgmt.lock);

    urpc_keepalive_task_entry_t *cur, *next;
    URPC_HMAP_FOR_EACH_SAFE(cur, next, task_node, &g_urpc_keepalive_mgmt.task_map) {
        urpc_keepalive_task_free(cur);
    }

    urpc_hmap_uninit(&g_urpc_keepalive_mgmt.server_info_map);
    urpc_hmap_uninit(&g_urpc_keepalive_mgmt.client_id_map);
    urpc_hmap_uninit(&g_urpc_keepalive_mgmt.server_id_map);
    urpc_hmap_uninit(&g_urpc_keepalive_mgmt.task_map);

    (void)pthread_rwlock_unlock(&g_urpc_keepalive_mgmt.lock);
}

static inline urpc_keepalive_task_entry_t *client_keepalive_task_lookup_by_id(urpc_keepalive_id_t *id)
{
    urpc_keepalive_task_entry_t *entry = NULL;
    uint32_t hash = urpc_hash_uint64(id->id);

    URPC_HMAP_FOR_EACH_WITH_HASH(entry, client_id_node, hash, &g_urpc_keepalive_mgmt.client_id_map) {
        if (is_urpc_keepalive_id_same(id, &entry->client_task_id)) {
            return entry;
        }
    }

    return NULL;
}

static inline urpc_keepalive_task_entry_t *server_keepalive_task_lookup_by_id(urpc_keepalive_id_t *id)
{
    urpc_keepalive_task_entry_t *entry = NULL;
    uint32_t hash = urpc_hash_uint64(id->id);

    URPC_HMAP_FOR_EACH_WITH_HASH(entry, server_id_node, hash, &g_urpc_keepalive_mgmt.server_id_map) {
        if (is_urpc_keepalive_id_same(id, &entry->server_task_id)) {
            return entry;
        }
    }

    return NULL;
}

static inline urpc_keepalive_task_entry_t *urpc_keepalive_task_lookup_by_id(urpc_keepalive_id_t *id, bool is_server)
{
    if (is_server) {
        return server_keepalive_task_lookup_by_id(id);
    }

    return client_keepalive_task_lookup_by_id(id);
}

static inline urpc_keepalive_task_entry_t *urpc_keepalive_task_lookup(urpc_instance_key_t *key)
{
    urpc_keepalive_task_entry_t *entry = NULL;
    uint32_t hash = urpc_instance_key_hash(key);

    URPC_HMAP_FOR_EACH_WITH_HASH(entry, task_node, hash, &g_urpc_keepalive_mgmt.task_map) {
        if (urpc_instance_key_cmp(key, &entry->key)) {
            return entry;
        }
    }

    return NULL;
}

static urpc_keepalive_task_entry_t *urpc_keepalive_task_lookup_by_server_info(urpc_host_info_t *server)
{
    urpc_keepalive_task_entry_t *entry = NULL;
    urpc_host_info_inner_t server_inner = {0};
    urpc_server_info_convert(server, &server_inner);
    uint32_t hash = urpc_hash_bytes(&server_inner, sizeof(urpc_host_info_inner_t), 0);

    URPC_HMAP_FOR_EACH_WITH_HASH(entry, server_info_node, hash, &g_urpc_keepalive_mgmt.server_info_map) {
        if (memcmp(&entry->server_inner, &server_inner, sizeof(urpc_host_info_inner_t)) == 0) {
            return entry;
        }
    }

    return NULL;
}

static inline void urpc_keepalive_task_reachable(urpc_keepalive_task_entry_t *entry)
{
    if (URPC_LIKELY(urpc_list_is_in_list(&entry->list))) {
        urpc_list_remove(&entry->list);
    }

    urpc_list_push_back(&g_urpc_keepalive_mgmt.reachable_list, &entry->list);
}

// used when logic server recv rsp ta_ack or logic client recv rsp(version >= 1)
void urpc_keepalive_task_timestamp_update(urpc_keepalive_id_t *id, bool is_server)
{
    urpc_keepalive_task_entry_t *entry = NULL;
    bool updated = false;

    (void)pthread_rwlock_wrlock(&g_urpc_keepalive_mgmt.lock);
    entry = urpc_keepalive_task_lookup_by_id(id, is_server);
    if (URPC_LIKELY(entry != NULL)) {
        // in the following cases, we should update keepalive task timestamp
        // 1. for server, always update
        // 2. for client, local and remote version >= 1 and has logic server
        updated = (is_server && entry->has_server == URPC_TRUE) ||
                  (!is_server && entry->has_server == URPC_TRUE && entry->remote_version > 0);
        if (URPC_LIKELY(updated)) {
            (void)pthread_spin_lock(&entry->lock);
            entry->cpu_cycles = urpc_get_cpu_cycles();
            urpc_keepalive_task_reachable(entry);
            (void)pthread_spin_unlock(&entry->lock);
        }
    }
    (void)pthread_rwlock_unlock(&g_urpc_keepalive_mgmt.lock);

    if (updated) {
        URPC_LIB_LIMIT_LOG_DEBUG(
            "update keepalive task timestamp successful, local is %s, client chid[%u], server chid[%u]\n",
            is_server ? "server" : "client", id->client_chid, id->server_chid);
    }
}

int urpc_keepalive_task_entry_info_get(urpc_keepalive_id_t *id, bool is_server, urpc_keepalive_event_info_t *info)
{
    int ret = URPC_FAIL;
    urpc_keepalive_task_entry_t *entry = NULL;

    (void)pthread_rwlock_rdlock(&g_urpc_keepalive_mgmt.lock);
    entry = urpc_keepalive_task_lookup_by_id(id, is_server);
    if (URPC_LIKELY(entry != NULL)) {
        (void)pthread_spin_lock(&entry->lock);
        info->user_ctx = entry->user_ctx;
        info->peer_pid = entry->key.pid;
        ret = URPC_SUCCESS;
        (void)pthread_spin_unlock(&entry->lock);
    }
    (void)pthread_rwlock_unlock(&g_urpc_keepalive_mgmt.lock);

    return ret;
}

int urpc_keepalive_task_server_chid_add(urpc_instance_key_t *key, urpc_keepalive_task_info_t *info)
{
    int ret = URPC_SUCCESS;
    urpc_keepalive_task_entry_t *entry;
    (void)pthread_rwlock_rdlock(&g_urpc_keepalive_mgmt.lock);

    entry = urpc_keepalive_task_lookup(key);
    if (entry == NULL) {
        URPC_LIB_LOG_ERR("find keepalive task failed, server chid[%u], " EID_FMT ", pid: %u\n", info->server_chid,
                         EID_ARGS(key->eid), key->pid);
        (void)pthread_rwlock_unlock(&g_urpc_keepalive_mgmt.lock);
        return URPC_FAIL;
    }

    (void)pthread_spin_lock(&entry->lock);

    for (uint8_t i = 0; i < entry->server_chid_num; i++) {
        if (entry->server_chid[i] == info->server_chid) {
            URPC_LIB_LOG_DEBUG("keepalive task server chid[%u] already existed, " EID_FMT ", pid: %u\n",
                info->server_chid, EID_ARGS(key->eid), key->pid);
            goto UNLOCK;
        }
    }

    if (entry->server_chid_num >= URPC_MAX_CHANNEL_PER_CLIENT) {
        URPC_LIB_LOG_ERR("keepalive task server chid[%u] num exceed %d, " EID_FMT ", pid: %u\n",
            info->server_chid, URPC_MAX_CHANNEL_PER_CLIENT, EID_ARGS(key->eid), key->pid);
        ret = URPC_FAIL;
        goto UNLOCK;
    }

    entry->server_chid[entry->server_chid_num++] = info->server_chid;
    URPC_LIB_LOG_INFO("keepalive task server chid[%u] add successful, " EID_FMT ", pid: %u\n",
                info->server_chid, EID_ARGS(key->eid), key->pid);

UNLOCK:
    (void)pthread_spin_unlock(&entry->lock);
    (void)pthread_rwlock_unlock(&g_urpc_keepalive_mgmt.lock);

    return ret;
}

void urpc_keepalive_task_server_chid_delete(urpc_instance_key_t *key, urpc_keepalive_task_info_t *info)
{
    uint8_t i;
    urpc_keepalive_task_entry_t *entry;
    (void)pthread_rwlock_rdlock(&g_urpc_keepalive_mgmt.lock);

    entry = urpc_keepalive_task_lookup(key);
    if (entry == NULL) {
        URPC_LIB_LOG_ERR("find keepalive task failed, server chid[%u], " EID_FMT ", pid: %u\n", info->server_chid,
                         EID_ARGS(key->eid), key->pid);
        goto MGMT_UNLOCK;
    }

    (void)pthread_spin_lock(&entry->lock);
    for (i = 0; i < entry->server_chid_num; i++) {
        if (entry->server_chid[i] == info->server_chid) {
            break;
        }
    }
    // logic server info not found
    if (i == entry->server_chid_num) {
        URPC_LIB_LOG_ERR("find keepalive task server chid[%u] failed, " EID_FMT ", pid: %u\n", info->server_chid,
                         EID_ARGS(key->eid), key->pid);
        goto ENTRY_UNLOCK;
    }

    // delete remote client channel id
    for (uint8_t j = i + 1; j < entry->server_chid_num; j++) {
        entry->server_chid[j - 1] = entry->server_chid[j];
    }
    entry->server_chid_num--;
    URPC_LIB_LOG_INFO("keepalive task server chid[%u] delete successful, " EID_FMT ", pid: %u\n",
                info->server_chid, EID_ARGS(key->eid), key->pid);

ENTRY_UNLOCK:
    (void)pthread_spin_unlock(&entry->lock);

MGMT_UNLOCK:
    (void)pthread_rwlock_unlock(&g_urpc_keepalive_mgmt.lock);
}

static inline bool is_urpc_keepalive_entry_id_same(urpc_keepalive_task_info_t *info, urpc_keepalive_task_entry_t *entry)
{
    if (info->is_server) {
        return ((info->client_chid == entry->server_task_id.client_chid) &&
                (info->server_chid == entry->server_task_id.server_chid));
    }

    return ((info->client_chid == entry->client_task_id.client_chid) &&
            (info->server_chid == entry->client_task_id.server_chid));
}

static int urpc_keepalive_task_add_logic_server(
    urpc_instance_key_t *key, urpc_keepalive_task_info_t *info, urpc_keepalive_task_entry_t *entry)
{
    bool update_server_id = false;
    if (entry->has_server == URPC_TRUE) {
        // update server_task_id if necessary
        if (is_urpc_keepalive_entry_id_same(info, entry)) {
            URPC_LIB_LOG_DEBUG("keepalive logic server existed, client chid[%u], server chid[%u], " EID_FMT
                              ", pid: %u\n", info->client_chid, info->server_chid, EID_ARGS(key->eid), key->pid);
            return URPC_SUCCESS;
        }

        // remove old id_node, and then update new id_node
        update_server_id = true;
        urpc_hmap_remove(&g_urpc_keepalive_mgmt.server_id_map, &entry->server_id_node);
    }

    entry->has_server = URPC_TRUE;
    urpc_keepalive_id_fill(&entry->server_task_id, info->client_chid, info->server_chid);
    uint32_t id_hash = urpc_hash_uint64(entry->server_task_id.id);
    urpc_hmap_insert(&g_urpc_keepalive_mgmt.server_id_map, &entry->server_id_node, id_hash);

    // insert reachable list tail
    entry->cpu_cycles = urpc_get_cpu_cycles();
    urpc_keepalive_task_reachable(entry);

    URPC_LIB_LOG_DEBUG(
        "keepalive %s logic server successful, client chid[%u], server chid[%u], " EID_FMT ", pid: %u\n",
        update_server_id ? "update" : "add", info->client_chid, info->server_chid, EID_ARGS(key->eid), key->pid);

    return URPC_SUCCESS;
}

int urpc_keepalive_msg_send(urpc_keepalive_id_t *id)
{
    int ret;
    urpc_keepalive_task_entry_t *entry;
    (void)pthread_rwlock_rdlock(&g_urpc_keepalive_mgmt.lock);
    entry = urpc_keepalive_task_lookup_by_id(id, false);
    if (URPC_UNLIKELY(entry == NULL)) {
        (void)pthread_rwlock_unlock(&g_urpc_keepalive_mgmt.lock);
        URPC_LIB_LIMIT_LOG_ERR("keepalive task probe failed, client chid[%u] server chid[%u] not exist\n",
            id->client_chid, id->server_chid);
        return URPC_FAIL;
    }

    (void)pthread_spin_lock(&entry->lock);
    ret = urpc_keepalive_request_send(entry);
    (void)pthread_spin_unlock(&entry->lock);

    (void)pthread_rwlock_unlock(&g_urpc_keepalive_mgmt.lock);

    return ret;
}

static void urpc_keepalive_probe_callback(void *args)
{
    if (URPC_UNLIKELY(args == NULL)) {
        return;
    }

    uint64_t id = (uint64_t)(uintptr_t)args;
    urpc_keepalive_id_t task_id = {.id = id};
    (void)urpc_keepalive_msg_send(&task_id);
}

static int urpc_keepalive_probe_start(urpc_instance_key_t *key, urpc_keepalive_task_entry_t *entry)
{
    if (entry->timer != NULL) {
        urpc_timer_destroy(entry->timer);
    }

    entry->timer = urpc_timer_create(URPC_INVALID_ID_U32, false);
    if (URPC_UNLIKELY(entry->timer == NULL)) {
        URPC_LIB_LOG_ERR(
            "keepalive task create timer failed, " EID_FMT ", pid: %u\n", EID_ARGS(key->eid), key->pid);
        return URPC_FAIL;
    }

    if (urpc_timer_start(entry->timer, urpc_keepalive_cycle_time_get() * MS_PER_SEC, urpc_keepalive_probe_callback,
        (void *)(uintptr_t)(entry->client_task_id.id), true) != URPC_SUCCESS) {
        URPC_LIB_LOG_ERR(
            "keepalive task start timer failed, " EID_FMT ", pid: %u\n", EID_ARGS(key->eid), key->pid);
        urpc_timer_destroy(entry->timer);
        entry->timer = NULL;
        return URPC_FAIL;
    }

    return URPC_SUCCESS;
}

static int urpc_keepalive_task_add_logic_client(
    urpc_instance_key_t *key, urpc_keepalive_task_info_t *info, urpc_keepalive_task_entry_t *entry)
{
    bool update_client_id = false;
    if (entry->has_client == URPC_TRUE) {
        // update client task info if necessary
        if (!urpc_instance_key_cmp(&entry->key, key)) {
            urpc_hmap_remove(&g_urpc_keepalive_mgmt.task_map, &entry->task_node);
            memcpy(&(entry->key), key, sizeof(urpc_instance_key_t));
            uint32_t task_hash = urpc_instance_key_hash(key);
            urpc_hmap_insert(&g_urpc_keepalive_mgmt.task_map, &entry->task_node, task_hash);

            URPC_LIB_LOG_INFO("keepalive logic client update task info, client chid[%u], server chid[%u], " EID_FMT
                              ", pid: %u\n", info->client_chid, info->server_chid, EID_ARGS(key->eid), key->pid);
        }
        // update client_task_id if necessary
        if (is_urpc_keepalive_entry_id_same(info, entry)) {
            entry->client_status = URPC_KEEPALIVE_TASK_RUNNING;
            URPC_LIB_LOG_INFO("keepalive logic client existed, client chid[%u], server chid[%u], " EID_FMT
                              ", pid: %u\n", info->client_chid, info->server_chid, EID_ARGS(key->eid), key->pid);
            return URPC_SUCCESS;
        }

        // remove old id_node, and then update new id_node
        update_client_id = true;
        urpc_hmap_remove(&g_urpc_keepalive_mgmt.client_id_map, &entry->client_id_node);
        urpc_hmap_remove(&g_urpc_keepalive_mgmt.server_info_map, &entry->server_info_node);
    }

    entry->has_client = URPC_TRUE;
    urpc_keepalive_id_fill(&entry->client_task_id, info->client_chid, info->server_chid);
    uint32_t id_hash = urpc_hash_uint64(entry->client_task_id.id);
    urpc_hmap_insert(&g_urpc_keepalive_mgmt.client_id_map, &entry->client_id_node, id_hash);

    urpc_server_info_convert(info->server, &entry->server_inner);
    uint32_t server_info_hash = urpc_hash_bytes(&entry->server_inner, sizeof(urpc_host_info_inner_t), 0);
    urpc_hmap_insert(&g_urpc_keepalive_mgmt.server_info_map, &entry->server_info_node, server_info_hash);

    // if remote is primary server, local must be primary client
    if (info->remote_primary_is_server == URPC_TRUE) {
        entry->primary_is_server = URPC_FALSE;
    }

    // we should start client probe if:
    // 1. primary is client, or
    // 2. entry has logic client and remote version == 0, or
    // 3. entry timer is already started
    if (!((info->remote_version == 0) || (entry->primary_is_server == URPC_FALSE) || (entry->timer != NULL))) {
        URPC_LIB_LOG_INFO("keepalive logic client existed, client chid[%u], server chid[%u], " EID_FMT
                          ", pid: %u\n", info->client_chid, info->server_chid, EID_ARGS(key->eid), key->pid);
        entry->client_status = URPC_KEEPALIVE_TASK_RUNNING;
        return URPC_SUCCESS;
    }

    if (urpc_keepalive_probe_start(key, entry) != URPC_SUCCESS) {
        urpc_hmap_remove(&g_urpc_keepalive_mgmt.server_info_map, &entry->server_info_node);
        urpc_hmap_remove(&g_urpc_keepalive_mgmt.client_id_map, &entry->client_id_node);
        urpc_keepalive_id_fill(&entry->client_task_id, 0, 0);
        entry->has_client = URPC_FALSE;

        return URPC_FAIL;
    }

    entry->client_status = URPC_KEEPALIVE_TASK_RUNNING;
    URPC_LIB_LOG_INFO(
        "keepalive %s logic client successful, client chid[%u], server chid[%u], " EID_FMT ", pid: %u\n",
        update_client_id ? "update" : "add", info->client_chid, info->server_chid, EID_ARGS(key->eid), key->pid);

    return URPC_SUCCESS;
}

static int urpc_keepalive_task_update(
    urpc_instance_key_t *key, urpc_keepalive_task_info_t *info, urpc_keepalive_task_entry_t *entry)
{
    int ret;
    (void)pthread_spin_lock(&entry->lock);
    if (info->is_server == URPC_TRUE) {
        ret = urpc_keepalive_task_add_logic_server(key, info, entry);
    } else {
        ret = urpc_keepalive_task_add_logic_client(key, info, entry);
    }
    (void)pthread_spin_unlock(&entry->lock);

    return ret;
}

bool urpc_keepalive_task_primary_is_client(urpc_instance_key_t *key)
{
    bool primary_is_client = false;
    urpc_keepalive_task_entry_t *entry;

    (void)pthread_rwlock_rdlock(&g_urpc_keepalive_mgmt.lock);
    entry = urpc_keepalive_task_lookup(key);
    if (entry != NULL) {
        primary_is_client = entry->primary_is_server == URPC_FALSE;
    }
    (void)pthread_rwlock_unlock(&g_urpc_keepalive_mgmt.lock);

    return primary_is_client;
}

// when client/server manage channel create
int urpc_keepalive_task_create(urpc_instance_key_t *key, urpc_keepalive_task_info_t *info)
{
    int ret;
    urpc_keepalive_task_entry_t *entry;

    (void)pthread_rwlock_wrlock(&g_urpc_keepalive_mgmt.lock);
    entry = urpc_keepalive_task_lookup(key);
    if (entry == NULL && info->is_server == URPC_FALSE) {
        // client retry to use server info to find keepalive task in case server is re-started
        entry = urpc_keepalive_task_lookup_by_server_info(info->server);
    }
    if (entry != NULL) {
        ret = urpc_keepalive_task_update(key, info, entry);
        (void)pthread_rwlock_unlock(&g_urpc_keepalive_mgmt.lock);
        return ret;
    }

    entry = (urpc_keepalive_task_entry_t *)urpc_dbuf_calloc(
        URPC_DBUF_TYPE_KEEPALIVE, 1, sizeof(urpc_keepalive_task_entry_t));
    if (entry == NULL) {
        (void)pthread_rwlock_unlock(&g_urpc_keepalive_mgmt.lock);
        URPC_LIB_LOG_ERR("malloc keepalive entry failed\n");
        return URPC_FAIL;
    }

    entry->cpu_cycles = urpc_get_cpu_cycles();
    entry->user_ctx = info->user_ctx;
    entry->remote_version = info->remote_version;
    entry->primary_is_server = info->is_server;
    memcpy(&(entry->key), key, sizeof(urpc_instance_key_t));
    (void)pthread_spin_init(&entry->lock, PTHREAD_PROCESS_PRIVATE);

    ret = urpc_keepalive_task_update(key, info, entry);
    if (ret != URPC_SUCCESS) {
        pthread_spin_destroy(&entry->lock);
        urpc_dbuf_free(entry);

        (void)pthread_rwlock_unlock(&g_urpc_keepalive_mgmt.lock);
        URPC_LIB_LOG_ERR("create keepalive task failed, client chid[%u], server chid[%u], " EID_FMT ", pid: %u\n",
                         info->client_chid, info->server_chid, EID_ARGS(key->eid), key->pid);
        return URPC_FAIL;
    }

    uint32_t task_hash = urpc_instance_key_hash(key);
    urpc_hmap_insert(&g_urpc_keepalive_mgmt.task_map, &entry->task_node, task_hash);

    (void)pthread_rwlock_unlock(&g_urpc_keepalive_mgmt.lock);

    URPC_LIB_LOG_INFO("create keepalive task successful, client chid[%u] server chid[%u], " EID_FMT ", pid: %u\n",
                      info->client_chid, info->server_chid, EID_ARGS(key->eid), key->pid);

    return URPC_SUCCESS;
}

static void urpc_keepalive_task_delete_logic_server(urpc_instance_key_t *key, urpc_keepalive_task_entry_t *entry)
{
    if (entry->server_chid_num > 0) {
        URPC_LIB_LOG_WARN("keepalive task server chid num [%u] is not zero, " EID_FMT ", pid: %u\n",
            entry->server_chid_num, EID_ARGS(key->eid), key->pid);
    }

    entry->server_chid_num = 0;
    // no logic server
    entry->has_server = URPC_FALSE;
    urpc_hmap_remove(&g_urpc_keepalive_mgmt.server_id_map, &entry->server_id_node);
    // remove from reachable list
    if (URPC_LIKELY(urpc_list_is_in_list(&entry->list))) {
        urpc_list_remove(&entry->list);
    }

    URPC_LIB_LOG_INFO("keepalive delete logic server successful, client chid[%u], server chid[%u], " EID_FMT
                       ", pid: %u\n",
        entry->server_task_id.client_chid, entry->server_task_id.server_chid, EID_ARGS(key->eid), key->pid);

    if (entry->primary_is_server == URPC_FALSE) {
        return;
    }
    entry->primary_is_server = URPC_FALSE;
    // we should start client probe if:
    // 1. primary is server && 2. entry has logic client && 3. remote version > 0 && 4. client task status is running
    if (!((entry->has_client == URPC_TRUE) && (entry->remote_version > 0) &&
          (entry->client_status == URPC_KEEPALIVE_TASK_RUNNING))) {
        return;
    }

    (void)urpc_keepalive_probe_start(key, entry);
}

static void urpc_keepalive_task_delete_logic_client(urpc_instance_key_t *key, urpc_keepalive_task_entry_t *entry)
{
    if (entry->timer != NULL) {
        urpc_timer_destroy(entry->timer);
        entry->timer = NULL;
    }

    urpc_hmap_remove(&g_urpc_keepalive_mgmt.client_id_map, &entry->client_id_node);
    urpc_hmap_remove(&g_urpc_keepalive_mgmt.server_info_map, &entry->server_info_node);

    entry->has_client = URPC_FALSE;
    if (entry->has_server == URPC_TRUE) {
        entry->primary_is_server = URPC_TRUE;
    }
    entry->client_status = URPC_KEEPALIVE_TASK_STOPPED;

    URPC_LIB_LOG_INFO("keepalive delete logic client successful, client chid[%u], server chid[%u], " EID_FMT
                       ", pid: %u\n",
        entry->client_task_id.client_chid, entry->client_task_id.server_chid, EID_ARGS(key->eid), key->pid);

    return;
}

// when client/server manage channel destroy
void urpc_keepalive_task_delete(urpc_instance_key_t *key, urpc_keepalive_task_info_t *info)
{
    urpc_keepalive_task_entry_t *entry;

    (void)pthread_rwlock_wrlock(&g_urpc_keepalive_mgmt.lock);
    entry = urpc_keepalive_task_lookup(key);
    if (entry == NULL) {
        (void)pthread_rwlock_unlock(&g_urpc_keepalive_mgmt.lock);
        URPC_LIB_LOG_INFO("find keepalive task miss, client chid[%u] server chid[%u], " EID_FMT ", pid: %u\n",
                          info->client_chid, info->server_chid, EID_ARGS(key->eid), key->pid);
        return;
    }

    (void)pthread_spin_lock(&entry->lock);
    if (!is_urpc_keepalive_entry_id_same(info, entry)) {
        URPC_LIB_LOG_WARN("keepalive task chid has changed, client chid[%u] server chid[%u], " EID_FMT
                          ", pid: %u\n", info->client_chid, info->server_chid, EID_ARGS(key->eid), key->pid);
    }

    if (info->is_server == URPC_TRUE && entry->has_server == URPC_TRUE) {
        urpc_keepalive_task_delete_logic_server(&entry->key, entry);
    } else if (info->is_server == URPC_FALSE && entry->has_client == URPC_TRUE) {
        urpc_keepalive_task_delete_logic_client(&entry->key, entry);
    } else {
        URPC_LIB_LOG_WARN(
            "no keepalive task created currently, local is %s, client chid[%u], server chid[%u], " EID_FMT
            ", pid: %u\n", info->is_server == URPC_TRUE ? "server" : "client", info->client_chid, info->server_chid,
            EID_ARGS(key->eid), key->pid);
    }

    if (entry->has_client == URPC_FALSE && entry->has_server == URPC_FALSE) {
        URPC_LIB_LOG_INFO("delete keepalive task successful, client chid[%u], server chid[%u], " EID_FMT
                          ", pid: %u\n", info->client_chid, info->server_chid, EID_ARGS(key->eid), key->pid);
    }

    (void)pthread_spin_unlock(&entry->lock);

    if (entry->has_client == URPC_FALSE && entry->has_server == URPC_FALSE) {
        urpc_keepalive_task_free(entry);
    }

    (void)pthread_rwlock_unlock(&g_urpc_keepalive_mgmt.lock);
}

int keepalive_task_restart(urpc_instance_key_t *key, urpc_keepalive_task_info_t *info)
{
    int ret = URPC_FAIL;
    urpc_keepalive_task_entry_t *entry;

    (void)pthread_rwlock_wrlock(&g_urpc_keepalive_mgmt.lock);
    entry = urpc_keepalive_task_lookup(key);
    if (entry == NULL) {
        URPC_LIB_LOG_ERR(
            "restart keepalive task failed, can't find task, client chid[%u] server chid[%u], " EID_FMT
            ", pid: %u\n", info->client_chid, info->server_chid, EID_ARGS(key->eid), key->pid);
        goto MGMT_UNLOCK;
    }

    (void)pthread_spin_lock(&entry->lock);
    bool task_id_changed = !is_urpc_keepalive_entry_id_same(info, entry);
    if (task_id_changed) {
        URPC_LIB_LOG_WARN("keepalive task chid has changed, client chid[%u] server chid[%u], " EID_FMT
                          ", pid: %u\n", info->client_chid, info->server_chid, EID_ARGS(key->eid), key->pid);
    }

    // logic client restart keepalive probe
    if ((info->is_server == URPC_FALSE) && (entry->has_client == URPC_TRUE)) {
        if (task_id_changed) {
            // remove old id_node, and then update new id_node
            urpc_hmap_remove(&g_urpc_keepalive_mgmt.client_id_map, &entry->client_id_node);

            urpc_keepalive_id_fill(&entry->client_task_id, info->client_chid, info->server_chid);
            uint32_t id_hash = urpc_hash_uint64(entry->client_task_id.id);
            urpc_hmap_insert(&g_urpc_keepalive_mgmt.client_id_map, &entry->client_id_node, id_hash);
        }

        ret = urpc_keepalive_probe_start(&entry->key, entry);
        if (ret != URPC_SUCCESS) {
            goto ENTRY_UNLOCK;
        }
        entry->client_status = URPC_KEEPALIVE_TASK_RUNNING;
    }

    // logic server add to reachable list
    if ((info->is_server == URPC_TRUE) && (entry->has_server == URPC_TRUE)) {
        if (task_id_changed) {
            // remove old id_node, and then update new id_node
            urpc_hmap_remove(&g_urpc_keepalive_mgmt.server_id_map, &entry->server_id_node);

            urpc_keepalive_id_fill(&entry->server_task_id, info->client_chid, info->server_chid);
            uint32_t id_hash = urpc_hash_uint64(entry->server_task_id.id);
            urpc_hmap_insert(&g_urpc_keepalive_mgmt.server_id_map, &entry->server_id_node, id_hash);
        }

        entry->cpu_cycles = urpc_get_cpu_cycles();
        urpc_keepalive_task_reachable(entry);
    }

    ret = URPC_SUCCESS;

ENTRY_UNLOCK:
    (void)pthread_spin_unlock(&entry->lock);

MGMT_UNLOCK:
    (void)pthread_rwlock_unlock(&g_urpc_keepalive_mgmt.lock);

    return ret;
}

int keepalive_task_stop(urpc_instance_key_t *key, urpc_keepalive_task_info_t *info)
{
    int ret = URPC_FAIL;
    urpc_keepalive_task_entry_t *entry;

    (void)pthread_rwlock_wrlock(&g_urpc_keepalive_mgmt.lock);
    entry = urpc_keepalive_task_lookup(key);
    if (entry == NULL) {
        URPC_LIB_LOG_ERR("stop keepalive task failed, can't find task, client chid[%u] server chid[%u], " EID_FMT
                         ", pid: %u\n", info->client_chid, info->server_chid, EID_ARGS(key->eid), key->pid);
        goto MGMT_UNLOCK;
    }

    (void)pthread_spin_lock(&entry->lock);
    if (!is_urpc_keepalive_entry_id_same(info, entry)) {
        URPC_LIB_LOG_WARN("keepalive task chid has changed, client chid[%u] server chid[%u], " EID_FMT
                          ", pid: %u\n", info->client_chid, info->server_chid, EID_ARGS(key->eid), key->pid);
    }

    // logic client stop keepalive probe
    if ((info->is_server == URPC_FALSE) && (entry->has_client == URPC_TRUE)) {
        if (entry->timer != NULL) {
            urpc_timer_destroy(entry->timer);
            entry->timer = NULL;
        }
        entry->client_status = URPC_KEEPALIVE_TASK_STOPPED;
    }

    // logic server remove from reachable list
    if ((info->is_server == URPC_TRUE) && (entry->has_server == URPC_TRUE)) {
        if (URPC_LIKELY(urpc_list_is_in_list(&entry->list))) {
            urpc_list_remove(&entry->list);
        }
    }

    ret = URPC_SUCCESS;

    (void)pthread_spin_unlock(&entry->lock);

MGMT_UNLOCK:
    (void)pthread_rwlock_unlock(&g_urpc_keepalive_mgmt.lock);

    return ret;
}

static void urpc_keepalive_task_entry_timeout(uint64_t cur_cpu_cycles, urpc_keepalive_task_entry_t *entry)
{
    bool need_delete_task = false;
    (void)pthread_spin_lock(&entry->lock);
    // 1. release server channel resource
    for (uint8_t i = 0; i < entry->server_chid_num; i++) {
        // g_urpc_keepalive_mgmt has been locked outside, set lock_free here
        if (server_manage_channel_put(&entry->key, false, true) == 0) {
            (void)server_channel_free(entry->server_task_id.server_chid, false);
        }
        (void)server_channel_free(entry->server_chid[i], false);
    }

    // 2. keepalive callback
    urpc_keepalive_event_info_t info = {
        .user_ctx = entry->user_ctx,
        .inactivated_time = (cur_cpu_cycles - entry->cpu_cycles) / urpc_get_cpu_hz(),
        .peer_pid = entry->key.pid,
    };

    if (entry->server_chid_num != 0) {
        URPC_LIB_LOG_WARN("keepalive timeout, client chid[%u], server chid[%u], " EID_FMT
                          ", pid: %u, user info %lu, inactivated for %u seconds\n",
                          entry->server_task_id.client_chid, entry->server_task_id.server_chid,
                          EID_ARGS(entry->key.eid), entry->key.pid, info.user_ctx, info.inactivated_time);
        urpc_keepalive_callback_get()(URPC_KEEPALIVE_FAILED, info);
    }

    // 3. delete logic server, and if local has no logic client, free task
    urpc_keepalive_task_delete_logic_server(&entry->key, entry);
    need_delete_task = entry->has_client == URPC_FALSE;

    (void)pthread_spin_unlock(&entry->lock);

    if (need_delete_task) {
        urpc_keepalive_task_free(entry);
    }
}

static void urpc_keepalive_task_timeout(void)
{
    uint64_t check_time = urpc_keepalive_check_time_get() * urpc_get_cpu_hz();
    uint64_t cur_cpu_cycles = urpc_get_cpu_cycles();
    struct urpc_list list_head;
    urpc_list_init(&list_head);

    urpc_keepalive_task_entry_t *cur = NULL;
    urpc_keepalive_task_entry_t *next = NULL;

    (void)pthread_rwlock_wrlock(&g_urpc_keepalive_mgmt.lock);
    URPC_LIST_FOR_EACH_SAFE(cur, next, list, &g_urpc_keepalive_mgmt.reachable_list) {
        if (cur->has_server == URPC_FALSE) {
            continue;
        }

        // 1. current thread cpu cycles is not ahead of entry cpu cycles, or
        // 2. entry is not timeout
        if ((cur_cpu_cycles <= cur->cpu_cycles) || ((cur_cpu_cycles - cur->cpu_cycles) < check_time)) {
            break;
        }

        urpc_list_remove(&cur->list);
        urpc_list_push_back(&list_head, &cur->list);
    }

    URPC_LIST_FOR_EACH_SAFE(cur, next, list, &list_head) {
        urpc_keepalive_task_entry_timeout(cur_cpu_cycles, cur);
    }

    (void)pthread_rwlock_unlock(&g_urpc_keepalive_mgmt.lock);
}

// move to listen thread
void urpc_keepalive_check(void *args)
{
    if (urpc_role_get() == URPC_ROLE_CLIENT || !is_feature_enable(URPC_FEATURE_KEEPALIVE) ||
        urpc_state_get() != URPC_STATE_INIT) {
        return;
    }

    urpc_keepalive_task_timeout();
}

int urpc_keepalive_init(urpc_keepalive_config_t *cfg)
{
    int ret;

    ret = urpc_keepalive_task_init();
    if (ret != URPC_SUCCESS) {
        return URPC_FAIL;
    }

    ret = urpc_keepalive_probe_init(cfg);
    if (ret != URPC_SUCCESS) {
        urpc_keepalive_task_uninit();
        return URPC_FAIL;
    }

    urpc_manage_job_register(URPC_MANAGE_JOB_TYPE_LISTEN, urpc_keepalive_check, NULL, MS_PER_SEC);

    URPC_LIB_LOG_INFO("urpc keepalive init successful, cycle %us, check time %us, delay release time %us\n",
                      cfg->keepalive_cycle_time, cfg->keepalive_check_time, cfg->delay_release_time);

    return URPC_SUCCESS;
}

void urpc_keepalive_uninit(void)
{
    urpc_keepalive_probe_uninit();
    urpc_keepalive_task_uninit();
}
