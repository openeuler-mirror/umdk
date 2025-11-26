/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2024-2024. All rights reserved.
 * Description: realize server channel function
 */

#include <stdint.h>
#include "cp_vers_compat.h"
#include "crypto.h"
#include "cp.h"
#include "keepalive.h"
#include "protocol.h"
#include "server_manage_channel.h"
#include "urpc_hash.h"
#include "urpc_hmap.h"
#include "urpc_lib_log.h"
#include "urpc_framework_types.h"
#include "urpc_dbuf_stat.h"

#include "channel.h"

#define CONNECT_HMAP_NUM 512
#define SERVER_ID_MAP_NUM (8192)
#define SERVER_CHID_INSERT_MAX_RETRY_NUM (3)

typedef struct server_id_entry {
    struct urpc_hmap_node node;
    uint32_t id;
    uint32_t mapped_id;
} server_id_entry_t;

static pthread_rwlock_t g_urpc_server_channel_lock = PTHREAD_RWLOCK_INITIALIZER;
static urpc_server_channel_info_t *g_urpc_server_channels[URPC_SERVER_MAX_CHANNELS] = {0};

// if authentication is on, use random id as server_channel id sent to client, otherwise, just use server_channel->id
static struct {
    pthread_rwlock_t lock;
    struct urpc_hmap id_map;
} g_urpc_server_id_map;

static urpc_channel_id_allocator_t g_urpc_server_channel_base_id_allocator = {0};

static urpc_server_connect_table_t g_urpc_server_channel_connect_hamp = {0};

static int server_channel_id_map_init(void)
{
    if (urpc_hmap_init(&g_urpc_server_id_map.id_map, SERVER_ID_MAP_NUM) != URPC_SUCCESS) {
        URPC_LIB_LOG_ERR("init server channel id_map failed\n");
        return URPC_FAIL;
    }

    (void)pthread_rwlock_init(&g_urpc_server_id_map.lock, NULL);
    return URPC_SUCCESS;
}

static void server_channel_id_map_uninit(void)
{
    server_id_entry_t *cur, *next;
    URPC_HMAP_FOR_EACH_SAFE(cur, next, node, &g_urpc_server_id_map.id_map) {
        urpc_hmap_remove(&g_urpc_server_id_map.id_map, &cur->node);
        urpc_dbuf_free(cur);
    }

    urpc_hmap_uninit(&g_urpc_server_id_map.id_map);

    (void)pthread_rwlock_destroy(&g_urpc_server_id_map.lock);
}

static server_id_entry_t *server_channel_id_map_lookup_inner(uint32_t mapped_id)
{
    uint32_t hash = urpc_hash_bytes(&mapped_id, sizeof(uint32_t), 0);
    server_id_entry_t *entry = NULL;

    URPC_HMAP_FOR_EACH_WITH_HASH(entry, node, hash, &g_urpc_server_id_map.id_map) {
        if (entry->mapped_id == mapped_id) {
            return entry;
        }
    }

    return NULL;
}

static int server_channel_id_map_insert(uint32_t id, uint32_t mapped_id)
{
    if (!crypto_is_ssl_enabled_lock_free()) {
        return URPC_SUCCESS;
    }

    server_id_entry_t *entry =
        (server_id_entry_t *)urpc_dbuf_calloc(URPC_DBUF_TYPE_CHANNEL, 1, sizeof(server_id_entry_t));
    if (entry == NULL) {
        URPC_LIB_LOG_ERR("malloc server_id_entry_t failed\n");
        return URPC_FAIL;
    }
    entry->id = id;
    entry->mapped_id = mapped_id;
    uint32_t hash = urpc_hash_bytes(&entry->mapped_id, sizeof(uint32_t), 0);

    (void)pthread_rwlock_wrlock(&g_urpc_server_id_map.lock);
    if (server_channel_id_map_lookup_inner(mapped_id) != NULL) {
        (void)pthread_rwlock_unlock(&g_urpc_server_id_map.lock);
        URPC_LIB_LOG_ERR("mapped channel id already existed, chid[%u]\n", id);
        urpc_dbuf_free(entry);
        return URPC_FAIL;
    }

    urpc_hmap_insert(&g_urpc_server_id_map.id_map, &entry->node, hash);
    (void)pthread_rwlock_unlock(&g_urpc_server_id_map.lock);

    return URPC_SUCCESS;
}

static void server_channel_id_map_remove(uint32_t mapped_id)
{
    server_id_entry_t *entry = NULL;

    (void)pthread_rwlock_wrlock(&g_urpc_server_id_map.lock);
    entry = server_channel_id_map_lookup_inner(mapped_id);
    if (entry != NULL) {
        urpc_hmap_remove(&g_urpc_server_id_map.id_map, &entry->node);
        urpc_dbuf_free(entry);
    }
    (void)pthread_rwlock_unlock(&g_urpc_server_id_map.lock);
}

uint32_t server_channel_id_map_lookup(uint32_t mapped_id)
{
    if (URPC_LIKELY(!crypto_is_ssl_enabled_lock_free())) {
        return mapped_id;
    }

    uint32_t id = URPC_INVALID_ID_U32;
    (void)pthread_rwlock_rdlock(&g_urpc_server_id_map.lock);
    server_id_entry_t *entry = server_channel_id_map_lookup_inner(mapped_id);
    if (entry != NULL) {
        id = entry->id;
    }
    (void)pthread_rwlock_unlock(&g_urpc_server_id_map.lock);
    return id;
}

void server_channel_connect_hmap_lock(void)
{
    if (!g_urpc_server_channel_connect_hamp.lock_inited) {
        return;
    }
    (void)pthread_spin_lock(&g_urpc_server_channel_connect_hamp.lock);
}

void server_channel_connect_hmap_unlock(void)
{
    if (!g_urpc_server_channel_connect_hamp.lock_inited) {
        return;
    }
    (void)pthread_spin_unlock(&g_urpc_server_channel_connect_hamp.lock);
}

static void server_channel_connect_hmap_insert(struct urpc_hmap_node *node, uint32_t hash)
{
    urpc_hmap_insert(&g_urpc_server_channel_connect_hamp.hmap, node, hash);
}

static int server_channel_connect_hmap_init(void)
{
    int ret = urpc_hmap_init(&g_urpc_server_channel_connect_hamp.hmap, CONNECT_HMAP_NUM);
    if (ret != URPC_SUCCESS) {
        URPC_LIB_LOG_ERR("init server channel connect hmap failed, ret:%d\n", ret);
        return URPC_FAIL;
    }
    (void)pthread_spin_init(&g_urpc_server_channel_connect_hamp.lock, PTHREAD_PROCESS_PRIVATE);
    g_urpc_server_channel_connect_hamp.lock_inited = true;
    return URPC_SUCCESS;
}

static void server_channel_connect_hmap_uninit(void)
{
    urpc_server_connect_entry_t *info = NULL;
    urpc_server_connect_entry_t *next = NULL;
    server_channel_connect_hmap_lock();
    URPC_HMAP_FOR_EACH_SAFE(info, next, node, &g_urpc_server_channel_connect_hamp.hmap) {
        // remove count_id
        channel_id_allocator_uninit(&info->count_id);
        urpc_dbuf_free(info);
    }
    server_channel_connect_hmap_unlock();
    pthread_spin_destroy(&g_urpc_server_channel_connect_hamp.lock);
    g_urpc_server_channel_connect_hamp.lock_inited = false;
    urpc_hmap_uninit(&g_urpc_server_channel_connect_hamp.hmap);
}

int urpc_server_channel_id_allocator_init(void)
{
    /* the logic of the channel ID allocator on the server contains 20 bits(base_id) + 4 bits(count_id). */
    // init base_id allocator
    if (channel_id_allocator_init(&g_urpc_server_channel_base_id_allocator, URPC_MAX_CLIENTS) != URPC_SUCCESS) {
        URPC_LIB_LOG_ERR("init server channel id[base id] allocator failed\n");
        return URPC_FAIL;
    }
    // init hmap info, count_id allocator will be set in here
    if (server_channel_connect_hmap_init() != URPC_SUCCESS) {
        goto ID_ALLOCATOR_UNINIT;
    }

    if (server_channel_id_map_init() != URPC_SUCCESS) {
        goto CONNECT_HMAP_UNINIT;
    }

    return URPC_SUCCESS;

CONNECT_HMAP_UNINIT:
    server_channel_connect_hmap_uninit();

ID_ALLOCATOR_UNINIT:
    channel_id_allocator_uninit(&g_urpc_server_channel_base_id_allocator);

    return URPC_FAIL;
}

void urpc_server_channel_id_allocator_uninit(void)
{
    server_channel_id_map_uninit();
    // uninit base_id allocator
    channel_id_allocator_uninit(&g_urpc_server_channel_base_id_allocator);
    // uninit hmap info and count_id allocator
    server_channel_connect_hmap_uninit();
}

static urpc_server_connect_entry_t *server_channel_connect_entry_get(urpc_instance_key_t *key, uint32_t hash)
{
    urpc_server_connect_entry_t *info = NULL;
    URPC_HMAP_FOR_EACH_WITH_HASH(info, node, hash, &g_urpc_server_channel_connect_hamp.hmap) {
        if (urpc_instance_key_cmp(key, &info->key)) {
            return info;
        }
    }
    return NULL;
}

static uint32_t server_channel_connect_hmap_id_get(urpc_server_connect_entry_t *info)
{
    uint32_t id = URPC_SERVER_MAX_CHANNELS;
    uint32_t count_id = channel_id_allocator_get(&info->count_id, URPC_MAX_CHANNEL_PER_CLIENT);
    if (count_id >= URPC_MAX_CHANNEL_PER_CLIENT) {
        URPC_LIB_LOG_ERR("The number of connections from this client reaches the upper limit\n");
        return id;
    }
    id = (info->base_id << URPC_BASE_ID_OFFSETS) + count_id;
    return id;
}

static uint32_t server_channel_connect_alloc_id(urpc_instance_key_t *key, uint32_t hash)
{
    uint32_t id = URPC_SERVER_MAX_CHANNELS;
    urpc_server_connect_entry_t *info = (urpc_server_connect_entry_t *)urpc_dbuf_calloc(URPC_DBUF_TYPE_CHANNEL,
        1, sizeof(urpc_server_connect_entry_t));
    if (info == NULL) {
        URPC_LIB_LOG_ERR("malloc connect client info failed, errno:%d\n", errno);
        return id;
    }
    info->key = *key;
    info->base_id = channel_id_allocator_get(&g_urpc_server_channel_base_id_allocator, URPC_MAX_CLIENTS);
    if (info->base_id >= URPC_MAX_CLIENTS) {
        URPC_LIB_LOG_ERR("The number of connections reaches the upper limit, base id[%u]\n", info->base_id);
        urpc_dbuf_free(info);
        return id;
    }
    // init count_id allocator
    info->count_id.available_ids = NULL;
    if (channel_id_allocator_init(&info->count_id, URPC_MAX_CHANNEL_PER_CLIENT) != URPC_SUCCESS) {
        URPC_LIB_LOG_ERR("init count id allocator failed\n");
        channel_id_allocator_release(&g_urpc_server_channel_base_id_allocator, URPC_MAX_CLIENTS, info->base_id);
        urpc_dbuf_free(info);
        return id;
    }

    id = (info->base_id << URPC_BASE_ID_OFFSETS) + info->count_id.next_id;
    info->count_id.next_id = 1;
    server_channel_connect_hmap_insert(&info->node, hash);

    return id;
}

static int local_queue_unpair_by_qid(uint16_t qid)
{
    int ret = URPC_SUCCESS;
    queue_local_t *local_q;
    queue_transport_ctx_t *queue_ctx = get_queue_transport_ctx();
    (void)pthread_mutex_lock(&queue_ctx->queue_list_mutex);
    URPC_LIST_FOR_EACH(local_q, node, &queue_ctx->queue_list) {
        if (local_q->qid == qid && local_q->is_binded == URPC_TRUE) {
            ret = local_q->queue.ops->unbind_queue(&local_q->queue);
            (void)pthread_mutex_unlock(&queue_ctx->queue_list_mutex);
            return ret;
        }
    }
    (void)pthread_mutex_unlock(&queue_ctx->queue_list_mutex);
    URPC_LIB_LOG_INFO("not find queue %u\n", qid);
    return ret;
}

void server_channel_remove_remote_queue(urpc_server_channel_info_t *channel, queue_node_t *cur_node)
{
    queue_remote_t *remote_q = (queue_remote_t *)(uintptr_t)cur_node->urpc_qh;
    queue_t *queue = &remote_q->queue;
    URPC_SLIST_REMOVE(&channel->r_queue_nodes_head, cur_node, queue_node, node);
    if (local_queue_unpair_by_qid(remote_q->bind_local_qid) != URPC_SUCCESS) {
        URPC_LIB_LOG_ERR("queue %u unpair failed\n", remote_q->bind_local_qid);
    }
    queue->ops->unimport_remote_queue(queue);
    /* server remote queue should be deleted when channel is freed */
    queue->ops->delete_remote_queue(queue);
    urpc_dbuf_free(cur_node);
}

// Return the removed channel with write locked
static urpc_server_channel_info_t *server_channel_get_and_remove(uint32_t urpc_chid, bool skip_manage)
{
    int ret = -1;
    urpc_server_channel_info_t *channel = NULL;
    while (ret != 0) {
        (void)pthread_rwlock_wrlock(&g_urpc_server_channel_lock);
        channel = g_urpc_server_channels[urpc_chid];
        if (channel == NULL || (skip_manage && channel->attr == URPC_ATTR_MANAGE)) {
            (void)pthread_rwlock_unlock(&g_urpc_server_channel_lock);
            return NULL;
        }
        // channel may be used by other threads，wait to remove
        (ret = pthread_rwlock_trywrlock(&channel->rw_lock)) == 0 ? g_urpc_server_channels[urpc_chid] = NULL : 0;
        (void)pthread_rwlock_unlock(&g_urpc_server_channel_lock);
    }

    return channel;
}

static int server_channel_set_user_ctx(uint32_t id, uint64_t user_ctx)
{
    urpc_server_connect_entry_t *info = NULL;
    urpc_server_connect_entry_t *next = NULL;
    uint32_t base_id = (id >> URPC_BASE_ID_OFFSETS);
    URPC_HMAP_FOR_EACH_SAFE(info, next, node, &g_urpc_server_channel_connect_hamp.hmap) {
        if (info->base_id == base_id) {
            if (info->user_ctx != user_ctx) {
                URPC_LIB_LOG_DEBUG("server channel set user context, base id: %u, user ctx: %lu\n", base_id, user_ctx);
            }
            info->user_ctx = user_ctx;
            return URPC_SUCCESS;
        }
    }
    return URPC_FAIL;
}

static uint32_t server_channel_id_get(urpc_instance_key_t *key)
{
    /* the logic of the channel ID allocator on the server contains 20 bits(base_id) + 4 bits(count_id). */
    uint32_t hash = urpc_instance_key_hash(key);
    urpc_server_connect_entry_t *info = server_channel_connect_entry_get(key, hash);
    if (info == NULL) {
        return server_channel_connect_alloc_id(key, hash);
    }
    return server_channel_connect_hmap_id_get(info);
}

uint32_t urpc_server_channel_id_all_get(urpc_instance_key_t *key, uint32_t *server_chids, uint32_t server_chids_max_num)
{
    /* the logic of the channel ID allocator on the server contains 20 bits(base_id) + 4 bits(count_id). */
    uint32_t hash = urpc_instance_key_hash(key);
    urpc_server_connect_entry_t *info = server_channel_connect_entry_get(key, hash);
    if (info == NULL) {
        return 0;
    }

    uint32_t idx = 0;
    (void)pthread_rwlock_rdlock(&g_urpc_server_channel_lock);
    for (uint32_t i = 0; i < URPC_MAX_CHANNEL_PER_CLIENT && idx < server_chids_max_num; ++i) {
        uint32_t cur_chid = (info->base_id << URPC_BASE_ID_OFFSETS) + i;
        if (g_urpc_server_channels[cur_chid] == NULL) {
            continue;
        } else if (g_urpc_server_channels[cur_chid]->attr == URPC_ATTR_MANAGE) {
            // ensure the manage server channel is put at server_chids[0]
            server_chids[idx++] = server_chids[0];
            server_chids[0] = cur_chid;
        } else {
            server_chids[idx++] = cur_chid;
        }
    }
    (void)pthread_rwlock_unlock(&g_urpc_server_channel_lock);
    return idx;
}

static void server_channel_id_release(uint32_t urpc_chid, urpc_instance_key_t *key, bool lock_free)
{
    /* the logic of the channel ID allocator on the server contains 20 bits(base_id) + 4 bits(count_id). */
    uint32_t count_id = urpc_chid & 0xF;
    uint32_t base_id = urpc_chid >> URPC_BASE_ID_OFFSETS;
    uint32_t hash = urpc_instance_key_hash(key);
    lock_free ? 0 : server_channel_connect_hmap_lock();
    urpc_server_connect_entry_t *info = server_channel_connect_entry_get(key, hash);
    if (info == NULL) {
        URPC_LIB_LOG_DEBUG("find connect hmap info failed\n");
        lock_free ? 0 : server_channel_connect_hmap_unlock();
        return;
    }
    if (info->base_id == base_id) {
        channel_id_allocator_release(&info->count_id, URPC_MAX_CHANNEL_PER_CLIENT, count_id);
        if (info->count_id.num_available == info->count_id.next_id) { // all ids for this client are released
            channel_id_allocator_uninit(&info->count_id);
            urpc_hmap_remove(&g_urpc_server_channel_connect_hamp.hmap, &info->node);
            urpc_dbuf_free(info);
            channel_id_allocator_release(&g_urpc_server_channel_base_id_allocator, URPC_MAX_CLIENTS, base_id);
        }
    }
    lock_free ? 0 : server_channel_connect_hmap_unlock();
}

// The alloced channel is write locked to avoid being cleared by other threads
urpc_server_channel_info_t *server_channel_alloc(urpc_instance_key_t *key, uint64_t user_ctx)
{
    urpc_server_channel_info_t *info = (urpc_server_channel_info_t *)urpc_dbuf_calloc(URPC_DBUF_TYPE_CHANNEL,
        1, sizeof(urpc_server_channel_info_t));
    if (info == NULL) {
        URPC_LIB_LOG_ERR("malloc server channel info failed\n");
        return NULL;
    }
    if (crypto_is_dp_ssl_enabled()) {
        info->cipher_opt = (urpc_cipher_t *)urpc_dbuf_calloc(URPC_DBUF_TYPE_ENCRYPT, 1, sizeof(urpc_cipher_t));
        if (info->cipher_opt == NULL) {
            urpc_dbuf_free(info);
            URPC_LIB_LOG_ERR("malloc cipher_opt for server channel failed\n");
            return NULL;
        }
        info->cipher_opt->chid = URPC_INVALID_ID_U32;
    }

    info->id = server_channel_id_get(key);
    info->manage_chid = URPC_INVALID_ID_U32;
    info->keepalive_attr = user_ctx;
    if (info->id >= URPC_SERVER_MAX_CHANNELS) {
        URPC_LIB_LOG_ERR("server channel ID exceeds upper limit, id[%u], chid upper limit[%u]\n",
            info->id, URPC_SERVER_MAX_CHANNELS);
        goto ERROR;
    }
    memcpy(&(info->key), key, sizeof(urpc_instance_key_t));

    int ret = URPC_FAIL;
    for (uint8_t retry_cnt = 0; retry_cnt < SERVER_CHID_INSERT_MAX_RETRY_NUM; ++retry_cnt) {
        info->mapped_id = crypto_gen_rand_channel_id(info->id);
        if ((ret = server_channel_id_map_insert(info->id, info->mapped_id)) == URPC_SUCCESS) {
            break;
        }
    }
    if (URPC_UNLIKELY(ret != URPC_SUCCESS)) {
        URPC_LIB_LOG_ERR(
            "insert server channel into id_map failed, has retried for %d times\n", SERVER_CHID_INSERT_MAX_RETRY_NUM);
        goto RELEASE_ID;
    }

    URPC_SLIST_INIT(&info->r_queue_nodes_head);
    urpc_list_init(&info->mem_key_list);
    (void)pthread_rwlock_init(&info->rw_lock, NULL);
    server_channel_set_user_ctx(info->id, user_ctx);

    (void)pthread_rwlock_wrlock(&g_urpc_server_channel_lock);
    g_urpc_server_channels[info->id] = info;
    (void)pthread_rwlock_wrlock(&info->rw_lock);
    (void)pthread_rwlock_unlock(&g_urpc_server_channel_lock);

    URPC_LIB_LOG_DEBUG("create server channel[%u] successful\n", info->id);
    return info;

RELEASE_ID:
    server_channel_id_release(info->id, key, false);
ERROR:
    urpc_dbuf_free(info->cipher_opt);
    urpc_dbuf_free(info);
    return NULL;
}

// Get a server channel which has been locked. It's safe to read g_urpc_server_channels without lock
urpc_server_channel_info_t *server_channel_get(uint32_t urpc_chid)
{
    if (urpc_chid >= URPC_SERVER_MAX_CHANNELS) {
        URPC_LIB_LOG_ERR("server channel id invalid\n");
        return NULL;
    }

    return g_urpc_server_channels[urpc_chid];
}

// Get server channel with read_write locked. Avoid the concurrence of using and deleting.
urpc_server_channel_info_t *server_channel_get_with_rw_lock(uint32_t urpc_chid, bool is_write)
{
    if (urpc_chid >= URPC_SERVER_MAX_CHANNELS) {
        URPC_LIB_LIMIT_LOG_ERR("server channel id invalid\n");
        return NULL;
    }

    urpc_server_channel_info_t *channel = NULL;
    int ret = -1;
    while (ret != 0) {
        (void)pthread_rwlock_rdlock(&g_urpc_server_channel_lock);
        channel = g_urpc_server_channels[urpc_chid];
        if (channel != NULL) {
            ret = is_write ? pthread_rwlock_trywrlock(&channel->rw_lock) : pthread_rwlock_tryrdlock(&channel->rw_lock);
        } else {
            (void)pthread_rwlock_unlock(&g_urpc_server_channel_lock);
            break;
        }
        (void)pthread_rwlock_unlock(&g_urpc_server_channel_lock);
    }

    return channel;
}

static void server_channel_get_queue_trans_info_size(urpc_server_channel_info_t *server_channel, uint32_t *output_size,
                                                     uint32_t *queue_cnt)
{
    uint32_t output_size_ = 0;
    uint32_t queue_cnt_ = 0;
    queue_node_t *cur_node;
    URPC_SLIST_FOR_EACH(cur_node, &server_channel->r_queue_nodes_head, node) {
        queue_t *queue = (queue_t *)(uintptr_t)cur_node->urpc_qh;
        output_size_ += queue->ops->query_trans_info(queue, QUEUE_QUERY_TRANS_INFO_SIZE, NULL);
        queue_cnt_++;
    }

    *output_size = output_size_;
    *queue_cnt = queue_cnt_;
}

static int server_channel_get_queue_trans_info_fill_with_output(urpc_server_channel_info_t *server_channel,
                                                                uint32_t output_size, char *output)
{
    queue_node_t *cur_node;
    uint32_t offset = 0;
    URPC_SLIST_FOR_EACH(cur_node, &server_channel->r_queue_nodes_head, node) {
        if (offset >= output_size) {
            URPC_LIB_LOG_ERR("Exceed query output size\n");
            return URPC_FAIL;
        }

        queue_t *queue = (queue_t *)(uintptr_t)cur_node->urpc_qh;
        offset += queue->ops->query_trans_info(queue, QUEUE_QUERY_TRANS_INFO_DATA, output + offset);
    }

    return URPC_SUCCESS;
}

int server_channel_get_queue_trans_info(uint32_t urpc_chid, char **output, uint32_t *output_size)
{
    urpc_server_channel_info_t *server_channel = server_channel_get_with_rw_lock(urpc_chid, false);
    if (server_channel == NULL) {
        URPC_LIB_LOG_ERR("Failed to get server channel[%u]\n", urpc_chid);
        return URPC_FAIL;
    }

    uint32_t output_size_ = 0;
    uint32_t queue_cnt_ = 0;
    server_channel_get_queue_trans_info_size(server_channel, &output_size_, &queue_cnt_);

    char *output_ = (char *)urpc_dbuf_malloc(URPC_DBUF_TYPE_CHANNEL, output_size_);
    if (output_ == NULL) {
        (void)pthread_rwlock_unlock(&server_channel->rw_lock);
        URPC_LIB_LOG_ERR("Failed to malloc, errno: %d\n", errno);
        return -URPC_ERR_ENOMEM;
    }

    if (server_channel_get_queue_trans_info_fill_with_output(server_channel, output_size_, output_) != URPC_SUCCESS) {
        (void)pthread_rwlock_unlock(&server_channel->rw_lock);
        urpc_dbuf_free(output_);
        URPC_LIB_LOG_ERR("Exceed query output size\n");
        return URPC_FAIL;
    }

    (void)pthread_rwlock_unlock(&server_channel->rw_lock);

    *output = output_;
    *output_size = output_size_;

    return URPC_SUCCESS;
}

static int server_channel_add_remote_queue(
    urpc_server_channel_info_t *channel, queue_info_t *queue_info, batch_queue_import_ctx_t *ctx)
{
    queue_ops_t *ops = queue_get_ops(queue_info->trans_mode);
    if (ops == NULL) {
        URPC_LIB_LOG_ERR("get queue ops failed\n");
        return URPC_FAIL;
    }

    queue_t *queue = NULL;

    provider_t *provider = NULL;
    urpc_list_t *provider_list = get_provider_list();
    URPC_LIST_FOR_EACH(provider, node, provider_list)
    {
        queue = ops->create_remote_queue(queue_info, channel->id, 0);
        if (queue == NULL) {
            URPC_LIB_LOG_ERR("create remote queue failed\n");
            return URPC_FAIL;
        }
        // import send success, add to ctx
        queue_import_async_info_t *async_info =
            (queue_import_async_info_t *)urpc_dbuf_calloc(URPC_DBUF_TYPE_CHANNEL, 1, sizeof(queue_import_async_info_t));
        if (async_info == NULL) {
            ops->delete_remote_queue(queue);
            URPC_LIB_LOG_ERR("malloc queue node failed\n");
            return URPC_FAIL;
        }
        async_info->provider = provider;
        async_info->queue_handle = (uint64_t)(uintptr_t)queue;
        async_info->status = QUEUE_IMPORT_INIT;
        async_info->task = ctx->task;
        int ret = URPC_SUCCESS;
        ret = queue->ops->import_remote_queue(queue, provider);
        if (ret == URPC_SUCCESS) {
            async_info->status = QUEUE_IMPORT_SUCCESS;
            urpc_list_push_back(&ctx->import_list, &async_info->node);
            continue;
        }
        if (ret != URPC_RUNNING) {
            URPC_LIB_LOG_ERR("send import remote queue failed, ret:%d\n", ret);
            urpc_dbuf_free(async_info);
            ops->delete_remote_queue(queue);
            return URPC_FAIL;
        }
        ctx->running_count++;
        async_info->status = QUEUE_IMPORT_RUNNING;
        urpc_list_push_back(&ctx->import_list, &async_info->node);
    }
    if (ctx->running_count == 0) {
        return URPC_SUCCESS;
    }
    return URPC_RUNNING;
}

static int server_channel_post_add_remote_queue_async(
    urpc_server_channel_info_t *channel, queue_import_async_info_t *entry)
{
    queue_node_t *node = NULL;
    queue_t *queue = (queue_t *)(uintptr_t)entry->queue_handle;

    if (entry->status == QUEUE_IMPORT_FAIL) {
        goto DELETE_REMOTE_QUEUE;
    }

    node = (queue_node_t *)urpc_dbuf_malloc(URPC_DBUF_TYPE_CHANNEL, sizeof(queue_node_t));
    if (node == NULL) {
        URPC_LIB_LOG_ERR("malloc queue node failed\n");
        goto UNIMPORT_REMOTE_QUEUE;
    }
    node->node.next = NULL;
    node->urpc_qh = (uint64_t)(uintptr_t)queue;
    queue->ref_cnt = 1;
    URPC_SLIST_INSERT_HEAD(&channel->r_queue_nodes_head, node, node);

    return URPC_SUCCESS;

UNIMPORT_REMOTE_QUEUE:
    queue->ops->unimport_remote_queue(queue);
DELETE_REMOTE_QUEUE:
    queue->ops->delete_remote_queue(queue);
    return URPC_FAIL;
}

int server_channel_free(uint32_t urpc_chid, bool lock_free)
{
    if (urpc_chid >= URPC_SERVER_MAX_CHANNELS) {
        URPC_LIB_LOG_ERR("server channel id invalid\n");
        return -URPC_ERR_EINVAL;
    }

    urpc_server_channel_info_t *channel = server_channel_get_and_remove(urpc_chid, false);
    if (channel == NULL) {
        return -URPC_ERR_EINVAL;
    }
    if (urpc_list_is_in_list(&channel->node)) {
        urpc_list_remove(&channel->node);
    }
    urpc_instance_key_t key = {.eid = channel->key.eid, .pid = channel->key.pid};
    queue_node_t *cur_node, *next_node;
    URPC_SLIST_FOR_EACH_SAFE(cur_node, &channel->r_queue_nodes_head, node, next_node) {
        server_channel_remove_remote_queue(channel, cur_node);
    }

    mem_entry_key_node_t *cur_mem_entry, *next_mem_entry;
    URPC_LIST_FOR_EACH_SAFE(cur_mem_entry, next_mem_entry, node, &channel->mem_key_list) {
        (void)urpc_mem_unimport(urpc_chid, cur_mem_entry->mem_key.token_id, cur_mem_entry->mem_key.token_value);
        urpc_list_remove(&cur_mem_entry->node);
        urpc_dbuf_free(cur_mem_entry);
    }
    (void)pthread_rwlock_unlock(&channel->rw_lock);

    (void)pthread_rwlock_destroy(&channel->rw_lock);
    server_channel_id_map_remove(channel->mapped_id);
    crypto_cipher_uninit(channel->cipher_opt);
    urpc_dbuf_free(channel->cipher_opt);
    urpc_dbuf_free(channel);
    server_channel_id_release(urpc_chid, &key, lock_free);
    URPC_LIB_LOG_INFO("free server channel[%u] successful\n", urpc_chid);

    return URPC_SUCCESS;
}

int server_channel_add_new_remote_queue_async(
    urpc_server_channel_info_t *channel, queue_info_t *queue_info, batch_queue_import_ctx_t *ctx)
{
    queue_node_t *cur_node;
    URPC_SLIST_FOR_EACH(cur_node, &channel->r_queue_nodes_head, node)
    {
        queue_t *queue = (queue_t *)(uintptr_t)cur_node->urpc_qh;
        if (queue->ops->is_same_queue(queue, queue_info, QUEUE_AUTHN_BY_QUEUE_INFO)) {
            if (urpc_list_is_empty(&ctx->list)) {
                queue->ref_cnt++;
            }
            URPC_LIB_LOG_INFO("refresh remote queue to add in channel[%u] already exist\n", channel->id);
            return URPC_SUCCESS;
        }
    }
    return server_channel_add_remote_queue(channel, queue_info, ctx);
}

int server_channel_put_remote_queue_async(uint32_t server_chid, void *chmsg_input, batch_queue_import_ctx_t *ctx)
{
    int ret = URPC_SUCCESS;
    urpc_chmsg_v1_t *chmsg = (urpc_chmsg_v1_t *)chmsg_input;
    if (chmsg == NULL) {
        return URPC_SUCCESS;
    }

    urpc_server_channel_info_t *server_channel = server_channel_get_with_rw_lock(server_chid, true);
    if (server_channel == NULL) {
        return URPC_FAIL;
    }

    uint32_t queue_num = chmsg->qinfo_arr.arr_num;
    if (URPC_SLIST_EMPTY(&server_channel->r_queue_nodes_head)) {
        // this is a new client
        for (uint32_t i = 0; i < queue_num; i++) {
            ret = server_channel_add_new_remote_queue_async(server_channel, chmsg->qinfo_arr.qinfos[i], ctx);
            if (ret != URPC_SUCCESS && ret != URPC_RUNNING) {
                break;
            }

            if (i == queue_num - 1) {
                break;
            }
        }
        (void)pthread_rwlock_unlock(&server_channel->rw_lock);

        return ret;
    }

    queue_node_t *cur_node, *next_node;
    URPC_SLIST_FOR_EACH_SAFE(cur_node, &server_channel->r_queue_nodes_head, node, next_node) {
        queue_t *remote_q = (queue_t *)(uintptr_t)cur_node->urpc_qh;
       // the old chain-building process need is_remote_queue_in_queue_info func to check
        if ((!urpc_list_is_empty(&ctx->list) && !is_remote_queue_in_queue_info(remote_q, chmsg_input))) {
            server_channel_remove_remote_queue(server_channel, cur_node);
        }
    }

    // add new remote queue
    for (uint32_t i = 0; i < queue_num; i++) {
        // no need to remove remote queue which has been successfully added, because server channel will be
        // destroyed after keepalive timeout, or client will attach again
        ret = server_channel_add_new_remote_queue_async(server_channel, chmsg->qinfo_arr.qinfos[i], ctx);
        if (ret != URPC_SUCCESS && ret != URPC_RUNNING) {
            break;
        }

        if (i == queue_num - 1) {
            break;
        }
    }
    (void)pthread_rwlock_unlock(&server_channel->rw_lock);

    return ret;
}

int server_channel_post_put_remote_queue(uint32_t server_chid, batch_queue_import_ctx_t *ctx)
{
    urpc_server_channel_info_t *server_channel = server_channel_get_with_rw_lock(server_chid, true);
    if (server_channel == NULL) {
        return URPC_FAIL;
    }

    int result = URPC_SUCCESS;
    queue_import_async_info_t *import_cur = NULL;
    queue_import_async_info_t *import_next = NULL;

    URPC_LIST_FOR_EACH_SAFE(import_cur, import_next, node, &ctx->import_list)
    {
        if (server_channel_post_add_remote_queue_async(server_channel, import_cur) != URPC_SUCCESS) {
            result = URPC_FAIL;
        }
        urpc_list_remove(&import_cur->node);
        urpc_dbuf_free(import_cur);
    }
    (void)pthread_rwlock_unlock(&server_channel->rw_lock);
    return result;
}

void server_channel_unlock(uint32_t server_chid)
{
    urpc_server_channel_info_t *server_channel = server_channel_get(server_chid);
    if (server_channel == NULL) {
        URPC_LIB_LOG_DEBUG("server channel %u is not found, unlock failed\n", server_chid);
        return;
    }
    (void)pthread_rwlock_unlock(&server_channel->rw_lock);
}

// Once the r_queue is found, the corresponding server channel is read locked until the r_queue is not used anymore.
queue_t *server_channel_search_remote_queue(uint32_t server_chid, queue_t *l_queue, queue_t *q_src)
{
    if (server_chid == URPC_INVALID_ID_U32 || q_src == NULL) {
        URPC_LIB_LOG_ERR("parameter invalid\n");
        return NULL;
    }

    urpc_server_channel_info_t *server_channel = server_channel_get_with_rw_lock(server_chid, false);
    if (server_channel == NULL) {
        URPC_LIB_LOG_ERR("get server channel[%u] failed\n", server_chid);
        return NULL;
    }

    queue_node_t *cur_node;
    URPC_SLIST_FOR_EACH(cur_node, &server_channel->r_queue_nodes_head, node) {
        queue_t *queue = (queue_t *)(uintptr_t)cur_node->urpc_qh;
        if (l_queue->provider != queue->provider || queue->status == QUEUE_STATUS_ERR) {
            continue;
        }

        if (queue->ops->is_same_queue(queue, q_src, QUEUE_AUTHN_BY_QUEUE)) {
            return queue;
        }
    }
    (void)pthread_rwlock_unlock(&server_channel->rw_lock);
    URPC_LIB_LOG_DEBUG("lookup remote queue failed, server_chid = %u, attr = %d\n", server_chid, server_channel->attr);
    return NULL;
}

// Once the r_queue is found, the corresponding server channel is read locked until the r_queue is not used anymore.
queue_t *server_channel_search_remote_queue_by_flag(uint32_t server_chid, urpc_queue_flag_t flag)
{
    if (server_chid == URPC_INVALID_ID_U32) {
        URPC_LIB_LOG_ERR("parameter invalid\n");
        return NULL;
    }

    urpc_server_channel_info_t *server_channel = server_channel_get_with_rw_lock(server_chid, false);
    if (server_channel == NULL) {
        URPC_LIB_LOG_ERR("get server channel[%u] failed\n", server_chid);
        return NULL;
    }

    queue_node_t *cur_node;
    URPC_SLIST_FOR_EACH(cur_node, &server_channel->r_queue_nodes_head, node) {
        queue_t *queue = (queue_t *)(uintptr_t)cur_node->urpc_qh;
        if (is_queue_flag_same(queue->flag, flag)) {
            if (queue->status == QUEUE_STATUS_ERR) {
                URPC_LIB_LOG_DEBUG("queue status not ready\n");
            } else {
                return queue;
            }
        }
    }
    (void)pthread_rwlock_unlock(&server_channel->rw_lock);
    URPC_LIB_LOG_DEBUG("lookup remote queue by queue flag failed, server_chid = %u\n", server_chid);
    return NULL;
}

int server_channel_cipher_init(urpc_server_channel_info_t *channel, crypto_key_t *crypto_key)
{
    if (channel->cipher_opt->chid != URPC_INVALID_ID_U32) {
        return URPC_SUCCESS;
    }

    if (crypto_cipher_init(channel->cipher_opt, crypto_key) != URPC_SUCCESS) {
        URPC_LIB_LOG_ERR("init cipher for server channel failed\n");
        return URPC_FAIL;
    }
    channel->cipher_opt->chid = channel->id;
    return URPC_SUCCESS;
}

int server_channel_import_rollback(uint32_t urpc_chid, queue_info_t *queue_info)
{
    urpc_server_channel_info_t *server_channel = server_channel_get_with_rw_lock(urpc_chid, true);
    if (server_channel == NULL) {
        return URPC_FAIL;
    }
    queue_node_t *cur_node = NULL;
    queue_node_t *next_node = NULL;
    URPC_SLIST_FOR_EACH_SAFE(cur_node, &server_channel->r_queue_nodes_head, node, next_node)
    {
        queue_t *queue = (queue_t *)(uintptr_t)cur_node->urpc_qh;
        if (queue->ops->is_same_queue(queue, queue_info, QUEUE_AUTHN_BY_QUEUE_INFO)) {
            if (queue->ref_cnt > 0) {
                queue->ref_cnt--;
            }
            if (queue->ref_cnt != 0) {
                URPC_LIB_LOG_DEBUG("remove remote queue, ref_cnt[%u]\n", queue->ref_cnt);
                continue;
            }
            server_channel_remove_remote_queue(server_channel, cur_node);
        }
    }
    (void)pthread_rwlock_unlock(&server_channel->rw_lock);
    return URPC_SUCCESS;
}

int server_channel_add_client_chid(urpc_server_channel_info_t *server_channel, uint32_t client_chid)
{
    uint32_t *client_chid_ptr = server_channel->client_chid;
    for (uint32_t i = 0; i < server_channel->client_chid_num; i++) {
        if (client_chid_ptr[i] == client_chid) {
            return URPC_SUCCESS;
        }
    }

    if (server_channel->client_chid_num >= URPC_MAX_CLIENT_CHANNELS_PER_CLIENT) {
        return URPC_FAIL;
    }

    client_chid_ptr[server_channel->client_chid_num++] = client_chid;
    return URPC_SUCCESS;
}

void server_channel_rm_client_chid(urpc_server_channel_info_t *server_channel, uint32_t client_chid)
{
    uint32_t *client_chid_ptr = server_channel->client_chid;
    uint32_t new_pos = 0;
    for (uint32_t i = 0; i < server_channel->client_chid_num; i++) {
        if (client_chid_ptr[i] != client_chid) {
            client_chid_ptr[new_pos++] = client_chid_ptr[i];
        }
    }
    server_channel->client_chid_num = new_pos;
}

int server_channel_add_mem(urpc_server_channel_info_t *server_channel, xchg_mem_info_t *xchg_mem)
{
    mem_entry_key_node_t *key_node =
        (mem_entry_key_node_t *)urpc_dbuf_malloc(URPC_DBUF_TYPE_CHANNEL, sizeof(mem_entry_key_node_t));
    if (key_node == NULL) {
        URPC_LIB_LOG_ERR("memory alloc failed\n");
        return -URPC_ERR_ENOMEM;
    }
    key_node->mem_key.token_id = xchg_mem->seg_token_id;
    key_node->mem_key.token_value = xchg_mem->token.token;
    key_node->mem_key.server_chid = server_channel->id;
    urpc_list_push_back(&server_channel->mem_key_list, &key_node->node);
    return URPC_SUCCESS;
}

static inline bool mem_info_in_mem_list(mem_hmap_key_t *mem_key, xchg_mem_info_t **mem_info, uint32_t mem_info_num)
{
    for (uint32_t i = 0; i < mem_info_num; i++) {
        if (mem_key->token_id == mem_info[i]->seg_token_id && mem_key->token_value == mem_info[i]->token.token) {
            return true;
        }
    }
    return false;
}

int server_channel_put_mem_info(uint32_t server_chid, xchg_mem_info_t **mem_info, uint32_t mem_info_num)
{
    urpc_server_channel_info_t *server_channel = server_channel_get_with_rw_lock(server_chid, true);
    if (server_channel == NULL) {
        return URPC_FAIL;
    }

    mem_entry_key_node_t *cur_node, *next_node;
    URPC_LIST_FOR_EACH_SAFE(cur_node, next_node, node, &server_channel->mem_key_list) {
        if (mem_info_in_mem_list(&cur_node->mem_key, mem_info, mem_info_num)) {
            continue;
        }
        (void)urpc_mem_unimport(server_chid, cur_node->mem_key.token_id, cur_node->mem_key.token_value);
        urpc_list_remove(&cur_node->node);
        urpc_dbuf_free(cur_node);
    }

    int ret;
    uint32_t i;
    for (i = 0; i < mem_info_num; i++) {
        ret = urpc_mem_import(server_chid, mem_info[i]);
        if (ret != URPC_SUCCESS) {
            (void)pthread_rwlock_unlock(&server_channel->rw_lock);
            URPC_LIB_LOG_ERR("import mem failed\n");
            goto UNIMPORT_MEM;
        }

        if (server_channel_add_mem(server_channel, mem_info[i]) != URPC_SUCCESS) {
            (void)urpc_mem_unimport(server_chid, mem_info[i]->seg_token_id, mem_info[i]->token.token);
            (void)pthread_rwlock_unlock(&server_channel->rw_lock);
            URPC_LIB_LOG_ERR("server channel add mem failed\n");
            ret = -URPC_ERR_ENOMEM;
            goto UNIMPORT_MEM;
        }
    }
    (void)pthread_rwlock_unlock(&server_channel->rw_lock);
    return URPC_SUCCESS;

UNIMPORT_MEM:
    for (uint32_t j = 0; j < i; j++) {
        (void)urpc_mem_unimport(server_chid, mem_info[j]->seg_token_id, mem_info[j]->token.token);
    }
    return ret;
}