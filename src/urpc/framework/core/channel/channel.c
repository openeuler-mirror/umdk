/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2024-2024. All rights reserved.
 * Description: realize channel function
 */

#include <stdint.h>
#include "cp_vers_compat.h"
#include "urpc_framework_errno.h"
#include "ip_handshaker.h"
#include "urpc_framework_api.h"
#include "urpc_hash.h"
#include "urpc_lib_log.h"
#include "notify.h"
#include "keepalive.h"
#include "crypto.h"
#include "cp.h"
#include "dp.h"
#include "urpc_dbuf_stat.h"
#include "channel.h"

static urpc_channel_info_t *g_urpc_channels[URPC_MAX_CHANNELS] = {0};
static urpc_channel_id_allocator_t g_urpc_channel_id_allocator = {0};

int channel_id_allocator_init(urpc_channel_id_allocator_t *id_allocator, uint32_t max_num)
{
    if (id_allocator->available_ids != NULL) {
        URPC_LIB_LOG_ERR("channel ID allocator is already initialized\n");
        return URPC_FAIL;
    }

    id_allocator->available_ids = (uint32_t *)urpc_dbuf_malloc(URPC_DBUF_TYPE_CHANNEL, max_num * sizeof(int));
    if (id_allocator->available_ids == NULL) {
        URPC_LIB_LOG_ERR("malloc channel ID allocator failed\n");
        return URPC_FAIL;
    }

    id_allocator->num_available = 0;
    id_allocator->next_id = 0;
    (void)pthread_mutex_init(&id_allocator->lock, NULL);

    return URPC_SUCCESS;
}

void channel_id_allocator_uninit(urpc_channel_id_allocator_t *id_allocator)
{
    (void)pthread_mutex_destroy(&id_allocator->lock);
    urpc_dbuf_free(id_allocator->available_ids);
    id_allocator->available_ids = NULL;
}

uint32_t channel_id_allocator_get(urpc_channel_id_allocator_t *id_allocator, uint32_t max_id)
{
    uint32_t id;
    (void)pthread_mutex_lock(&id_allocator->lock);
    if (id_allocator->num_available > 0) {
        id = id_allocator->available_ids[--id_allocator->num_available];
    } else {
        id = id_allocator->next_id++;
        if (id >= max_id) {
            id_allocator->next_id--;
        }
    }
    (void)pthread_mutex_unlock(&id_allocator->lock);

    return id;
}

void channel_id_allocator_release(urpc_channel_id_allocator_t *id_allocator, uint32_t max_id, uint32_t urpc_chid)
{
    if (id_allocator->available_ids == NULL) {
        return;
    }
    (void)pthread_mutex_lock(&id_allocator->lock);
    if (id_allocator->num_available < max_id) {
        id_allocator->available_ids[id_allocator->num_available++] = urpc_chid;
    }
    (void)pthread_mutex_unlock(&id_allocator->lock);
    return;
}

int urpc_client_channel_id_allocator_init(void)
{
    return channel_id_allocator_init(&g_urpc_channel_id_allocator, URPC_MAX_CHANNELS);
}

void urpc_client_channel_id_allocator_uninit(void)
{
    channel_id_allocator_uninit(&g_urpc_channel_id_allocator);
}

static uint32_t client_channel_id_get(void)
{
    return channel_id_allocator_get(&g_urpc_channel_id_allocator, URPC_MAX_CHANNELS);
}

static void client_channel_id_release(uint32_t urpc_chid)
{
    channel_id_allocator_release(&g_urpc_channel_id_allocator, URPC_MAX_CHANNELS, urpc_chid);
}

static inline bool urpc_server_info_cmp(urpc_host_info_t *server, urpc_host_info_t *target)
{
    if (server->host_type < HOST_TYPE_UB) {
        return urpc_server_info_ip_compare(server, target);
    }

    return ((server->host_type == target->host_type) &&
            (memcmp(&server->ub.eid, &target->ub.eid, sizeof(urpc_eid_t)) == 0));
}

// server_info src should be validated before convert
void urpc_server_info_convert(urpc_host_info_t *src, urpc_host_info_inner_t *dst)
{
    dst->host_type = src->host_type;
    if (src->host_type == HOST_TYPE_UB) {
        dst->ub.eid = src->ub.eid;
        return;
    }

    if (src->host_type == HOST_TYPE_IPV4) {
        dst->ipv4.port = src->ipv4.port;
        (void)inet_pton(AF_INET, src->ipv4.ip_addr, &(dst->ipv4.sin_addr));
        return;
    }

    dst->ipv6.port = src->ipv6.port;
    (void)inet_pton(AF_INET6, src->ipv6.ip_addr, &(dst->ipv6.sin6_addr));
}

urpc_channel_info_t *channel_alloc(void)
{
    urpc_channel_info_t *info =
        (urpc_channel_info_t *)urpc_dbuf_calloc(URPC_DBUF_TYPE_CHANNEL, 1, sizeof(urpc_channel_info_t));
    if (info == NULL) {
        URPC_LIB_LOG_ERR("malloc channel info failed\n");
        return NULL;
    }

    info->manage_chid = URPC_INVALID_ID_U32;
    info->id = client_channel_id_get();
    if (info->id >= URPC_MAX_CHANNELS) {
        URPC_LIB_LOG_ERR("channel ID[%u] exceeds the upper limit[%u]\n", info->id, URPC_MAX_CHANNELS);
        urpc_dbuf_free(info);
        return NULL;
    }

    urpc_list_init(&info->server_nodes_list);
    URPC_SLIST_INIT(&info->l_queue_nodes_head);
    URPC_SLIST_INIT(&info->r_queue_nodes_head);

    (void)pthread_spin_init(&info->lock, PTHREAD_PROCESS_PRIVATE);
    (void)pthread_rwlock_init(&info->rw_lock, NULL);
    (void)pthread_rwlock_init(&info->mem_info_lock, NULL);
    urpc_list_init(&info->mem_info_list);
    info->mem_info_num = 0;
    g_urpc_channels[info->id] = info;
    urpc_list_init(&info->task_ready_list);

    return info;
}

int channel_free(uint32_t urpc_chid)
{
    urpc_channel_info_t *channel = channel_get(urpc_chid);
    if (channel == NULL) {
        URPC_LIB_LOG_ERR("get channel[%u] failed\n", urpc_chid);
        return -URPC_ERR_EINVAL;
    }

    queue_node_t *cur_node, *next_node;
    URPC_SLIST_FOR_EACH_SAFE(cur_node, &channel->r_queue_nodes_head, node, next_node) {
        URPC_SLIST_REMOVE(&channel->r_queue_nodes_head, cur_node, queue_node, node);
        queue_t *r_queue = (queue_t *)(uintptr_t)(cur_node->urpc_qh);
        (void)r_queue->ops->unimport_remote_queue(r_queue);
        urpc_dbuf_free(cur_node);
    }

    URPC_SLIST_FOR_EACH_SAFE(cur_node, &channel->l_queue_nodes_head, node, next_node) {
        URPC_SLIST_REMOVE(&channel->l_queue_nodes_head, cur_node, queue_node, node);
        queue_t *l_queue = (queue_t *)(uintptr_t)cur_node->urpc_qh;
        (void)__sync_fetch_and_sub(&l_queue->ref_cnt, 1);
        urpc_dbuf_free(cur_node);
    }

    server_node_t *cur_server_node, *next_server_node;
    URPC_LIST_FOR_EACH_SAFE(cur_server_node, next_server_node, node, &channel->server_nodes_list) {
        for (uint32_t i = 0; i < cur_server_node->urpc_qh_count; ++i) {
            queue_t *r_queue = (queue_t *)(uintptr_t)cur_server_node->urpc_qh[i];
            r_queue->ops->delete_remote_queue(r_queue);
        }
        urpc_list_remove(&cur_server_node->node);
        urpc_dbuf_free(cur_server_node->urpc_qh);
        crypto_cipher_uninit(cur_server_node->cipher_opt);
        urpc_dbuf_free(cur_server_node->cipher_opt);
        urpc_dbuf_free(cur_server_node);
    }

    if (channel->req_entry_table != NULL) {
        for (uint32_t i = 0; i < channel->req_entry_size; ++i) {
            (void)pthread_mutex_destroy(&channel->req_entry_table[i].lock);
            if ((is_feature_enable(URPC_TIMER_FEATURE_FLAG) && channel->req_entry_table[i].timer != NULL)) {
                urpc_timer_destroy(channel->req_entry_table[i].timer);
                channel->req_entry_table[i].timer = NULL;
            }
        }
        urpc_dbuf_free(channel->req_entry_table);
    }

    if (URPC_LIKELY(is_feature_enable(URPC_TIMER_FEATURE_FLAG))) {
        urpc_timer_pool_delete(urpc_chid, false);
    }
    g_urpc_channels[urpc_chid] = NULL;

    if (!urpc_list_is_empty(&channel->mem_info_list)) {
        (void)pthread_rwlock_wrlock(&channel->mem_info_lock);
        channel_mem_info_t *cur_mem_info, *mem_info_next;
        URPC_LIST_FOR_EACH_SAFE(cur_mem_info, mem_info_next, node, &channel->mem_info_list) {
            urpc_list_remove(&cur_mem_info->node);
            urpc_dbuf_free(cur_mem_info);
        }
        (void)pthread_rwlock_unlock(&channel->mem_info_lock);
        URPC_LIB_LOG_WARN("channel has mem info enable\n");
    }

    (void)pthread_rwlock_destroy(&channel->mem_info_lock);

    (void)pthread_spin_destroy(&channel->lock);
    (void)pthread_rwlock_destroy(&channel->rw_lock);
    urpc_dbuf_free(channel);
    client_channel_id_release(urpc_chid);

    URPC_LIB_LOG_INFO("free client channel[%u] successful\n", urpc_chid);

    return URPC_SUCCESS;
}

urpc_channel_info_t *channel_get(uint32_t urpc_chid)
{
    if (urpc_chid >= URPC_MAX_CHANNELS) {
        URPC_LIB_LOG_ERR("chid invalid, %u\n", urpc_chid);
        return NULL;
    }

    return g_urpc_channels[urpc_chid];
}

void req_entry_table_init(urpc_channel_info_t *channel)
{
    if (channel->req_entry_size == 0) {
        channel->req_entry_size = URPC_DEFAULT_CHANNEL_REQ_ENTRY;
    }

    req_entry_t *req_entry_table = (req_entry_t *)urpc_dbuf_calloc(URPC_DBUF_TYPE_CHANNEL,
        1, channel->req_entry_size * sizeof(req_entry_t));
    if (URPC_UNLIKELY((req_entry_table == NULL))) {
        URPC_LIB_LOG_ERR("malloc %u channel entry table failed\n", channel->req_entry_size);
        return;
    }

    if (URPC_LIKELY(is_feature_enable(URPC_TIMER_FEATURE_FLAG))) {
        int ret = urpc_timer_pool_add(channel->id, channel->req_entry_size, false);
        if (URPC_UNLIKELY(ret != URPC_SUCCESS && ret != -URPC_ERR_EEXIST)) {
            urpc_dbuf_free(req_entry_table);
            return;
        }
    }

    for (uint32_t i = 0; i < channel->req_entry_size; ++i) {
        (void)pthread_mutex_init(&req_entry_table[i].lock, NULL);
    }

    channel->req_entry_table = req_entry_table;
    channel->stats[CHANNEL_REQ_ENTRY_TOTAL_NUM] = channel->req_entry_size;
    channel->stats[CHANNEL_REQ_ENTRY_FREE_NUM] = channel->req_entry_size;
}

req_entry_t *req_entry_get(urpc_channel_info_t *channel, void *ctx)
{
    (void)pthread_spin_lock(&channel->lock);
    if (URPC_UNLIKELY((channel->req_entry_table == NULL))) {
        req_entry_table_init(channel);
        if (URPC_UNLIKELY((channel->req_entry_table == NULL))) {
            (void)pthread_spin_unlock(&channel->lock);
            return NULL;
        }
    }

    uint32_t req_id = channel->req_id++;
    uint32_t tried = 0;

    req_entry_t *req_entry_table = channel->req_entry_table;
    uint32_t req_entry_size = channel->req_entry_size;
    req_entry_t *req_entry = &req_entry_table[req_id & (req_entry_size - 1)];

    while (req_entry->valid == 1 && tried++ < req_entry_size) {
        req_id = channel->req_id++;
        req_entry = &req_entry_table[req_id & (req_entry_size - 1)];
    }

    if (URPC_UNLIKELY((tried > req_entry_size))) {
        (void)pthread_spin_unlock(&channel->lock);
        URPC_LIB_LIMIT_LOG_DEBUG("no empty request entry available\n");
        return NULL;
    }
    channel->stats[CHANNEL_REQ_ENTRY_FREE_NUM]--;
    channel->stats[CHANNEL_LAST_ALLOC_REQ_ID] = req_id;

    req_entry->req_id = req_id;
    req_entry->ctx = ctx;
    req_entry->valid = 1;
    req_entry->cb = NULL;
    req_entry->cb_arg = NULL;
    (void)pthread_spin_unlock(&channel->lock);

    return req_entry;
}

/* multi thread poll rsp and ack will query same req_entry, need lock */
req_entry_t *req_entry_query(uint32_t urpc_chid, uint32_t req_id, bool need_lock)
{
    if (urpc_chid >= URPC_MAX_CHANNELS) {
        URPC_LIB_LIMIT_LOG_DEBUG("channel id invalid\n");
        return NULL;
    }

    urpc_channel_info_t *channel = g_urpc_channels[urpc_chid];
    if (channel == NULL || channel->req_entry_table == NULL) {
        URPC_LIB_LIMIT_LOG_DEBUG("channel or channel entry table is null\n");
        return NULL;
    }

    req_entry_t *req_entry = &channel->req_entry_table[req_id & (channel->req_entry_size - 1)];
    if (need_lock) {
        (void)pthread_mutex_lock(&req_entry->lock);
    }

    if (req_entry->valid == 0 || req_entry->req_id != req_id) {
        if (need_lock) {
            (void)pthread_mutex_unlock(&req_entry->lock);
        }
        URPC_LIB_LIMIT_LOG_DEBUG("request entry invalid, or req id is not expected(req_id %u, expect req_id %u)\n",
            req_entry->req_id, req_id);
        return NULL;
    }

    return req_entry;
}

void req_entry_put(req_entry_t *req_entry)
{
    if (URPC_LIKELY(is_feature_enable(URPC_TIMER_FEATURE_FLAG) && req_entry->timer != NULL)) {
        urpc_timer_destroy(req_entry->timer);
        req_entry->timer = NULL;
    }

    if (req_entry->cb_arg != NULL) {
        sync_req_cb_arg_t *req_cb_arg = (sync_req_cb_arg_t *)req_entry->cb_arg;
        sem_destroy(&req_cb_arg->rsp_sem);
        urpc_dbuf_free(req_cb_arg);
        req_entry->cb = NULL;
        req_entry->cb_arg = NULL;
    }

    req_entry->valid = 0;
    urpc_channel_info_t *channel = g_urpc_channels[req_entry->local_chid];
    if (channel == NULL || channel->req_entry_table == NULL) {
        URPC_LIB_LIMIT_LOG_ERR("channel or channel entry table is null\n");
        return;
    }
    channel->stats[CHANNEL_REQ_ENTRY_FREE_NUM]++;
    channel->stats[CHANNEL_LAST_FREE_REQ_ID] = req_entry->req_id;
}

int channel_add_remote_queue(
    urpc_channel_info_t *channel, queue_t *queue, batch_queue_import_ctx_t *ctx, int timeout)
{
    provider_t *provider = channel->provider;
    if (provider == NULL || provider->ops == NULL || queue->ops->import_remote_queue == NULL) {
        URPC_LIB_LOG_ERR("get provider failed, channel[%u]\n", channel->id);
        return URPC_FAIL;
    }

    if (queue->ref_cnt != 0) {
        queue->ref_cnt++;
        return URPC_SUCCESS;
    }

    queue_import_async_info_t *import_info =
        (queue_import_async_info_t *)urpc_dbuf_calloc(URPC_DBUF_TYPE_CP, 1, sizeof(queue_import_async_info_t));
    if (import_info == NULL) {
        URPC_LIB_LOG_ERR("import_info malloc failed\n");
        return URPC_FAIL;
    }
    import_info->queue_handle = (uint64_t)(uintptr_t)queue;
    import_info->provider = channel->provider;
    import_info->status = QUEUE_IMPORT_INIT;
    import_info->task = ctx->task;
    int ret = queue->ops->import_remote_queue(queue, provider);
    if (ret == URPC_SUCCESS) {
        import_info->status = QUEUE_IMPORT_SUCCESS;
        urpc_list_push_back(&ctx->import_list, &import_info->node);
        return URPC_SUCCESS;
    }
    if (ret != URPC_RUNNING) {
        URPC_LIB_LOG_ERR("import remote queue failed, ret: %d, channel[%u]\n", ret, channel->id);
        urpc_dbuf_free(import_info);
        return URPC_FAIL;
    }
    ctx->running_count++;
    import_info->status = QUEUE_IMPORT_RUNNING;
    urpc_list_push_back(&ctx->import_list, &import_info->node);
    return URPC_RUNNING;
}

int channel_post_add_remote_queue(urpc_channel_info_t *channel, queue_t *queue, void *ctx)
{
    // import success to do
    queue_node_t *node = (queue_node_t *)urpc_dbuf_malloc(URPC_DBUF_TYPE_CHANNEL, sizeof(queue_node_t));
    if (node == NULL) {
        if (queue->ref_cnt == 0) {
            (void)queue->ops->unimport_remote_queue_async(queue);
        }
        URPC_LIB_LOG_ERR("malloc queue node failed, channel[%u]\n", channel->id);
        return URPC_FAIL;
    }

    node->node.next = NULL;
    node->urpc_qh = (uint64_t)(uintptr_t)queue;

    URPC_SLIST_INSERT_HEAD(&channel->r_queue_nodes_head, node, node);
    channel->r_qnum++;
    queue->ref_cnt++;

    return URPC_SUCCESS;
}

int channel_remove_local_queue(urpc_channel_info_t *channel, queue_t *queue)
{
    uint64_t urpc_qh = (uint64_t)(uintptr_t)queue;
    if (channel->cur_rr_local_queue != NULL && channel->cur_rr_local_queue->urpc_qh == urpc_qh) {
        channel->cur_rr_local_queue = NULL;
    }
    if (channel->cur_poll_queue != NULL && channel->cur_poll_queue->urpc_qh == urpc_qh) {
        channel->cur_poll_queue = NULL;
    }

    queue_node_t *cur_node, *next_node;
    URPC_SLIST_FOR_EACH_SAFE(cur_node, &channel->l_queue_nodes_head, node, next_node) {
        if (cur_node->urpc_qh == urpc_qh) {
            cur_node->ref_cnt--;
            if (cur_node->ref_cnt != 0) {
                return URPC_SUCCESS;
            }
            (void)__sync_fetch_and_sub(&queue->ref_cnt, 1);
            URPC_SLIST_REMOVE(&channel->l_queue_nodes_head, cur_node, queue_node, node);
            urpc_dbuf_free(cur_node);
            channel->l_qnum--;
            return URPC_SUCCESS;
        }
    }

    URPC_LIB_LOG_ERR("remove local queue failed in channel[%u]\n", channel->id);
    return URPC_FAIL;
}

int channel_remove_remote_queue(urpc_channel_info_t *channel, queue_t *queue)
{
    uint64_t urpc_qh = (uint64_t)(uintptr_t)queue;
    if (channel->cur_rr_remote_queue != NULL && channel->cur_rr_remote_queue->urpc_qh == urpc_qh) {
        channel->cur_rr_remote_queue = NULL;
    }
    queue_node_t *cur_node, *next_node;
    URPC_SLIST_FOR_EACH_SAFE(cur_node, &channel->r_queue_nodes_head, node, next_node) {
        if (cur_node->urpc_qh == urpc_qh) {
            queue->ref_cnt--;
            if (queue->ref_cnt != 0) {
                return URPC_SUCCESS;
            }
            URPC_SLIST_REMOVE(&channel->r_queue_nodes_head, cur_node, queue_node, node);
            (void)queue->ops->unimport_remote_queue(queue);
            channel->r_qnum--;
            urpc_dbuf_free(cur_node);
            cur_node = NULL;

            return URPC_SUCCESS;
        }
    }

    URPC_LIB_LOG_ERR("not find queue in channel[%u]\n", channel->id);
    return URPC_FAIL;
}

int channel_remove_remote_queue_async(urpc_channel_info_t *channel, queue_t *queue)
{
    uint64_t urpc_qh = (uint64_t)(uintptr_t)queue;
    if (channel->cur_rr_remote_queue != NULL && channel->cur_rr_remote_queue->urpc_qh == urpc_qh) {
        channel->cur_rr_remote_queue = NULL;
    }
    queue_node_t *cur_node, *next_node;
    URPC_SLIST_FOR_EACH_SAFE(cur_node, &channel->r_queue_nodes_head, node, next_node) {
        if (cur_node->urpc_qh == urpc_qh) {
            queue->ref_cnt--;
            if (queue->ref_cnt != 0) {
                return URPC_SUCCESS;
            }
            URPC_SLIST_REMOVE(&channel->r_queue_nodes_head, cur_node, queue_node, node);
            (void)queue->ops->unimport_remote_queue(queue);
            channel->r_qnum--;
            urpc_dbuf_free(cur_node);
            cur_node = NULL;

            return URPC_SUCCESS;
        }
    }

    URPC_LIB_LOG_ERR("not find queue in channel[%u]\n", channel->id);
    return URPC_FAIL;
}

int channel_get_local_queue_info(uint64_t qh, queue_info_t *queue_info)
{
    queue_t *queue = (queue_t *)(uintptr_t)qh;
    return queue->ops->query_local_queue(queue, queue_info);
}

int channel_get_local_queues(urpc_channel_info_t *channel, uint32_t queue_size, uint64_t *qh)
{
    uint32_t idx = 0;
    queue_node_t *cur_node = NULL;

    if (queue_size > MAX_QUEUE_SIZE) {
        return URPC_FAIL;
    }
    URPC_SLIST_FOR_EACH(cur_node, &channel->l_queue_nodes_head, node) {
        if (idx >= queue_size) {
            URPC_LIB_LOG_ERR("local queue num(%u) is larger than the set size of queue(%u)\n", idx + 1, queue_size);
            return URPC_FAIL;
        }

        qh[idx++] = cur_node->urpc_qh;
    }

    return URPC_SUCCESS;
}

static void channel_get_queue_trans_info_size(urpc_channel_info_t *channel, uint32_t *output_size, uint32_t *queue_cnt)
{
    uint32_t output_size_ = 0;
    uint32_t queue_cnt_ = 0;
    queue_node_t *cur_node;
    URPC_SLIST_FOR_EACH(cur_node, &channel->l_queue_nodes_head, node) {
        queue_t *queue = (queue_t *)(uintptr_t)cur_node->urpc_qh;
        output_size_ += queue->ops->query_trans_info(queue, QUEUE_QUERY_TRANS_INFO_SIZE, NULL);
        queue_cnt_++;
    }

    URPC_SLIST_FOR_EACH(cur_node, &channel->r_queue_nodes_head, node) {
        queue_t *queue = (queue_t *)(uintptr_t)cur_node->urpc_qh;
        output_size_ += queue->ops->query_trans_info(queue, QUEUE_QUERY_TRANS_INFO_SIZE, NULL);
        queue_cnt_++;
    }

    *output_size = output_size_;
    *queue_cnt = queue_cnt_;
}

static int channel_get_queue_trans_info_fill_with_output(urpc_channel_info_t *channel, uint32_t output_size,
                                                         char *output)
{
    queue_node_t *cur_node;
    uint32_t offset = 0;
    URPC_SLIST_FOR_EACH(cur_node, &channel->l_queue_nodes_head, node) {
        if (offset >= output_size) {
            URPC_LIB_LOG_ERR("Exceed query output size\n");
            return URPC_FAIL;
        }

        queue_t *queue = (queue_t *)(uintptr_t)cur_node->urpc_qh;
        offset += queue->ops->query_trans_info(queue, QUEUE_QUERY_TRANS_INFO_DATA, output + offset);
    }

    URPC_SLIST_FOR_EACH(cur_node, &channel->r_queue_nodes_head, node) {
        if (offset >= output_size) {
            URPC_LIB_LOG_ERR("Exceed query output size\n");
            return URPC_FAIL;
        }

        queue_t *queue = (queue_t *)(uintptr_t)cur_node->urpc_qh;
        offset += queue->ops->query_trans_info(queue, QUEUE_QUERY_TRANS_INFO_DATA, output + offset);
    }

    return URPC_SUCCESS;
}

int channel_get_queue_trans_info(uint32_t urpc_chid, char **output, uint32_t *output_size)
{
    urpc_channel_info_t *channel = channel_get(urpc_chid);
    if (channel == NULL) {
        URPC_LIB_LOG_ERR("Failed to get channel[%u]\n", urpc_chid);
        return URPC_FAIL;
    }

    (void)pthread_rwlock_rdlock(&channel->rw_lock);
    uint32_t cnt = channel->l_qnum + channel->r_qnum;
    if (cnt == 0) {
        (void)pthread_rwlock_unlock(&channel->rw_lock);
        return URPC_SUCCESS;
    }

    uint32_t output_size_ = 0;
    uint32_t queue_cnt_ = 0;
    channel_get_queue_trans_info_size(channel, &output_size_, &queue_cnt_);
    if (cnt != queue_cnt_) {
        (void)pthread_rwlock_unlock(&channel->rw_lock);
        URPC_LIB_LOG_ERR("The number of queues(%u) is inconsistent with the actual number.(%u)\n", cnt, queue_cnt_);
        return URPC_FAIL;
    }

    char *output_ = (char *)urpc_dbuf_malloc(URPC_DBUF_TYPE_CHANNEL, output_size_);
    if (output_ == NULL) {
        (void)pthread_rwlock_unlock(&channel->rw_lock);
        URPC_LIB_LOG_ERR("Failed to malloc, errno: %d\n", errno);
        return -URPC_ERR_ENOMEM;
    }

    if (channel_get_queue_trans_info_fill_with_output(channel, output_size_, output_) != URPC_SUCCESS) {
        (void)pthread_rwlock_unlock(&channel->rw_lock);
        urpc_dbuf_free(output_);
        URPC_LIB_LOG_ERR("Exceed query output size\n");
        return URPC_FAIL;
    }
    (void)pthread_rwlock_unlock(&channel->rw_lock);

    *output = output_;
    *output_size = output_size_;

    return URPC_SUCCESS;
}

bool channel_put_remote_queue_infos(
    urpc_channel_info_t *channel, uint32_t remote_chid, urpc_endpoints_t *endpoints, void *chmsg_input)
{
    urpc_chmsg_v1_t *chmsg = (urpc_chmsg_v1_t *)chmsg_input;
    queue_ops_t *ops = NULL;
    queue_t *queue = NULL;
    uint32_t queue_num = chmsg->qinfo_arr.arr_num;
    uint32_t i = 0;

    server_node_t *node = (server_node_t *)urpc_dbuf_calloc(URPC_DBUF_TYPE_CHANNEL, 1, sizeof(server_node_t));
    if (node == NULL) {
        URPC_LIB_LOG_ERR("malloc server node failed\n");
        return false;
    }

    uint64_t *qhs = (uint64_t *)urpc_dbuf_calloc(URPC_DBUF_TYPE_CHANNEL, 1, sizeof(uint64_t) * queue_num);
    if (qhs == NULL) {
        URPC_LIB_LOG_ERR("malloc queue handle failed\n");
        goto FREE_NODE;
    }
    node->endpoints = *endpoints;
    node->urpc_qh_count = queue_num;
    node->urpc_qh = qhs;
    node->server_chid = remote_chid;
    node->cap = chmsg->chinfo->cap;
    node->instance_key = chmsg->chinfo->key;
    node->index = channel->server_node_index++;

    if (crypto_is_dp_ssl_enabled()) {
        node->cipher_opt = (urpc_cipher_t *)urpc_dbuf_calloc(URPC_DBUF_TYPE_ENCRYPT, 1, sizeof(urpc_cipher_t));
        if (node->cipher_opt == NULL) {
            URPC_LIB_LOG_ERR("malloc cipher_opt failed\n");
            goto FREE_QUEUE;
        }
        node->cipher_opt->chid = URPC_INVALID_ID_U32;
    }

    for (; i < queue_num; i++) {
        ops = queue_get_ops(chmsg->qinfo_arr.qinfos[i]->trans_mode);
        if (ops == NULL) {
            URPC_LIB_LOG_ERR("get queue ops failed\n");
            goto FREE_CIPHER;
        }

        queue = ops->create_remote_queue(chmsg->qinfo_arr.qinfos[i], remote_chid, 0);
        if (queue == NULL) {
            URPC_LIB_LOG_ERR("create remote queue failed\n");
            goto FREE_CIPHER;
        }

        URPC_LIB_LOG_DEBUG("channel[%u] create and put remote queue, remote chid[%u]\n", channel->id, remote_chid);

        queue_remote_t *remote_q = CONTAINER_OF_FIELD(queue, queue_remote_t, queue);
        remote_q->cfg.server_node = node;
        qhs[i] = (uint64_t)(uintptr_t)queue;
    }
    urpc_list_push_back(&channel->server_nodes_list, &node->node);

    return true;

FREE_CIPHER:
    urpc_dbuf_free(node->cipher_opt);

FREE_QUEUE:
    for (uint32_t j = 0; j < i; j++) {
        queue = (queue_t *)(uintptr_t)qhs[j];
        queue->ops->delete_remote_queue(queue);
    }
    urpc_dbuf_free(node->urpc_qh);

FREE_NODE:
    urpc_dbuf_free(node);

    return false;
}

static void server_node_qh_update(server_node_t *server_node, uint64_t *valid_rq, uint32_t valid_num)
{
    if (server_node->urpc_qh_count == valid_num) {
        return;
    }

    server_node->urpc_qh_count = valid_num;
    for (uint32_t i = 0; i < valid_num; i++) {
        server_node->urpc_qh[i] = valid_rq[i];
    }
}

// server restart, client need to add new rq, set old added rq to QUEUE_STATUS_ERR, and delete
// not added rq. cipher_opt also need to be reset in this case
int channel_flush_remote_queue_info(
    urpc_channel_info_t *channel, urpc_endpoints_t *endpoints, server_node_t *server_node, void *chmsg_input)
{
    uint64_t added_rqh[MAX_QUEUE_SIZE];
    uint32_t added_rq_num = 0;
    uint32_t i = 0;
    queue_ops_t *ops = NULL;
    queue_t *queue = NULL;
    queue_remote_t *remote_q = NULL;
    urpc_chmsg_v1_t *chmsg = (urpc_chmsg_v1_t *)chmsg_input;
    uint32_t queue_num = chmsg->qinfo_arr.arr_num;

    // 1. remove not added rq
    for (i = 0; i < server_node->urpc_qh_count; i++) {
        queue = (queue_t *)(uintptr_t)server_node->urpc_qh[i];
        if (queue->ref_cnt == 0) {
            queue->ops->delete_remote_queue(queue);
        } else {
            queue->status = QUEUE_STATUS_ERR;
            added_rqh[added_rq_num++] = server_node->urpc_qh[i];
        }
    }

    // update rq info in server_node
    server_node_qh_update(server_node, added_rqh, added_rq_num);

    // if total rq over MAX_QUEUE_SIZE, user must remove QUEUE_STATUS_ERR remote q first
    if ((queue_num + added_rq_num) > MAX_QUEUE_SIZE) {
        URPC_LIB_LOG_ERR("server already restarted, and remote queue num %u exceed MAX_QUEUE_SIZE, need to remove "
                         "QUEUE_STATUS_ERR remote queue in this channel first\n",
            (queue_num + added_rq_num));
        return URPC_FAIL;
    }

    uint64_t *new_rqh = (uint64_t *)urpc_dbuf_calloc(URPC_DBUF_TYPE_CHANNEL,
        1, (queue_num + added_rq_num) * sizeof(uint64_t));
    if (new_rqh == NULL) {
        URPC_LIB_LOG_ERR("malloc new remote queue array failed, errno %d\n", errno);
        return URPC_FAIL;
    }

    // 2. create new remote q
    for (i = 0; i < queue_num; i++) {
        ops = queue_get_ops(chmsg->qinfo_arr.qinfos[i]->trans_mode);
        if (ops == NULL) {
            URPC_LIB_LOG_ERR("get queue ops failed\n");
            goto FREE_RQ;
        }

        queue = ops->create_remote_queue(chmsg->qinfo_arr.qinfos[i], chmsg->chinfo->chid, 0);
        if (queue == NULL) {
            URPC_LIB_LOG_ERR("create remote queue failed\n");
            goto FREE_RQ;
        }

        remote_q = CONTAINER_OF_FIELD(queue, queue_remote_t, queue);
        remote_q->cfg.server_node = server_node;
        new_rqh[i] = (uint64_t)(uintptr_t)queue;
    }

    // 3. move old added rq to new node
    for (i = 0; i < added_rq_num; i++) {
        new_rqh[queue_num + i] = added_rqh[i];
    }

    // 4. reset server info
    uint64_t *old_rqs = server_node->urpc_qh;
    server_node->endpoints = *endpoints;
    server_node->urpc_qh_count = queue_num + added_rq_num;
    server_node->server_chid = chmsg->chinfo->chid;
    server_node->urpc_qh = new_rqh;
    server_node->cap = chmsg->chinfo->cap;
    server_node->instance_key = chmsg->chinfo->key;

    urpc_dbuf_free(old_rqs);

    if (server_node->cipher_opt != NULL) {
        memset(server_node->cipher_opt, 0, sizeof(urpc_cipher_t));
        server_node->cipher_opt->chid = URPC_INVALID_ID_U32;
    }

    return URPC_SUCCESS;

FREE_RQ:
    for (uint32_t j = 0; j < i; j++) {
        queue = (queue_t *)(uintptr_t)new_rqh[j];
        if (queue == NULL) {
            break;
        }

        queue->ops->delete_remote_queue(queue);
    }

    urpc_dbuf_free(new_rqh);

    return URPC_FAIL;
}

bool is_remote_queue_in_queue_info(queue_t *queue, void *chmsg_input)
{
    urpc_chmsg_v1_t *chmsg = (urpc_chmsg_v1_t *)chmsg_input;

    for (uint32_t i = 0; i < chmsg->qinfo_arr.arr_num; i++) {
        if (queue->ops->is_same_queue(queue, chmsg->qinfo_arr.qinfos[i], QUEUE_AUTHN_BY_QUEUE_INFO)) {
            return true;
        }
    }

    return false;
}

static bool is_queue_info_in_remote_qhs(queue_info_t *q_info, server_node_t *server_node)
{
    queue_t *queue = NULL;

    for (uint32_t i = 0; i < server_node->urpc_qh_count; i++) {
        queue = (queue_t *)(uintptr_t)server_node->urpc_qh[i];
        if (queue->ops->is_same_queue(queue, q_info, QUEUE_AUTHN_BY_QUEUE_INFO)) {
            return true;
        }
    }

    return false;
}

static void after_exchange_queues_update_remote_queue(
    server_node_t *server_node, void *chmsg_input, uint64_t rq_valid[], uint32_t *rq_valid_num, bool is_all_queue)
{
    urpc_chmsg_v1_t *chmsg = (urpc_chmsg_v1_t *)chmsg_input;
    queue_remote_t *remote_q = NULL;
    // 1. find all rq in server_node that has been deleted by remote
    for (uint32_t i = 0; i < server_node->urpc_qh_count; i++) {
        queue_t *queue = (queue_t *)(uintptr_t)server_node->urpc_qh[i];
        remote_q = CONTAINER_OF_FIELD(queue, queue_remote_t, queue);
        remote_q->cfg.remote_chid = chmsg->chinfo->chid;
        if (!is_remote_queue_in_queue_info(queue, chmsg_input)) {
            if (!is_all_queue) {
                // add remote exchange one queue
                rq_valid[(*rq_valid_num)++] = server_node->urpc_qh[i];
                continue;
            }
            // attach exchange all queue, queue not in chmsg_input, set deleted rq to QUEUE_STATUS_ERR
            if (queue->ref_cnt == 0) {
                queue->ops->delete_remote_queue(queue);
            } else {
                queue->status = QUEUE_STATUS_ERR;
                rq_valid[(*rq_valid_num)++] = server_node->urpc_qh[i];
            }
        } else {
            rq_valid[(*rq_valid_num)++] = server_node->urpc_qh[i];
        }
    }
}

// client and server has attached before, find out different rq here, set deleted rq to QUEUE_STATUS_ERR, and if it's
// not added, just delete it. then add new remote queue
int channel_update_remote_queue_info(urpc_channel_info_t *channel, urpc_endpoints_t *endpoints,
    server_node_t *server_node, void *chmsg_input, bool is_all_queue)
{
    // remote add these queue
    queue_info_t *rq_info_new[MAX_QUEUE_SIZE];
    uint32_t rq_info_new_num = 0;
    // remote q still in use
    uint64_t rq_valid[MAX_QUEUE_SIZE];
    uint32_t rq_valid_num = 0;
    uint32_t i = 0;
    queue_t *queue = NULL;
    queue_remote_t *remote_q = NULL;
    queue_ops_t *ops = NULL;
    queue_info_t *queue_info = NULL;
    urpc_chmsg_v1_t *chmsg = (urpc_chmsg_v1_t *)chmsg_input;

    after_exchange_queues_update_remote_queue(server_node, chmsg_input, rq_valid, &rq_valid_num, is_all_queue);

    // update rq info in server_node
    server_node_qh_update(server_node, rq_valid, rq_valid_num);

    // 2. find all rq in info_xchg that remote newly created
    for (i = 0; i < chmsg->qinfo_arr.arr_num; i++) {
        if (!is_queue_info_in_remote_qhs(chmsg->qinfo_arr.qinfos[i], server_node)) {
            rq_info_new[rq_info_new_num++] = chmsg->qinfo_arr.qinfos[i];
        }
    }

    // if total rq over MAX_QUEUE_SIZE, user must remove QUEUE_STATUS_ERR remote q first
    if ((rq_valid_num + rq_info_new_num) > MAX_QUEUE_SIZE) {
        URPC_LIB_LOG_ERR("server remote queue num %u exceed MAX_QUEUE_SIZE, need to remove "
                         "QUEUE_STATUS_ERR remote queue in this channel first\n",
            (rq_valid_num + rq_info_new_num));
        return URPC_FAIL;
    }

    // update server_chid/cipher info in case that server channel is re-created
    if (server_node->server_chid != chmsg->chinfo->chid) {
        server_node->server_chid = chmsg->chinfo->chid;
        crypto_cipher_uninit(server_node->cipher_opt);
    }

    // 3. create new rq
    if (rq_info_new_num == 0) {
        return URPC_SUCCESS;
    }

    uint64_t *new_rqh = (uint64_t *)urpc_dbuf_calloc(URPC_DBUF_TYPE_CHANNEL,
        1, (rq_valid_num + rq_info_new_num) * sizeof(uint64_t));
    if (new_rqh == NULL) {
        URPC_LIB_LOG_ERR("malloc new remote queue array failed, errno %d\n", errno);
        return URPC_FAIL;
    }

    // 4. create new remote q
    for (i = 0; i < rq_info_new_num; i++) {
        queue_info = rq_info_new[i];
        ops = queue_get_ops(queue_info->trans_mode);
        if (ops == NULL) {
            URPC_LIB_LOG_ERR("get queue ops failed\n");
            goto FREE_RQ;
        }

        queue = ops->create_remote_queue(queue_info, chmsg->chinfo->chid, 0);
        if (queue == NULL) {
            URPC_LIB_LOG_ERR("create remote queue failed\n");
            goto FREE_RQ;
        }

        remote_q = CONTAINER_OF_FIELD(queue, queue_remote_t, queue);
        remote_q->cfg.server_node = server_node;
        new_rqh[i] = (uint64_t)(uintptr_t)queue;
    }

    // 5. move old added rq to new node
    for (i = 0; i < rq_valid_num; i++) {
        new_rqh[rq_info_new_num + i] = rq_valid[i];
    }

    // 6. reset server info
    uint64_t *old_rqs = server_node->urpc_qh;
    server_node->endpoints = *endpoints;
    server_node->urpc_qh_count = rq_valid_num + rq_info_new_num;
    server_node->server_chid = chmsg->chinfo->chid;
    server_node->urpc_qh = new_rqh;
    server_node->cap = chmsg->chinfo->cap;
    server_node->instance_key = chmsg->chinfo->key;

    urpc_dbuf_free(old_rqs);

    return URPC_SUCCESS;

FREE_RQ:
    for (uint32_t j = 0; j < i; j++) {
        queue = (queue_t *)(uintptr_t)new_rqh[j];
        if (queue == NULL) {
            break;
        }

        queue->ops->delete_remote_queue(queue);
    }

    urpc_dbuf_free(new_rqh);

    return URPC_FAIL;
}

uint32_t channel_remove_server(urpc_channel_info_t *channel, urpc_host_info_t *server)
{
    uint32_t server_chid = URPC_INVALID_ID_U32;
    server_node_t *cur_server_node, *next_server_node;
    URPC_LIST_FOR_EACH_SAFE(cur_server_node, next_server_node, node, &channel->server_nodes_list) {
        if (!urpc_server_info_cmp(&cur_server_node->endpoints.server, server)) {
            continue;
        }
        uint32_t count = cur_server_node->urpc_qh_count;
        uint64_t *urpc_qhs = cur_server_node->urpc_qh;
        queue_t *queue;
        for (uint32_t i = 0; i < count; ++i) {
            queue = (queue_t *)(uintptr_t)urpc_qhs[i];
            while (queue->ref_cnt != 0) {
                int ret = channel_remove_remote_queue(channel, queue);
                if (ret != URPC_SUCCESS) {
                    break;
                }
            }
            queue->ops->delete_remote_queue(queue);
        }
        urpc_dbuf_free(urpc_qhs);
        urpc_list_remove(&cur_server_node->node);
        server_chid = cur_server_node->server_chid;
        crypto_cipher_uninit(cur_server_node->cipher_opt);
        urpc_dbuf_free(cur_server_node->cipher_opt);
        urpc_dbuf_free(cur_server_node);
    }

    return server_chid;
}

server_node_t *channel_get_server_node(urpc_channel_info_t *channel, urpc_host_info_t *server)
{
    server_node_t *cur_server_node;
    URPC_LIST_FOR_EACH(cur_server_node, node, &channel->server_nodes_list) {
        if (server == NULL || urpc_server_info_cmp(&cur_server_node->endpoints.server, server)) {
            return cur_server_node;
        }
    }

    return NULL;
}

server_node_t *channel_get_server_node_by_index(urpc_channel_info_t *channel, uint64_t index)
{
    server_node_t *cur_server_node;
    URPC_LIST_FOR_EACH(cur_server_node, node, &channel->server_nodes_list) {
        if (cur_server_node->index == index) {
            return cur_server_node;
        }
    }
    return NULL;
}

// notice: server_chid is unique only if client channel attached to single server
server_node_t *channel_get_server_node_by_chid(urpc_channel_info_t *channel, uint32_t server_chid)
{
    server_node_t *cur_server_node;
    size_t server_node_num = urpc_list_size(&channel->server_nodes_list);
    if (URPC_UNLIKELY(server_node_num > 1)) {
        URPC_LIB_LIMIT_LOG_WARN("server_node is not unique, num %zu\n", server_node_num);
    }

    URPC_LIST_FOR_EACH(cur_server_node, node, &channel->server_nodes_list) {
        if (cur_server_node->server_chid == server_chid) {
            return cur_server_node;
        }
    }
    return NULL;
}

uint32_t channel_get_server_chid(urpc_channel_info_t *channel, urpc_host_info_t *server)
{
    server_node_t *server_node = channel_get_server_node(channel, server);
    if (server_node == NULL) {
        URPC_LIB_LOG_WARN("client get server node is NULL, client chid[%u]\n", channel->id);
        return URPC_INVALID_ID_U32;
    }

    return server_node->server_chid;
}

int channel_get_req_id(urpc_channel_info_t *channel, uint32_t *id)
{
    (void)pthread_spin_lock(&channel->lock);
    *id = channel->req_id++;
    (void)pthread_spin_unlock(&channel->lock);
    return 0;
}

void channel_queue_query(urpc_channel_info_t *channel, urpc_channel_qinfos_t *info)
{
    queue_node_t *cur_node;
    (void)pthread_rwlock_rdlock(&channel->rw_lock);
    urpc_channel_qinfo_t *qinfo = info->l_qinfo;
    URPC_SLIST_FOR_EACH(cur_node, &channel->l_queue_nodes_head, node) {
        queue_t *queue = (queue_t *)(uintptr_t)cur_node->urpc_qh;
        qinfo->urpc_qh = cur_node->urpc_qh;
        qinfo->status = queue->status;
        qinfo->ref_cnt = (uint32_t)queue->ref_cnt;

        qinfo++;
    }
    info->l_qnum = channel->l_qnum;

    qinfo = info->r_qinfo;
    uint32_t size, count = 0;
    server_node_t *cur_server_node;
    URPC_LIST_FOR_EACH(cur_server_node, node, &channel->server_nodes_list) {
        size = cur_server_node->urpc_qh_count;
        uint64_t *urpc_qhs = cur_server_node->urpc_qh;
        for (uint32_t i = 0; i < size && count < MAX_QUEUE_SIZE; ++i) {
            queue_t *queue = (queue_t *)(uintptr_t)urpc_qhs[i];
            qinfo->urpc_qh = urpc_qhs[i];
            qinfo->status = queue->status;
            qinfo->ref_cnt = (uint32_t)queue->ref_cnt;

            count++;
            qinfo++;
        }
    }
    info->r_qnum = count;
    (void)pthread_rwlock_unlock(&channel->rw_lock);
}

queue_t *channel_get_next_local_queue(urpc_channel_info_t *channel)
{
    (void)pthread_spin_lock(&channel->lock);
    bool reset = true;
    queue_node_t *cur_node = channel->cur_rr_local_queue;
    if (cur_node == NULL) {
        reset = false;
        cur_node = URPC_SLIST_FIRST(&channel->l_queue_nodes_head);
    }

    while (cur_node != NULL) {
        queue_t *queue = (queue_t *)(uintptr_t)cur_node->urpc_qh;
        if (queue->status == QUEUE_STATUS_READY) {
            channel->cur_rr_local_queue = URPC_SLIST_NEXT(cur_node, node);
            (void)pthread_spin_unlock(&channel->lock);
            return queue;
        }
        cur_node = cur_node->node.next;
        if (cur_node == NULL && reset) {
            reset = false;
            cur_node = URPC_SLIST_FIRST(&channel->l_queue_nodes_head);
        }
    }
    (void)pthread_spin_unlock(&channel->lock);
    URPC_LIB_LOG_DEBUG("local queue is null\n");

    return NULL;
}

queue_t *channel_get_next_remote_queue(urpc_channel_info_t *channel)
{
    (void)pthread_spin_lock(&channel->lock);
    bool reset = true;
    queue_node_t *cur_node = channel->cur_rr_remote_queue;
    if (cur_node == NULL) {
        reset = false;
        cur_node = URPC_SLIST_FIRST(&channel->r_queue_nodes_head);
    }

    while (cur_node != NULL) {
        queue_t *queue = (queue_t *)(uintptr_t)cur_node->urpc_qh;
        if (queue->status == QUEUE_STATUS_READY) {
            channel->cur_rr_remote_queue = URPC_SLIST_NEXT(cur_node, node);
            (void)pthread_spin_unlock(&channel->lock);

            return queue;
        }
        cur_node = cur_node->node.next;
        if (cur_node == NULL && reset) {
            reset = false;
            cur_node = URPC_SLIST_FIRST(&channel->r_queue_nodes_head);
        }
    }

    (void)pthread_spin_unlock(&channel->lock);
    URPC_LIB_LOG_DEBUG("remote queue is null\n");

    return NULL;
}

queue_t *channel_get_cur_poll_queue(urpc_channel_info_t *channel)
{
    (void)pthread_spin_lock(&channel->lock);
    queue_node_t *cur_node = channel->cur_poll_queue;
    if (cur_node == NULL) {
        cur_node = URPC_SLIST_FIRST(&channel->l_queue_nodes_head);
        if (cur_node == NULL) {
            (void)pthread_spin_unlock(&channel->lock);
            URPC_LIB_LIMIT_LOG_DEBUG("local queue is null\n");
            return NULL;
        }
    }
    channel->cur_poll_queue = URPC_SLIST_NEXT(cur_node, node);
    (void)pthread_spin_unlock(&channel->lock);

    return (queue_t *)(uintptr_t)cur_node->urpc_qh;
}

queue_t *channel_get_local_queue_by_handle(urpc_channel_info_t *channel, uint64_t urpc_qh)
{
    queue_t *queue = NULL;
    queue_node_t *cur_node;
    URPC_SLIST_FOR_EACH(cur_node, &channel->l_queue_nodes_head, node) {
        if (cur_node->urpc_qh == urpc_qh) {
            queue = (queue_t *)(uintptr_t)urpc_qh;
            if (queue->status != QUEUE_STATUS_READY) {
                URPC_LIB_LOG_DEBUG("queue status not ready\n");
                queue = NULL;
            }
            return queue;
        }
    }
    URPC_LIB_LOG_DEBUG("local queue not found\n");

    return NULL;
}

queue_t *channel_get_remote_queue_by_handle(urpc_channel_info_t *channel, uint64_t urpc_qh)
{
    queue_t *queue = NULL;
    queue_node_t *cur_node;
    URPC_SLIST_FOR_EACH(cur_node, &channel->r_queue_nodes_head, node) {
        if (cur_node->urpc_qh == urpc_qh) {
            queue = (queue_t *)(uintptr_t)urpc_qh;
            if (queue->status != QUEUE_STATUS_READY) {
                URPC_LIB_LOG_DEBUG("queue status not ready\n");
                queue = NULL;
            }
            return queue;
        }
    }
    URPC_LIB_LOG_DEBUG("remote queue not found\n");

    return queue;
}

// only used for search one manage queue, because manage channel only has one abort queue and one keepalive queue
queue_t *channel_get_remote_queue_by_flag(urpc_channel_info_t *channel, urpc_queue_flag_t flag)
{
    queue_t *queue = NULL;
    queue_node_t *cur_node;

    (void)pthread_rwlock_rdlock(&channel->rw_lock);
    URPC_SLIST_FOR_EACH(cur_node, &channel->r_queue_nodes_head, node) {
        queue = (queue_t *)(uintptr_t)cur_node->urpc_qh;
        if (is_queue_flag_same(queue->flag, flag)) {
            if (queue->status != QUEUE_STATUS_READY) {
                URPC_LIB_LOG_DEBUG("queue status not ready\n");
                queue = NULL;
            }
            (void)pthread_rwlock_unlock(&channel->rw_lock);

            return queue;
        }
    }

    (void)pthread_rwlock_unlock(&channel->rw_lock);
    URPC_LIB_LOG_DEBUG("remote queue not found\n");

    return queue;
}

queue_t *channel_get_remote_queue_by_qid(urpc_channel_info_t *channel, uint32_t qid)
{
    queue_t *queue = NULL;
    urpc_qcfg_get_t cfg_get = {0};
    server_node_t *server_node = channel_get_server_node(channel, NULL);
    if (server_node == NULL) {
        URPC_LIB_LIMIT_LOG_DEBUG("server node is null\n");
        return NULL;
    }
    for (uint32_t i = 0; i < server_node->urpc_qh_count; i++) {
        queue = (queue_t *)(uintptr_t)server_node->urpc_qh[i];
        if (urpc_queue_cfg_get(server_node->urpc_qh[i], &cfg_get) != URPC_SUCCESS) {
            continue;
        }
        if (cfg_get.qid == qid) {
            return queue;
        }
    }
    URPC_LIB_LOG_DEBUG("remote queue not found\n");
    return NULL;
}

uint32_t channel_num_get(void)
{
    return g_urpc_channel_id_allocator.next_id - g_urpc_channel_id_allocator.num_available;
}

static void channel_query_req_entry_info(urpc_channel_info_t *channel, uint64_t *stats, int stats_len)
{
    for (int i = 0; i < (int)CHANNEL_STATS_TYPE_MAX && i < stats_len; i++) {
        stats[i] = channel->stats[i];
    }
}

static void channel_server_info_get(urpc_channel_info_t *channel, channel_server_info_t *output, uint32_t cnt)
{
    server_node_t *server_node;
    uint32_t i = 0;
    URPC_LIST_FOR_EACH(server_node, node, &channel->server_nodes_list) {
        output[i].info = server_node->endpoints.server;
        output[i++].key = server_node->instance_key;
    }
}

int channel_info_get(uint32_t urpc_chid, char **output, uint32_t *output_size)
{
    urpc_channel_info_t *channel = channel_get(urpc_chid);
    if (channel == NULL) {
        URPC_LIB_LOG_ERR("failed to get channel[%u]\n", urpc_chid);
        return URPC_FAIL;
    }

    (void)pthread_rwlock_rdlock(&channel->rw_lock);
    size_t server_cnt = urpc_list_size(&channel->server_nodes_list);
    uint32_t cqi_size = (uint32_t)sizeof(channel_query_info_t) + server_cnt * (uint32_t)sizeof(channel_server_info_t);
    channel_query_info_t *cqi = (channel_query_info_t *)urpc_dbuf_calloc(URPC_DBUF_TYPE_CHANNEL, 1, cqi_size);
    if (cqi == NULL) {
        (void)pthread_rwlock_unlock(&channel->rw_lock);
        URPC_LIB_LOG_ERR("failed to malloc, errno: %d\n", errno);
        return -URPC_ERR_ENOMEM;
    }

    channel_query_req_entry_info(channel, (uint64_t *)cqi->req_entry_stats, CHANNEL_STATS_TYPE_MAX);
    urpc_query_timer_info(urpc_chid, false, (uint64_t *)cqi->timer_stats, TIMER_STATS_TYPE_MAX);
    channel_server_info_get(channel, cqi->server, cqi->server_cnt);
    cqi->server_cnt = server_cnt;
    (void)pthread_rwlock_unlock(&channel->rw_lock);

    *output = (char *)cqi;
    *output_size = cqi_size;

    return URPC_SUCCESS;
}

int urpc_mem_seg_remote_access_enable(uint32_t urpc_chid, uint64_t mem_h)
{
    if (mem_h == URPC_INVALID_HANDLE) {
        URPC_LIB_LOG_ERR("invalid memory handle\n");
        return -URPC_ERR_EINVAL;
    }

    urpc_channel_info_t *channel = channel_get(urpc_chid);
    if (channel == NULL || channel->provider == NULL) {
        URPC_LIB_LOG_ERR("get channel[%u] failed\n", urpc_chid);
        return -URPC_ERR_EINVAL;
    }

    (void)pthread_rwlock_wrlock(&channel->mem_info_lock);
    if (channel->mem_info_num >= MAX_MEM_H_SIZE) {
        (void)pthread_rwlock_unlock(&channel->mem_info_lock);
        URPC_LIB_LOG_ERR("chanel [%u] has mem info num %u, Cannot continue adding\n", urpc_chid, channel->mem_info_num);
        return -URPC_ERR_EBUSY;
    }

    channel_mem_info_t *cur_mem_info;
    URPC_LIST_FOR_EACH(cur_mem_info, node, &channel->mem_info_list) {
        if (cur_mem_info->mem_h == mem_h) {
            (void)pthread_rwlock_unlock(&channel->mem_info_lock);
            URPC_LIB_LOG_ERR("memory handle exists\n");
            return -URPC_ERR_EINVAL;
        }
    }

    urma_target_seg_t *target_seg = (urma_target_seg_t *)(uintptr_t) \
        ((mem_handle_t *)(uintptr_t)mem_h)->handle[channel->provider->idx];
    urma_seg_t *seg = &target_seg->seg;
    uint32_t token = (uint32_t)target_seg->user_ctx;
    channel_mem_info_t *mem_info =
        (channel_mem_info_t *)urpc_dbuf_malloc(URPC_DBUF_TYPE_CHANNEL, sizeof(channel_mem_info_t));
    if (mem_info == NULL) {
        (void)pthread_rwlock_unlock(&channel->mem_info_lock);
        URPC_LIB_LOG_ERR("memory alloc failed\n");
        return -URPC_FAIL;
    }
    mem_info->mem_h = mem_h;
    mem_info->xchg_mem_info.seg_flag = (urma_import_seg_flag_t)seg->attr.value;
    mem_info->xchg_mem_info.seg_len = seg->len;
    mem_info->xchg_mem_info.seg_token_id = seg->token_id;
    mem_info->xchg_mem_info.token.token = token;
    memcpy(&mem_info->xchg_mem_info.ubva, &seg->ubva, sizeof(urma_ubva_t));
    urpc_list_push_back(&channel->mem_info_list, &mem_info->node);
    channel->mem_info_num++;

    (void)pthread_rwlock_unlock(&channel->mem_info_lock);
    URPC_LIB_LOG_INFO("chid[%u] mem seg remote access enable success\n", urpc_chid);

    return URPC_SUCCESS;
}

int urpc_mem_seg_remote_access_disable(uint32_t urpc_chid, uint64_t mem_h)
{
    if (mem_h == URPC_INVALID_HANDLE) {
        URPC_LIB_LOG_ERR("invalid memory handle\n");
        return -URPC_ERR_EINVAL;
    }

    urpc_channel_info_t *channel = channel_get(urpc_chid);
    if (channel == NULL || channel->provider == NULL) {
        URPC_LIB_LOG_ERR("get channel[%u] failed\n", urpc_chid);
        return -URPC_ERR_EINVAL;
    }

    bool find = false;
    (void)pthread_rwlock_wrlock(&channel->mem_info_lock);

    channel_mem_info_t *cur_mem_info, *mem_info_next;
    URPC_LIST_FOR_EACH_SAFE(cur_mem_info, mem_info_next, node, &channel->mem_info_list) {
        if (cur_mem_info->mem_h == mem_h) {
            urpc_list_remove(&cur_mem_info->node);
            urpc_dbuf_free(cur_mem_info);
            find = true;
            break;
        }
    }

    if (!find) {
        (void)pthread_rwlock_unlock(&channel->mem_info_lock);
        URPC_LIB_LOG_ERR("memory handle not exits\n");
        return -URPC_ERR_EINVAL;
    }

    channel->mem_info_num--;
    (void)pthread_rwlock_unlock(&channel->mem_info_lock);
    URPC_LIB_LOG_INFO("chid[%u] mem seg remote access disable success\n", urpc_chid);

    return URPC_SUCCESS;
}

static void reset_server_node(server_node_t *server_node, void *chmsg_input, urpc_endpoints_t *endpoints)
{
    urpc_chmsg_v1_t *chmsg = (urpc_chmsg_v1_t *)chmsg_input;
    server_node->endpoints = *endpoints;
    server_node->server_chid = chmsg->chinfo->chid;
    server_node->cap = chmsg->chinfo->cap;
    server_node->instance_key = chmsg->chinfo->key;
}

void channel_flush_server_node(server_node_t *server_node, void *chmsg_input, urpc_endpoints_t *endpoints)
{
    uint32_t i = 0;
    uint64_t added_rqh[MAX_QUEUE_SIZE];
    uint32_t added_rq_num = 0;
    queue_t *queue = NULL;
    for (i = 0; i < server_node->urpc_qh_count; i++) {
        queue = (queue_t *)(uintptr_t)server_node->urpc_qh[i];
        if (queue->ref_cnt == 0) {
            queue->ops->delete_remote_queue(queue);
        } else {
            queue->status = QUEUE_STATUS_ERR;
            added_rqh[added_rq_num++] = server_node->urpc_qh[i];
        }
    }
    server_node_qh_update(server_node, added_rqh, added_rq_num);
    // reset server info
    reset_server_node(server_node, chmsg_input, endpoints);
    if (server_node->cipher_opt != NULL) {
        (void)memset(server_node->cipher_opt, 0, sizeof(urpc_cipher_t));
        server_node->cipher_opt->chid = URPC_INVALID_ID_U32;
    }
}

void channel_update_server_node(server_node_t *server_node, void *chmsg_input, urpc_endpoints_t *endpoints)
{
    // update server_chid/cipher info in case that server channel is re-created
    urpc_chmsg_v1_t *chmsg = (urpc_chmsg_v1_t *)chmsg_input;
    if (server_node->server_chid != chmsg->chinfo->chid) {
        crypto_cipher_uninit(server_node->cipher_opt);
    }
    reset_server_node(server_node, chmsg_input, endpoints);
}
