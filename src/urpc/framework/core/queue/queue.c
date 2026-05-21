/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2024-2024. All rights reserved.
 * Description: queue function
 */
#include <pthread.h>
#include <unistd.h>
#include <string.h>

#include "cp.h"
#include "dp.h"
#include "urpc_hash.h"
#include "urpc_lib_log.h"
#include "urpc_framework_errno.h"
#include "urpc_id_generator.h"
#include "queue.h"

typedef struct provider_ctx {
    provider_flag_t flag;
    provider_t *cur_provider;
    pthread_mutex_t provider_alloc_mutex;           // mutex to protect the allocation of the provider
                                                    // when the multi-eid feature is enabled
    uint32_t cur_idx;
} provider_ctx_t;

static struct urpc_list g_urpc_queue_ops_list;
static pthread_mutex_t g_urpc_queue_ops_mutex = PTHREAD_MUTEX_INITIALIZER;
static struct urpc_list g_urpc_provider_ops_list;
static pthread_mutex_t g_urpc_provider_ops_mutex = PTHREAD_MUTEX_INITIALIZER;
static queue_ctx_info_t g_urpc_queue_ctx_infos[QUEUE_CTX_TYPE_MAX];
static bool g_urpc_queue_stats_enable = true;
static urpc_id_generator_t g_urpc_qid_gen;
static provider_ctx_t g_urpc_provider_ctx;
static queue_transport_ctx_t g_urpc_queue_transport_ctx;

static const char *g_urpc_queue_stats_name[] = {
    "request_send",
    "request_sges_send",
    "request_bytes_send",
    "request_dma_sges",
    "request_dma_bytes",
    "ack_send",
    "ack_sges_send",
    "ack_bytes_send",
    "response_send",
    "response_sges_send",
    "response_bytes_send",
    "ack_and_response_send",
    "ack_and_response_sges_send",
    "ack_and_response_bytes_send",
    "read",
    "read_sges",
    "read_bytes",

    "request_send_confirmed",
    "request_sges_send_confirmed",
    "request_bytes_send_confirmed",
    "ack_send_confirmed",
    "ack_sges_send_confirmed",
    "ack_bytes_send_confirmed",
    "response_send_confirmed",
    "response_sges_send_confirmed",
    "response_bytes_send_confirmed",
    "ack_and_response_send_confirmed",
    "ack_and_response_sges_send_confirmed",
    "ack_and_response_bytes_send_confirmed",
    "read_confirmed",
    "read_sges_confirmed",
    "read_bytes_confirmed",

    "request_receive",
    "request_sges_receive",
    "request_bytes_receive",
    "ack_receive",
    "ack_sges_receive",
    "ack_bytes_receive",
    "response_receive",
    "response_sges_receive",
    "response_bytes_receive",
    "ack_and_response_receive",
    "ack_and_response_sges_receive",
    "ack_and_response_bytes_receive",

    "plog_req_cnt",
    "plog_req_sges",
    "plog_req_bytes",

    "early_rsp_without_ack_req_sended",
    "early_rsp_without_ack_req_rsped",
    "early_rsp_with_ack_req_sended",
    "early_rsp_with_ack_req_acked_rsped",
    "normal_with_ack_req_sended",
    "normal_with_ack_req_acked_rsped",
    "normal_with_ack_req_acked",
    "normal_without_ack_req_sended",
    "normal_without_ack_req_rsped",
};

static const char *g_urpc_queue_error_stats_name[] = {
    "error_invalid_parameter",
    "error_invalid_memory_handle",
    "error_invalid_header_version",
    "error_invalid_header_length",
    "error_invalid_header_rsn",
    "error_invalid_header_func_defined",
    "error_no_channel",
    "error_no_local_queue",
    "error_no_remote_queue",
    "error_no_memory",
    "error_send",
    "error_read",
    "error_read_eagain",
    "error_poll",
    "error_post",

    "error_ack_no_allocator_buffer",
    "error_ack_allocator_buffer_length_invalid",
    "error_ack_get_tx_ctx_failed",
    "error_ack_failed",

    "error_ack_rsp_no_allocator_buffer",
    "error_ack_rsp_allocator_buffer_length_invalid",
    "error_ack_rsp_get_tx_ctx_failed",
    "error_ack_rsp_failed",

    "error_req_invalid_header_length",
    "error_req_invalid_header_version",
    "error_req_no_remote_queue",
    "error_req_get_req_ctx_memory_failed",
    "error_read_req_invalid_dma_cnt",
    "error_read_req_get_dma_pos_failed",
    "error_read_req_invalid_dma_len",
    "error_read_req_get_read_tx_ctx_failed",
    "error_read_req_parm_invalid",
    "error_read_req_provider_invalid",
    "error_read_data_post_invalid_dma_info",
    "error_req_read_err_cqe",
    "error_req_read_err_data_trans_mode",

    "error_func_call_param_invalid",
    "error_func_call_no_channel",
    "error_func_call_no_local_queue",
    "error_func_call_no_remote_queue",
    "error_func_call_get_tx_ctx_failed",
    "error_func_call_no_rsn",
    "error_func_call_queue_protocol_mismatch",
    "error_func_call_send_failed",

    "error_ext_func_call_param_invalid",
    "error_ext_func_call_param_valid_failed",
    "error_ext_func_call_fill_ext_hdr_failed",
    "error_ext_func_call_mode_invalid",

    "error_ext_func_call_fill_dma_info_no_channel",
    "error_ext_func_call_fill_dma_info_no_provider",
    "error_ext_func_call_fill_dma_info_sge_num_invalid",
    "error_ext_func_call_fill_dma_info_not_have_no_mem_sge",
    "error_ext_func_call_fill_dma_info_dma_cnt_zero",
    "error_ext_func_call_fill_dma_info_sge_flag_err",
    "error_ext_func_call_fill_dma_info_get_raw_buf_failed",
    "error_ext_func_call_fill_dma_info_mem_h_invalid",

    "error_call_select_queue_no_channel",
    "error_call_select_queue_no_local_queue",

    "error_req_early_rsp_without_ack",
    "error_req_early_rsp_with_ack",
    "error_req_normal_with_ack",
    "error_req_normal_without_ack",
    "error_response",
};

_Static_assert((sizeof(g_urpc_queue_stats_name) / sizeof(g_urpc_queue_stats_name[0])) == STATS_TYPE_MAX,
    "g_urpc_queue_stats_name size is inconsistent with STATS_TYPE_MAX");

_Static_assert((sizeof(g_urpc_queue_error_stats_name) / sizeof(g_urpc_queue_error_stats_name[0])) == ERR_STATS_TYPE_MAX,
    "g_urpc_queue_error_stats_name size is inconsistent with ERR_STATS_TYPE_MAX");

static volatile uint64_t g_urpc_queue_error_stats[ERR_STATS_TYPE_MAX];

void queue_stats_enable(void)
{
    g_urpc_queue_stats_enable = true;
    URPC_LIB_LOG_INFO("enable queue stats successful\n");
}

void queue_stats_disable(void)
{
    g_urpc_queue_stats_enable = false;
    URPC_LIB_LOG_INFO("disable queue stats successful\n");
}

bool is_queue_stats_enable(void)
{
    return g_urpc_queue_stats_enable;
}

queue_transport_ctx_t *get_queue_transport_ctx(void)
{
    return &g_urpc_queue_transport_ctx;
}

void queue_list_push(queue_local_t *local_q)
{
    (void)pthread_mutex_lock(&g_urpc_queue_transport_ctx.queue_list_mutex);
    urpc_list_push_back(&g_urpc_queue_transport_ctx.queue_list, &local_q->node);
    (void)pthread_mutex_unlock(&g_urpc_queue_transport_ctx.queue_list_mutex);
}

void queue_list_pop(queue_local_t *local_q)
{
    (void)pthread_mutex_lock(&g_urpc_queue_transport_ctx.queue_list_mutex);
    urpc_list_remove(&local_q->node);
    (void)pthread_mutex_unlock(&g_urpc_queue_transport_ctx.queue_list_mutex);
}

void queue_register_ops(queue_ops_t *queue_ops)
{
    (void)pthread_mutex_lock(&g_urpc_queue_ops_mutex);
    urpc_list_push_back(&g_urpc_queue_ops_list, &queue_ops->node);
    (void)pthread_mutex_unlock(&g_urpc_queue_ops_mutex);
}

queue_ops_t *queue_get_ops(urpc_queue_trans_mode_t mode)
{
    queue_ops_t *queue_ops;
    (void)pthread_mutex_lock(&g_urpc_queue_ops_mutex);
    URPC_LIST_FOR_EACH(queue_ops, node, &g_urpc_queue_ops_list)
    {
        if (queue_ops->mode == mode) {
            (void)pthread_mutex_unlock(&g_urpc_queue_ops_mutex);
            return queue_ops;
        }
    }
    (void)pthread_mutex_unlock(&g_urpc_queue_ops_mutex);
    return NULL;
}

void provider_list_push(provider_t *provider)
{
    urpc_list_push_back(&g_urpc_queue_transport_ctx.provider_list, &provider->node);
}

void provider_list_pop(provider_t *provider)
{
    urpc_list_remove(&provider->node);
}

void provider_register_ops(provider_ops_t *provider_ops)
{
    (void)pthread_mutex_lock(&g_urpc_provider_ops_mutex);
    urpc_list_push_back(&g_urpc_provider_ops_list, &provider_ops->node);
    (void)pthread_mutex_unlock(&g_urpc_provider_ops_mutex);
}

provider_ops_t *provider_get_ops(provider_ops_mode_t mode)
{
    provider_ops_t *provider_ops;
    (void)pthread_mutex_lock(&g_urpc_provider_ops_mutex);
    URPC_LIST_FOR_EACH(provider_ops, node, &g_urpc_provider_ops_list)
    {
        if (provider_ops->mode == mode) {
            (void)pthread_mutex_unlock(&g_urpc_provider_ops_mutex);
            return provider_ops;
        }
    }
    (void)pthread_mutex_unlock(&g_urpc_provider_ops_mutex);
    return NULL;
}

int provider_init(uint8_t cfg_num, urpc_trans_info_t *cfg, provider_flag_t flag)
{
    uint32_t fail_count = 0;
    uint32_t provider_count = 0;

    urpc_list_init(&g_urpc_queue_transport_ctx.queue_list);
    urpc_list_init(&g_urpc_queue_transport_ctx.provider_list);
    (void)pthread_mutex_init(&g_urpc_queue_transport_ctx.queue_list_mutex, NULL);
    (void)pthread_mutex_init(&g_urpc_provider_ctx.provider_alloc_mutex, NULL);

    (void)pthread_mutex_lock(&g_urpc_provider_ops_mutex);
    size_t ops_size = urpc_list_size(&g_urpc_provider_ops_list);
    if (ops_size == 0) {
        (void)pthread_mutex_unlock(&g_urpc_provider_ops_mutex);
        URPC_LIB_LOG_ERR("empty provider ops list\n");
        return URPC_FAIL;
    }

    for (uint32_t i = 0; i < cfg_num; i++) {
        provider_init_opt_t opt = { .cfg = &cfg[i], .flag = flag, .start_idx = g_urpc_provider_ctx.cur_idx };
        provider_ops_t *provider_ops;
        URPC_LIST_FOR_EACH(provider_ops, node, &g_urpc_provider_ops_list) {
            uint32_t cnt = provider_ops->init(&opt);
            if (cnt != 0) {
                provider_count += cnt;
                g_urpc_provider_ctx.cur_idx += cnt;
            } else {
                URPC_LIB_LOG_WARN("provider[%d] failed to init trans info[%u]\n", provider_ops->mode, i);
                fail_count++;
            }
        }
    }
    (void)pthread_mutex_unlock(&g_urpc_provider_ops_mutex);

    if (provider_count == 0) {
        URPC_LIB_LOG_ERR("all providers failed to init\n");
        return URPC_FAIL;
    }

    g_urpc_provider_ctx.flag = flag;
    URPC_LIST_FIRST_NODE(g_urpc_provider_ctx.cur_provider, node, &g_urpc_queue_transport_ctx.provider_list);

    if (fail_count != 0) {
        URPC_LIB_LOG_ERR("partial providers failed to init, count :%u\n", fail_count);
        return -URPC_ERR_INIT_PART_FAIL;
    }

    URPC_LIB_LOG_INFO("providers all success to init, count :%u\n", provider_count);

    return URPC_SUCCESS;
}

void flush_callback(queue_t *queue, void *data, int status_code, flush_type_t type)
{
    if (data == NULL) {
        URPC_LIB_LOG_ERR("UDMA reports no %s user context, status code: %d\n",
            (type == TX) ? "TX" : "RX", status_code);
        return;
    }

    queue_local_t *local_q = CONTAINER_OF_FIELD(queue, queue_local_t, queue);
    urpc_allocator_option_t option = {.qcustom_flag = local_q->cfg.custom_flag};
    if (type == TX) {
        /* user guarantees that there is no concurrency here. */
        int ret = queue_ctx_validate(queue, QUEUE_CTX_TYPE_TX, data);
        if (ret == -URPC_ERR_EPERM) {
            URPC_LIB_LOG_ERR("UDMA reports repeated TX user context, status code: %d\n", status_code);
            return;
        }

        tx_ctx_t *ctx = (tx_ctx_t *)data;
        req_entry_t *req_entry = req_entry_query(ctx->channel_id, ctx->req_id, false);
        if (req_entry != NULL) {
            req_entry_put(req_entry);
        }
        // no event report to user yet
        if (ctx->sge_handover_completed == URPC_FALSE) {
            default_allocator_get()->put(ctx->sges, ctx->sge_num, &option);
        }
        queue_ctx_put(QUEUE_CTX_TYPE_TX, ctx);
    } else if (type == RX) {
        struct rx_user_ctx *ctx = (struct rx_user_ctx *)data;
        default_allocator_get()->put(ctx->sges, ctx->sge_num, &option);
        rx_user_ctx_put(ctx);
    }
}

void provider_uninit(void)
{
    (void)pthread_mutex_lock(&g_urpc_queue_ops_mutex);
    if (urpc_list_is_empty(&g_urpc_provider_ops_list)) {
        (void)pthread_mutex_unlock(&g_urpc_queue_ops_mutex);
        return;
    }

    provider_t *provider_cur = NULL;
    provider_t *provider_next = NULL;
    URPC_LIST_FOR_EACH_SAFE(provider_cur, provider_next, node, &g_urpc_queue_transport_ctx.provider_list) {
        provider_cur->ops->uninit(provider_cur);
    }
    (void)pthread_mutex_unlock(&g_urpc_queue_ops_mutex);
    (void)pthread_mutex_destroy(&g_urpc_queue_transport_ctx.queue_list_mutex);
    (void)pthread_mutex_destroy(&g_urpc_provider_ctx.provider_alloc_mutex);
    memset(&g_urpc_provider_ctx, 0, sizeof(g_urpc_provider_ctx));
}

uint32_t provider_get_list_size(void)
{
    return g_urpc_provider_ctx.cur_idx;
}

void queue_slab_uninit(queue_local_t *local_q)
{
    for (int i = 0; i < (int)QUEUE_CTX_TYPE_MAX; i++) {
        if (local_q->slab[i].addr == NULL) {
            continue;
        }
        urpc_dbuf_free(local_q->slab[i].addr);
        local_q->slab[i].addr = NULL;
        eslab_uninit(&local_q->slab[i]);
    }
}

static inline uint32_t queue_ctx_num_get(queue_ctx_direction_t direction, queue_local_t *local_q)
{
    return direction == QUEUE_CTX_RX ? local_q->cfg.rx_depth : local_q->cfg.tx_depth;
}

int queue_slab_init(queue_local_t *local_q)
{
    queue_ctx_info_t ctx_infos[QUEUE_CTX_TYPE_MAX];
    queue_ctx_infos_get(ctx_infos, QUEUE_CTX_TYPE_MAX);
    uint32_t num;
    for (int i = 0; i < (int)QUEUE_CTX_TYPE_MAX; i++) {
        // if queue depth is 0, this queue won't use ctx
        num = queue_ctx_num_get(ctx_infos[i].direction, local_q);
        if (num == 0) {
            local_q->slab[i].next_free = UINT32_MAX;
            continue;
        }

        uint32_t size = ctx_infos[i].size + sizeof(queue_ctx_head_t);
        char *buf = urpc_dbuf_malloc(URPC_DBUF_TYPE_QUEUE, size * num);
        if (buf == NULL) {
            goto ERROR;
        }

        eslab_init(&local_q->slab[i], buf, size, num);
    }

    return 0;

ERROR:
    queue_slab_uninit(local_q);

    URPC_LIB_LOG_ERR("malloc local queue ctx failed\n");
    return -1;
}

void queue_ctx_infos_set(queue_ctx_info_t *info, int num)
{
    for (int i = 0; i < num; i++) {
        g_urpc_queue_ctx_infos[info[i].type] = info[i];
    }
}

void queue_ctx_infos_get(queue_ctx_info_t *info, int num)
{
    for (int i = 0; i < num && i < (int)QUEUE_CTX_TYPE_MAX; i++) {
        info[i] = g_urpc_queue_ctx_infos[i];
    }
}

size_t queue_ctx_size_get(queue_ctx_type_t type)
{
    return g_urpc_queue_ctx_infos[type].size;
}

void queue_common_error_stats_record(urpc_error_stats_type_t type)
{
    (void)__sync_add_and_fetch(&g_urpc_queue_error_stats[type], 1);
}

void queue_common_error_stats_get(uint64_t *stats, int stats_len)
{
    for (int i = 0; i < (int)ERR_STATS_TYPE_MAX && i < stats_len; i++) {
        stats[i] = (uint64_t)__sync_add_and_fetch(&g_urpc_queue_error_stats[i], 0);
    }
}

void queue_stats_get(queue_t *queue, uint64_t *stats, int stats_len)
{
    queue_local_t *local_q = CONTAINER_OF_FIELD(queue, queue_local_t, queue);
    for (int i = 0; i < (int)STATS_TYPE_MAX && i < stats_len; i++) {
        stats[i] = (uint64_t)__sync_add_and_fetch(&local_q->stats[i], 0);
    }
}

void queue_error_stats_get(queue_t *queue, uint64_t *stats, int stats_len)
{
    queue_local_t *local_q = CONTAINER_OF_FIELD(queue, queue_local_t, queue);
    for (int i = 0; i < (int)ERR_STATS_TYPE_MAX && i < stats_len; i++) {
        stats[i] = (uint64_t)__sync_add_and_fetch(&local_q->error_stats[i], 0);
    }
}

const char *queue_stats_name_get(int type)
{
    if (URPC_UNLIKELY(type >= (int)STATS_TYPE_MAX || type < 0)) {
        return "Unknown";
    }

    return g_urpc_queue_stats_name[type];
}

const char *queue_error_stats_name_get(int type)
{
    if (URPC_UNLIKELY(type >= (int)ERR_STATS_TYPE_MAX || type < 0)) {
        return "Unknown";
    }

    return g_urpc_queue_error_stats_name[type];
}

#if defined URPC_ASAN || defined URPC_CODE_COVERAGE
// use malloc ctx in asan mode, and record eslab ctx if available
void *queue_ctx_get(queue_t *l_queue, queue_ctx_type_t type)
{
    queue_local_t *local_q = CONTAINER_OF_FIELD(l_queue, queue_local_t, queue);
    if (URPC_UNLIKELY(local_q->slab[type].addr == NULL)) {
        return NULL;
    }

    queue_ctx_head_t *debug_ctx = queue_ctx_malloc(local_q, type);
    if (URPC_UNLIKELY(debug_ctx == NULL)) {
        return NULL;
    }

    queue_ctx_head_t *ctx_head;
    if (URPC_LIKELY(local_q->cfg.lock_free != 0)) {
        ctx_head = (queue_ctx_head_t *)eslab_get_buf_lockless(&local_q->slab[type]);
    } else {
        ctx_head = (queue_ctx_head_t *)eslab_get_buf(&local_q->slab[type]);
    }

    if (URPC_UNLIKELY(ctx_head == NULL)) {
        if (URPC_UNLIKELY(errno != URPC_ERR_ENOMEM)) {
            urpc_dbuf_free(debug_ctx);
            return NULL;
        }

        debug_ctx->eslab_ctx = NULL;
        return (void *)debug_ctx->buf;
    }

    ctx_head->l_queue = local_q;
    ctx_head->is_eslab = URPC_TRUE;
    ctx_head->in_use = URPC_TRUE;
    debug_ctx->eslab_ctx = ctx_head;
    return (void *)debug_ctx->buf;
}

void queue_ctx_put(queue_ctx_type_t type, void *ctx)
{
    if (URPC_UNLIKELY(ctx == NULL)) {
        return;
    }

    queue_ctx_head_t *debug_ctx = CONTAINER_OF_FIELD(ctx, queue_ctx_head_t, buf);
    if (debug_ctx->eslab_ctx != NULL) {
        if (URPC_LIKELY(debug_ctx->l_queue->cfg.lock_free != 0)) {
            eslab_put_buf_lockless(&debug_ctx->l_queue->slab[type], (void *)debug_ctx->eslab_ctx);
        } else {
            eslab_put_buf(&debug_ctx->l_queue->slab[type], (void *)debug_ctx->eslab_ctx);
        }
    }
    urpc_dbuf_free(debug_ctx);
}
#endif

int get_local_queues(uint32_t queue_max, uint64_t *qh, uint32_t *queue_num)
{
    size_t local_q_num = 0;
    queue_local_t *local_q = NULL;

    (void)pthread_mutex_lock(&g_urpc_queue_transport_ctx.queue_list_mutex);
    URPC_LIST_FOR_EACH(local_q, node, &g_urpc_queue_transport_ctx.queue_list) {
        // find 1. queues that are not related to keep alive queue.
        if (local_q->queue.flag.is_keepalive == URPC_FALSE) {
            qh[local_q_num++] = (uint64_t)(uintptr_t)local_q;
        }
    }

    if (local_q_num > queue_max) {
        (void)pthread_mutex_unlock(&g_urpc_queue_transport_ctx.queue_list_mutex);
        URPC_LIB_LOG_ERR("queue number(%u) exceed upper limit(%u)\n", local_q_num, queue_max);
        return URPC_FAIL;
    }

    if (local_q_num == 0) {
        (void)pthread_mutex_unlock(&g_urpc_queue_transport_ctx.queue_list_mutex);
        URPC_LIB_LOG_ERR("find queue info failed\n");
        return URPC_FAIL;
    }
    (void)pthread_mutex_unlock(&g_urpc_queue_transport_ctx.queue_list_mutex);

    *queue_num = (uint32_t)local_q_num;

    return URPC_SUCCESS;
}

uint64_t get_one_local_queue_by_qid(uint64_t qid)
{
    queue_local_t *local_q = NULL;
    (void)pthread_mutex_lock(&g_urpc_queue_transport_ctx.queue_list_mutex);
    URPC_LIST_FOR_EACH(local_q, node, &g_urpc_queue_transport_ctx.queue_list)
    {
        // find 1. queues that are not related to keep alive queue.
        if ((local_q->queue.flag.is_keepalive == URPC_FALSE) && local_q->qid == qid) {
            (void)pthread_mutex_unlock(&g_urpc_queue_transport_ctx.queue_list_mutex);
            return (uint64_t)(uintptr_t)local_q;
        }
    }
    (void)pthread_mutex_unlock(&g_urpc_queue_transport_ctx.queue_list_mutex);
    return URPC_INVALID_HANDLE;
}

int get_queue_trans_info(char **output, uint32_t *output_size)
{
    uint32_t output_size_ = 0;
    queue_local_t *local_q = NULL;

    (void)pthread_mutex_lock(&g_urpc_queue_transport_ctx.queue_list_mutex);
    URPC_LIST_FOR_EACH(local_q, node, &g_urpc_queue_transport_ctx.queue_list) {
        queue_t *queue = (queue_t *)(uintptr_t)local_q;
        output_size_ += queue->ops->query_trans_info(queue, QUEUE_QUERY_TRANS_INFO_SIZE, NULL);
    }

    if (output_size_ == 0) {
        (void)pthread_mutex_unlock(&g_urpc_queue_transport_ctx.queue_list_mutex);
        return URPC_SUCCESS;
    }

    char *output_ = (char *)urpc_dbuf_malloc(URPC_DBUF_TYPE_QUEUE, output_size_);
    if (output_ == NULL) {
        (void)pthread_mutex_unlock(&g_urpc_queue_transport_ctx.queue_list_mutex);
        URPC_LIB_LOG_ERR("Failed to malloc, errno: %d\n", errno);
        return URPC_FAIL;
    }

    uint32_t offset = 0;
    URPC_LIST_FOR_EACH(local_q, node, &g_urpc_queue_transport_ctx.queue_list) {
        if (offset >= output_size_) {
            (void)pthread_mutex_unlock(&g_urpc_queue_transport_ctx.queue_list_mutex);
            urpc_dbuf_free(output_);
            URPC_LIB_LOG_ERR("Exceed query output size\n");
            return URPC_FAIL;
        }

        queue_t *queue = (queue_t *)(uintptr_t)local_q;
        offset += queue->ops->query_trans_info(queue, QUEUE_QUERY_TRANS_INFO_DATA, output_ + offset);
    }

    (void)pthread_mutex_unlock(&g_urpc_queue_transport_ctx.queue_list_mutex);
    *output = output_;
    *output_size = output_size_;

    return URPC_SUCCESS;
}

void unadvise_local_queues(queue_t *r_queue)
{
    queue_local_t *local_q = NULL;
    (void)pthread_mutex_lock(&g_urpc_queue_transport_ctx.queue_list_mutex);
    URPC_LIST_FOR_EACH(local_q, node, &g_urpc_queue_transport_ctx.queue_list) {
        /* no need to advise/unadviseabort queue, keepalive queue */
        if (!is_queue_need_advise(&local_q->queue, r_queue)) {
            continue;
        }
        local_q->queue.ops->unbind_queue(&local_q->queue);
    }
    (void)pthread_mutex_unlock(&g_urpc_queue_transport_ctx.queue_list_mutex);
}

int advise_local_queues(queue_t *r_queue)
{
    if (r_queue == NULL) {
        URPC_LIB_LOG_ERR("r_queue is null\n");
        return -URPC_ERR_EINVAL;
    }

    queue_local_t *local_q = NULL;
    (void)pthread_mutex_lock(&g_urpc_queue_transport_ctx.queue_list_mutex);
    URPC_LIST_FOR_EACH(local_q, node, &g_urpc_queue_transport_ctx.queue_list) {
        /* no need to advise/unadvise abort queue, keepalive queue */
        if (!is_queue_need_advise(&local_q->queue, r_queue)) {
            continue;
        }

        if (local_q->queue.ops->bind_queue(&local_q->queue, r_queue) == URPC_SUCCESS) {
            continue;
        }

        queue_local_t *temp_local_q = NULL;
        URPC_LIST_FOR_EACH(temp_local_q, node, &g_urpc_queue_transport_ctx.queue_list) {
            if (temp_local_q == local_q) {
                break;
            }

            /* no need to advise/unadvise abort queue, keepalive queue */
            if (!is_queue_need_advise(&temp_local_q->queue, r_queue)) {
                continue;
            }

            temp_local_q->queue.ops->unbind_queue(&temp_local_q->queue);
        }
        (void)pthread_mutex_unlock(&g_urpc_queue_transport_ctx.queue_list_mutex);

        return URPC_FAIL;
    }
    (void)pthread_mutex_unlock(&g_urpc_queue_transport_ctx.queue_list_mutex);

    return URPC_SUCCESS;
}

void query_queues_stats(uint64_t *stats, int stats_len, uint64_t *error_stats, int error_stats_len)
{
    queue_local_t *local_q = NULL;
    uint64_t q_stats[STATS_TYPE_MAX];
    uint64_t q_error_stats[ERR_STATS_TYPE_MAX];

    (void)pthread_mutex_lock(&g_urpc_queue_transport_ctx.queue_list_mutex);
    URPC_LIST_FOR_EACH(local_q, node, &g_urpc_queue_transport_ctx.queue_list) {
        queue_stats_get(&local_q->queue, q_stats, STATS_TYPE_MAX);
        for (int i = 0; i < (int)STATS_TYPE_MAX && i < stats_len; i++) {
            stats[i] += q_stats[i];
        }

        queue_error_stats_get(&local_q->queue, q_error_stats, ERR_STATS_TYPE_MAX);
        for (int i = 0; i < (int)ERR_STATS_TYPE_MAX && i < error_stats_len; i++) {
            error_stats[i] += q_error_stats[i];
        }
    }
    (void)pthread_mutex_unlock(&g_urpc_queue_transport_ctx.queue_list_mutex);
}

int query_queues_stats_by_id(uint16_t qid, uint64_t *stats, int stats_len, uint64_t *error_stats, int error_stats_len)
{
    queue_local_t *local_q = NULL;
    (void)pthread_mutex_lock(&g_urpc_queue_transport_ctx.queue_list_mutex);
    URPC_LIST_FOR_EACH(local_q, node, &g_urpc_queue_transport_ctx.queue_list) {
        if (qid == local_q->qid) {
            queue_stats_get(&local_q->queue, stats, stats_len);
            queue_error_stats_get(&local_q->queue, error_stats, error_stats_len);
            (void)pthread_mutex_unlock(&g_urpc_queue_transport_ctx.queue_list_mutex);
            return URPC_SUCCESS;
        }
    }
    (void)pthread_mutex_unlock(&g_urpc_queue_transport_ctx.queue_list_mutex);
    return URPC_FAIL;
}

static inline provider_t *get_first_provider(void)
{
    provider_t *provider;
    URPC_LIST_FIRST_NODE(provider, node, &g_urpc_queue_transport_ctx.provider_list);
    return provider;
}

static inline bool is_provider_list_head(urpc_list_t *ptr)
{
    return (ptr == &g_urpc_queue_transport_ctx.provider_list);
}

provider_t *get_provider(urpc_eid_t *eid __attribute__((unused)))
{
    if (g_urpc_provider_ctx.flag.bs.multi_eid == URPC_FALSE) {
        return get_first_provider();
    }

    (void)pthread_mutex_lock(&g_urpc_provider_ctx.provider_alloc_mutex);
    provider_t *provider = g_urpc_provider_ctx.cur_provider;
    ASSIGN_CONTAINER_PTR(g_urpc_provider_ctx.cur_provider, (g_urpc_provider_ctx.cur_provider)->node.next, node);
    if (is_provider_list_head((urpc_list_t *)(uintptr_t)g_urpc_provider_ctx.cur_provider)) {
        /* Avoid to use list head as a provider node */
        g_urpc_provider_ctx.cur_provider = get_first_provider();
    }
    (void)pthread_mutex_unlock(&g_urpc_provider_ctx.provider_alloc_mutex);

    return provider;
}

urpc_queue_trans_mode_t urpc_queue_default_trans_mode_get(void)
{
    return QUEUE_TRANS_MODE_JETTY;
}

urpc_list_t *get_provider_list(void)
{
    return &g_urpc_queue_transport_ctx.provider_list;
}

void queue_read_cache_list_init(read_cache_list_t *rcache_list, uint32_t timeout)
{
    rcache_list->normal_node_num = 0;
    rcache_list->err_node_num = 0;
    rcache_list->timeout = timeout;
    rcache_list->init = URPC_TRUE;
    urpc_list_init(&rcache_list->read_cache_list);
    (void)pthread_spin_init(&rcache_list->lock, PTHREAD_PROCESS_PRIVATE);
}

void queue_read_cache_list_uninit(read_cache_list_t *rcache_list)
{
    if (rcache_list->init != URPC_TRUE) {
        return;
    }
    read_cache_t *cur, *next;
    URPC_LIST_FOR_EACH_SAFE(cur, next, node, &rcache_list->read_cache_list) {
        urpc_list_remove(&cur->node);
        cur->exception_callback(cur, 0, URPC_ERR_SERVER_DROP, NULL);
        urpc_dbuf_free(cur);
    }

    (void)pthread_spin_destroy(&rcache_list->lock);
    rcache_list->init = URPC_FALSE;
}

static void queue_read_cache_list_set_timeout_node(read_cache_list_t *rcache_list)
{
    if (rcache_list->timeout == 0) {
        return;
    }

    read_cache_t *read_cache_cur;
    uint32_t timestamp = get_timestamp();
    URPC_LIST_FOR_EACH(read_cache_cur, node, &rcache_list->read_cache_list) {
        if (read_cache_cur->err_code != 0) {
            continue;
        }

        if (timestamp - read_cache_cur->timestamp < rcache_list->timeout) {
            break;
        }

        read_cache_cur->err_code = URPC_ERR_TIMEOUT;
        rcache_list->normal_node_num--;
        rcache_list->err_node_num++;
    }
}

int queue_read_cache_list_push_back(read_cache_list_t *rcache_list, read_cache_t *read_cache)
{
    read_cache_t *read_cache_cur;
    pthread_spin_lock(&rcache_list->lock);
    queue_read_cache_list_set_timeout_node(rcache_list);
    if (rcache_list->normal_node_num >= DEFAULT_READ_CACHE_LIST_DEPTH) {
        pthread_spin_unlock(&rcache_list->lock);
        return URPC_FAIL;
    }

    if (urpc_list_is_empty(&rcache_list->read_cache_list)) {
        urpc_list_push_back(&rcache_list->read_cache_list, &read_cache->node);
    } else {
        URPC_LIST_FOR_EACH_REVERSE(read_cache_cur, node, &rcache_list->read_cache_list) {
            if (read_cache_cur->timestamp <= read_cache->timestamp) {
                urpc_list_insert_after(&read_cache_cur->node, &read_cache->node);
                goto EXIT;
            }
        }

        urpc_list_push_front(&rcache_list->read_cache_list, &read_cache->node);
    }

EXIT:
    rcache_list->normal_node_num++;
    pthread_spin_unlock(&rcache_list->lock);
    return URPC_SUCCESS;
}

void queue_read_cache_list_push_front(read_cache_list_t *rcache_list, read_cache_t *read_cache)
{
    /* used for rollback of pop front, no need to check list depth */
    read_cache_t *read_cache_cur;
    pthread_spin_lock(&rcache_list->lock);
    if (urpc_list_is_empty(&rcache_list->read_cache_list)) {
        urpc_list_push_front(&rcache_list->read_cache_list, &read_cache->node);
    } else {
        URPC_LIST_FOR_EACH(read_cache_cur, node, &rcache_list->read_cache_list) {
            if (read_cache_cur->timestamp >= read_cache->timestamp) {
                urpc_list_insert_before(&read_cache_cur->node, &read_cache->node);
                goto EXIT;
            }
        }

        urpc_list_push_back(&rcache_list->read_cache_list, &read_cache->node);
    }

EXIT:
    rcache_list->normal_node_num++;
    pthread_spin_unlock(&rcache_list->lock);
}

read_cache_t *queue_read_cache_list_pop_front(read_cache_list_t *rcache_list)
{
    read_cache_t *read_cache;
    pthread_spin_lock(&rcache_list->lock);
    queue_read_cache_list_set_timeout_node(rcache_list);
    URPC_LIST_FIRST_NODE(read_cache, node, &rcache_list->read_cache_list);
    if (read_cache == NULL) {
        pthread_spin_unlock(&rcache_list->lock);
        return NULL;
    }

    urpc_list_remove(&read_cache->node);
    if (read_cache->err_code == 0) {
        rcache_list->normal_node_num--;
    } else {
        rcache_list->err_node_num--;
    }
    pthread_spin_unlock(&rcache_list->lock);
    return read_cache;
}

int queue_id_allocator_init(void)
{
    int ret = urpc_id_generator_init(&g_urpc_qid_gen, URPC_ID_GENERATOR_TYPE_BITMAP_AUTO_INC, QUEUE_ID_MAX);
    if (ret != 0) {
        URPC_LIB_LOG_ERR("id generator init failed, ret:%d\n", ret);
        return ret;
    }

    return URPC_SUCCESS;
}

void queue_id_allocator_uninit(void)
{
    urpc_id_generator_uninit(&g_urpc_qid_gen);
}

int queue_id_allocator_alloc(uint32_t *qid)
{
    uint32_t id;
    /* Currently, id from generator is range from 1 ~ 0xffff. 0 is reserved for invalid id. */
    if (urpc_id_generator_alloc(&g_urpc_qid_gen, 1, &id) != URPC_SUCCESS) {
        return URPC_FAIL;
    }

    *qid = id;

    return URPC_SUCCESS;
}

void queue_id_allocator_free(uint32_t qid)
{
    if (queue_id_is_invaild(qid)) {
        return;
    }

    urpc_id_generator_free(&g_urpc_qid_gen, qid);
}

bool queue_id_is_invaild(uint32_t qid)
{
    return (qid == 0 || qid >= QUEUE_ID_MAX);
}

int urpc_instance_key_fill(urpc_instance_key_t *key)
{
    /* Only used by server channel. Client channel can get eid directly from 'channel.provider'.
     * Using the first provider(eid) as the instance key under both one-eid & multi-eid mode. */
    provider_t *provider = get_first_provider();
    if (provider == NULL) {
        URPC_LIB_LOG_ERR("get provider failed\n");
        return URPC_FAIL;
    }
    provider->ops->get_eid(provider, &key->eid);
    key->pid = (uint32_t)getpid();

    return URPC_SUCCESS;
}

uint32_t urpc_instance_key_hash(urpc_instance_key_t *key)
{
    // use k to avoid unexpected memory align
    urpc_instance_key_t k = {0};
    k.eid = key->eid;
    k.pid = key->pid;
    return urpc_hash_bytes(&k, sizeof(urpc_instance_key_t), 0);
}

bool urpc_instance_key_cmp(urpc_instance_key_t *key1, urpc_instance_key_t *key2)
{
    return ((memcmp(&key1->eid, &key2->eid, sizeof(urpc_eid_t)) == 0) && key1->pid == key2->pid);
}

URPC_CONSTRUCTOR(queue_ops_init, CONSTRUCTOR_PRIORITY_GLOBAL)
{
    urpc_list_init(&g_urpc_queue_ops_list);
    urpc_list_init(&g_urpc_provider_ops_list);
}

uint32_t urpc_get_local_qh(uint64_t **qh_list)
{
    queue_local_t *local_q = NULL;
    (void)pthread_mutex_lock(&g_urpc_queue_transport_ctx.queue_list_mutex);
    uint32_t queue_num = urpc_list_size(&g_urpc_queue_transport_ctx.queue_list);
    if (queue_num == 0) {
        (void)pthread_mutex_unlock(&g_urpc_queue_transport_ctx.queue_list_mutex);
        return 0;
    }
    uint32_t index = 0;
    uint64_t *tmp_qh_list = urpc_dbuf_calloc(URPC_DBUF_TYPE_CP, queue_num, sizeof(uint64_t));
    if (tmp_qh_list == NULL) {
        URPC_LIB_LOG_ERR("get local qh list failed to calloc\n");
        return URPC_FAIL;
    }
    URPC_LIST_FOR_EACH(local_q, node, &g_urpc_queue_transport_ctx.queue_list) {
        if (is_manager_queue(&local_q->queue.flag)) {
            continue;
        }
        tmp_qh_list[index++] = (uint64_t)(uintptr_t)local_q;
    }
    (void)pthread_mutex_unlock(&g_urpc_queue_transport_ctx.queue_list_mutex);

    if (index == 0) {
        urpc_dbuf_free(tmp_qh_list);
    } else {
        *qh_list = tmp_qh_list;
    }
    return index;
}

int queue_info_get(uint16_t qid, char **output, uint32_t *output_size)
{
    queue_local_t *local_q = NULL;
    (void)pthread_mutex_lock(&g_urpc_queue_transport_ctx.queue_list_mutex);
    uint32_t queue_num = urpc_list_size(&g_urpc_queue_transport_ctx.queue_list);
    if (queue_num == 0) {
        (void)pthread_mutex_unlock(&g_urpc_queue_transport_ctx.queue_list_mutex);
        return URPC_FAIL;
    }

    queue_t *queue = NULL;
    uint32_t qti_size = 0;
    URPC_LIST_FOR_EACH(local_q, node, &g_urpc_queue_transport_ctx.queue_list) {
        if (qid == local_q->qid) {
            queue = (queue_t *)(uintptr_t)local_q;
            qti_size = queue->ops->query_trans_info(queue, QUEUE_QUERY_TRANS_INFO_SIZE, NULL);
            break;
        }
    }
    if (queue == NULL) {
        (void)pthread_mutex_unlock(&g_urpc_queue_transport_ctx.queue_list_mutex);
        URPC_LIB_LOG_ERR("failed to get queue[%u]\n", qid);
        return URPC_FAIL;
    }

    queue_trans_info_t *qti = (queue_trans_info_t *)urpc_dbuf_calloc(URPC_DBUF_TYPE_QUEUE, 1, qti_size);
    if (qti == NULL) {
        (void)pthread_mutex_unlock(&g_urpc_queue_transport_ctx.queue_list_mutex);
        URPC_LIB_LOG_ERR("failed to malloc, errno: %d\n", errno);
        return -URPC_ERR_ENOMEM;
    }

    (void)queue->ops->query_trans_info(queue, QUEUE_QUERY_TRANS_INFO_DATA, (char *)qti);
    (void)pthread_mutex_unlock(&g_urpc_queue_transport_ctx.queue_list_mutex);
    *output = (char *)qti;
    *output_size = qti_size;

    return URPC_SUCCESS;
}