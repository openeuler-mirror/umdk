/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2024-2024. All rights reserved.
 * Description: realize data plane function
 */

#include <string.h>

#include "urpc_framework_api.h"
#include "cancel.h"
#include "notify.h"
#include "cp.h"
#include "keepalive.h"
#include "urpc_framework_errno.h"
#include "urpc_lib_log.h"
#include "perf.h"
#include "urpc_dbuf_stat.h"
#include "client_manage_channel.h"

#include "dp.h"

#define URPC_REF_READ_MAX_SGE_NUM 1
#define MAX_FUNC_DEFINED 256
#define POLL_MAX_NUM 64
static ext_ops_t *g_urpc_ext_ops[MAX_FUNC_DEFINED];

static urpc_func_poll_cb_t g_func_poll_cb = NULL;

static inline bool is_ssl_enabled(uint8_t func_defined)
{
    return crypto_is_dp_ssl_enabled_lock_free();
}

static inline bool is_sge_need_encrypt_and_decrypt(uint8_t func_defined, uint64_t func_id)
{
    return crypto_is_dp_ssl_enabled_lock_free() &&
        (func_id == URPC_KEEPALIVE_FUNCTION_ID);
}

static void rx_wr_cnt_add(queue_local_t *local_q)
{
    if (URPC_LIKELY(local_q->cfg.lock_free != 0)) {
        local_q->rq_ctx->rx_wr_cnt++;
    } else {
        (void)__sync_fetch_and_add(&local_q->rq_ctx->rx_wr_cnt, 1);
    }
}

static void rx_wr_cnt_dec(queue_local_t *local_q)
{
    if (URPC_LIKELY(local_q->cfg.lock_free != 0)) {
        local_q->rq_ctx->rx_wr_cnt--;
    } else {
        (void)__sync_fetch_and_sub(&local_q->rq_ctx->rx_wr_cnt, 1);
    }
}

int post_rx_buf(uint64_t qh, uint32_t post_num, uint64_t one_buffer_size)
{
    urpc_sge_t *sge;
    uint32_t sge_num;
    urpc_allocator_t *allocator = default_allocator_get();
    queue_t *queue = (queue_t *)(uintptr_t)qh;
    queue_local_t *local_q = CONTAINER_OF_FIELD(queue, queue_local_t, queue);
    urpc_allocator_option_t option = {
        .qcustom_flag = local_q->cfg.custom_flag,
        .is_rx_buf = URPC_TRUE,
    };
    for (uint32_t post_done = 0; post_done < post_num; post_done++) {
        int ret = allocator->get(&sge, &sge_num, one_buffer_size, &option);
        if (ret != URPC_SUCCESS) {
            URPC_LIB_LOG_ERR("allocator->get failed, ret:%d, errno:%d, message: %s\n", ret, errno, strerror(errno));
            return URPC_FAIL;
        }

        if (urpc_queue_rx_post(qh, sge, sge_num) != URPC_SUCCESS) {
            allocator->put(sge, sge_num, &option);
            URPC_LIB_LOG_ERR("abort post rx buffer failed post_done %u\n", post_done);
            return URPC_FAIL;
        }
    }
    return URPC_SUCCESS;
}

int urpc_queue_rx_post(uint64_t urpc_qh, urpc_sge_t *args, uint32_t args_sge_num)
{
    int ret = URPC_FAIL;
    if (urpc_qh == URPC_INVALID_HANDLE) {
        queue_error_stats_record(NULL, ERR_STATS_TYPE_INVALID_PARAM);
        URPC_LIB_LIMIT_LOG_DEBUG("queue handle invalid\n");
        return -URPC_ERR_EINVAL;
    }

    uint64_t post_start = urpc_perf_record_begin(PERF_RECORD_POINT_QUEUE_RX_POST);

    queue_t *l_q = (queue_t *)(uintptr_t)urpc_qh;
    if (l_q->flag.is_remote == URPC_TRUE) {
        queue_error_stats_record(NULL, ERR_STATS_TYPE_INVALID_PARAM);
        URPC_LIB_LIMIT_LOG_DEBUG("rx_post queue can't be remote type\n");
        ret = -URPC_ERR_EINVAL;
        goto RECORD_END;
    }
    if (URPC_UNLIKELY(args == NULL || args_sge_num == 0 || args_sge_num > URPC_SGE_NUM)) {
        queue_error_stats_record(l_q, ERR_STATS_TYPE_INVALID_PARAM);
        URPC_LIB_LIMIT_LOG_DEBUG("sge is null or sge num %u not in (0, %u]\n", args_sge_num, URPC_SGE_NUM);
        ret = -URPC_ERR_EINVAL;
        goto RECORD_END;
    }

    queue_local_t *local_q = CONTAINER_OF_FIELD(l_q, queue_local_t, queue);
    struct rx_user_ctx *rx_ctx = rx_user_ctx_get(l_q);
    if (URPC_UNLIKELY(rx_ctx == NULL)) {
        queue_error_stats_record(l_q, ERR_STATS_TYPE_NO_MEM);
        URPC_LIB_LIMIT_LOG_DEBUG("get rx_ctx failed\n");
        ret = -URPC_ERR_ENOMEM;
        goto RECORD_END;
    }
    rx_ctx->sges = args;
    rx_ctx->sge_num = args_sge_num;
    rx_ctx->rq_ctx = local_q->rq_ctx;

    queue_wr_t wr = {
        .sge = args,
        .sge_num = args_sge_num,
        .ctx = rx_ctx
    };
    ret = l_q->ops->post(l_q, &wr);
    if (URPC_UNLIKELY(ret != URPC_SUCCESS)) {
        queue_error_stats_record(l_q, ERR_STATS_TYPE_POST);
        rx_user_ctx_put(rx_ctx);
        return ret;
    }
    rx_wr_cnt_add(local_q);

RECORD_END:
    urpc_perf_record_end(PERF_RECORD_POINT_QUEUE_RX_POST, post_start);
    return ret;
}

queue_t *urpc_get_local_queue(urpc_channel_info_t *channel, urpc_call_option_t *option)
{
    if ((option->option_flag & FUNC_CALL_FLAG_L_QH) != 0) {
        if (option->l_qh == URPC_INVALID_HANDLE) {
            URPC_LIB_LIMIT_LOG_DEBUG("local queue handle invalid\n");
            return NULL;
        }
        return channel_get_local_queue_by_handle(channel, option->l_qh);
    }

    // local queue按rr选择
    return channel_get_next_local_queue(channel);
}

queue_t *urpc_get_remote_queue(urpc_channel_info_t *channel, urpc_call_option_t *option)
{
    if ((option->option_flag & FUNC_CALL_FLAG_R_QH) != 0) {
        if (option->r_qh == URPC_INVALID_HANDLE) {
            URPC_LIB_LIMIT_LOG_DEBUG("remote queue handle invalid\n");
            return NULL;
        }
        return channel_get_remote_queue_by_handle(channel, option->r_qh);
    }

    // remote queue按rr选择
    return channel_get_next_remote_queue(channel);
}

static int ext_func_call(urpc_poll_msg_t *msg, req_ctx_t **req_ctx, ext_call_ctx_t *ext_call_ctx)
{
    int ret = EXT_CALL_PROCESS_BACK_TO_NORMAL;
    ext_ops_t *ext_ops = g_urpc_ext_ops[ext_call_ctx->func_defined];
    if (ext_ops == NULL) {
        return ret;
    }
    switch (ext_call_ctx->pos) {
        case EXT_CALL_POS_RX_REQ:
            return ext_ops->rx_req_process ? ext_ops->rx_req_process(ext_call_ctx, req_ctx, msg) : ret;
        case EXT_CALL_POS_TX_READ:
            return ext_ops->tx_read_process ? ext_ops->tx_read_process(ext_call_ctx, msg) : ret;
        case EXT_CALL_POS_TX_READ_ERR:
            return ext_ops->tx_read_err_process ? ext_ops->tx_read_err_process(ext_call_ctx, msg) : ret;
        case EXT_CALL_POS_RX_RSP:
            return ext_ops->rx_rsp_process ? ext_ops->rx_rsp_process(ext_call_ctx, msg) : ret;
        default:
            return ret;
    }

    return ret;
}

// must be sure sges is not freed
static ALWAYS_INLINE uint32_t get_normal_sge_cnt(urpc_sge_t *sges, uint32_t sge_num, uint32_t completion_len)
{
    uint32_t cnt = 0;
    uint64_t total_len = 0;
    for (uint32_t i = 0; i < sge_num; i++) {
        if (URPC_UNLIKELY(sges[i].flag & SGE_FLAG_DATA_ZONE)) {
            continue;
        }
        if (URPC_UNLIKELY(total_len >= completion_len)) {
            break;
        }
        total_len += sges[i].length;
        cnt++;
    }

    return cnt;
}

static void fill_req_tx_ctx(
    tx_ctx_t *ctx, uint32_t chid, uint64_t l_qh, uint32_t req_id, urpc_call_wr_t *wr, urpc_call_option_t *option)
{
    ctx->user_ctx = (option->option_flag & FUNC_CALL_FLAG_USER_CTX) ? option->user_ctx : NULL;
    ctx->func_defined =
        ((option->option_flag & FUNC_CALL_FLAG_FUNC_DEFINED) != 0) ? option->func_defined : FUNC_DEF_NULL;
    ctx->sges = wr->args;
    ctx->sge_num = wr->args_num;
    ctx->l_qh = l_qh;
    ctx->normal_len = urpc_req_parse_req_total_size((urpc_req_head_t *)(uintptr_t)wr->args[0].addr);
    ctx->normal_sge_num = get_normal_sge_cnt(wr->args, wr->args_num, ctx->normal_len);
    ctx->channel_id = chid;
    ctx->req_id = req_id;
    ctx->msg_type = URPC_MSG_REQ;
    ctx->call_mode = (option->option_flag & FUNC_CALL_FLAG_CALL_MODE) ? option->call_mode : 0;
    ctx->cur_status = 0;
    ctx->free_events_completed = URPC_FALSE;
    ctx->sge_handover_completed = URPC_FALSE;
    ctx->internal_message = URPC_FALSE;
}

static ALWAYS_INLINE void cal_sges_total_size(struct urpc_sge *args, uint32_t args_num, sges_stats_t *stats)
{
    uint32_t total_size = 0;
    uint32_t dma_len = 0;
    uint32_t cnt = 0;
    uint32_t dma_cnt = 0;

    for (uint32_t i = 0; i < args_num; i++) {
        if (args[i].flag & SGE_FLAG_DATA_ZONE) {
            dma_len += args[i].length;
            if (dma_len < args[i].length) {
                dma_len -= args[i].length;
                break;
            }
            dma_cnt++;
            continue;
        }

        total_size += args[i].length;
        if (total_size < args[i].length) { // uint reversal
            total_size -= args[i].length;
            break;
        }
        cnt++;
    }

    stats->normal_cnt = cnt;
    stats->normal_len = total_size;
    stats->record_cnt = 1;
    stats->dma_cnt = dma_cnt;
    stats->dma_len = dma_len;
}

static int timeout_create(urpc_call_option_t *option, req_entry_t *req, uint8_t func_defined, urpc_call_wr_t *wr)
{
    if (URPC_LIKELY((option->option_flag & FUNC_CALL_FLAG_TIMEOUT) == 0 || option->timeout == 0 || req == NULL ||
                    func_defined >= MAX_FUNC_DEFINED)) {
        return URPC_SUCCESS;
    }

    if (URPC_UNLIKELY(!is_feature_enable(URPC_TIMER_FEATURE_FLAG))) {
        URPC_LIB_LIMIT_LOG_DEBUG("timeout feature is not enabled\n");
        return URPC_FAIL;
    }

    req->timer = urpc_timer_create(req->local_chid, false);
    if (URPC_UNLIKELY(req->timer == NULL)) {
        return URPC_FAIL;
    }

    // only cancel request process
    int ret = urpc_timer_start(req->timer, option->timeout, urpc_cancel_timeout_process, (void *)req, false);
    if (URPC_UNLIKELY(ret != URPC_SUCCESS)) {
        urpc_timer_destroy(req->timer);
        req->timer = NULL;
        return URPC_FAIL;
    }

    return URPC_SUCCESS;
}

static inline void ext_proto_fill_extra_info(uint8_t func_defined, urpc_req_head_t *req_head, queue_local_t *l_queue,
                                             queue_remote_t *r_queue)
{
    if (func_defined >= MAX_FUNC_DEFINED || g_urpc_ext_ops[func_defined] == NULL ||
        g_urpc_ext_ops[func_defined]->ext_proto_fill_extra_info == NULL) {
        return;
    }

    g_urpc_ext_ops[func_defined]->ext_proto_fill_extra_info(req_head, l_queue, r_queue);
}

static int func_call_sge_encrypt(uint8_t func_defined, urpc_channel_info_t *channel, queue_remote_t *r_queue,
    req_entry_t *req_entry, urpc_call_wr_t *wr)
{
    if (URPC_LIKELY(!is_sge_need_encrypt_and_decrypt(func_defined, wr->func_id))) {
        return URPC_SUCCESS;
    }

    server_node_t *server_node = ((queue_remote_t *)(uintptr_t)r_queue)->cfg.server_node;
    if (URPC_UNLIKELY(server_node == NULL)) {
        URPC_LIB_LIMIT_LOG_ERR("find server node for encrypt failed\n");
        return URPC_FAIL;
    }

    int ret;
    if (wr->func_id == URPC_KEEPALIVE_FUNCTION_ID) {
        ret = crypto_encrypt_keepalive_req(server_node->cipher_opt, wr->args, wr->args_num);
    } else {
        if (URPC_UNLIKELY(g_urpc_ext_ops[func_defined] == NULL || g_urpc_ext_ops[func_defined]->encrypt == NULL)) {
            return URPC_FAIL;
        }
        ret = g_urpc_ext_ops[func_defined]->encrypt(URPC_REQ, server_node->cipher_opt, wr->args,
            wr->args_num);
    }
    if (URPC_UNLIKELY(ret != URPC_SUCCESS)) {
        return URPC_FAIL;
    }

    if (req_entry != NULL) {
        req_entry->server_node_idx = server_node->index;
    }

    return URPC_SUCCESS;
}

static void sync_req_cb(urpc_sge_t *rsps, uint32_t rsps_sge_num, int err, void *arg, void *ctx)
{
    if (arg == NULL) {
        URPC_LIB_LOG_ERR("invalid argument\n");
        return;
    }

    sync_req_cb_arg_t *arg_ = (sync_req_cb_arg_t *)arg;
    arg_->err = err;
    if (err == URPC_SUCCESS) {
        arg_->rsp_received = 1;
    }
    (void)sem_post(&arg_->rsp_sem);
}

uint64_t urpc_func_call(uint32_t chid, urpc_call_wr_t *wr, urpc_call_option_t *option)
{
    if (URPC_UNLIKELY(wr == NULL || wr->args == NULL || wr->args_num == 0 || option == NULL ||
                      wr->args[0].length < sizeof(urpc_req_head_t)) || wr->args[0].addr == 0) {
        errno = URPC_ERR_EINVAL;
        queue_error_stats_record(NULL, ERR_STATS_TYPE_CALL_PARM_INVALID);
        URPC_LIB_LIMIT_LOG_DEBUG("parameter invalid\n");
        return URPC_U64_FAIL;
    }

    uint64_t func_call_start = urpc_perf_record_begin(PERF_RECORD_POINT_FUNC_CALL);

    urpc_channel_info_t *channel = channel_get(chid);
    if (URPC_UNLIKELY(channel == NULL)) {
        errno = URPC_ERR_SESSION_CLOSE;
        queue_error_stats_record(NULL, ERR_STATS_TYPE_CALL_NO_CHANNEL);
        URPC_LIB_LIMIT_LOG_DEBUG("get channel failed, chid:%u\n", chid);
        goto RECORD_END;
    }

    (void)pthread_rwlock_rdlock(&channel->rw_lock);
    queue_t *l_queue = urpc_get_local_queue(channel, option);
    if (URPC_UNLIKELY(l_queue == NULL)) {
        errno = URPC_ERR_LOCAL_QUEUE_ERR;
        queue_error_stats_record(NULL, ERR_STATS_TYPE_CALL_NO_L_QUEUE);
        URPC_LIB_LIMIT_LOG_DEBUG("get local queue failed\n");
        goto UNLOCK_CHANNEL;
    }

    queue_t *r_queue = urpc_get_remote_queue(channel, option);
    if (URPC_UNLIKELY(r_queue == NULL)) {
        errno = URPC_ERR_REMOTE_QUEUE_ERR;
        queue_error_stats_record(l_queue, ERR_STATS_TYPE_CALL_NO_R_QUEUE);
        URPC_LIB_LIMIT_LOG_DEBUG("get remote queue failed\n");
        goto UNLOCK_CHANNEL;
    }

    // alloc user_ctx
    tx_ctx_t *ctx = queue_ctx_get(l_queue, QUEUE_CTX_TYPE_TX);
    if (URPC_UNLIKELY(ctx == NULL)) {
        queue_error_stats_record(l_queue, ERR_STATS_TYPE_CALL_GET_TX_CTX_FAILED);
        URPC_LIB_LIMIT_LOG_DEBUG("malloc tx info failed\n");
        goto UNLOCK_CHANNEL;
    }

    uint32_t req_id = 0;
    req_entry_t *req_entry = NULL;
    sync_req_cb_arg_t *cb_arg = NULL;
    // early-rsp mode don't use req_entry
    if (URPC_LIKELY(((option->option_flag & FUNC_CALL_FLAG_CALL_MODE) != 0 &&
                     (option->call_mode == FUNC_CALL_MODE_EARLY_RSP)))) {
        (void)channel_get_req_id(channel, &req_id);
    } else {
        req_entry = req_entry_get(channel, ctx);
        if (URPC_UNLIKELY((req_entry == NULL))) {
            errno = URPC_ERR_EAGAIN;
            queue_error_stats_record(l_queue, ERR_STATS_TYPE_CALL_NO_RSN);
            URPC_LIB_LIMIT_LOG_DEBUG("get request entry failed\n");
            goto PUT_CTX;
        }
        req_entry->local_chid = chid;
        req_entry->args = wr->args;
        req_entry->args_num = wr->args_num;
        req_entry->send_qh = (uint64_t)(uintptr_t)l_queue;
        req_id = req_entry->req_id;

        if ((option->option_flag & FUNC_CALL_FLAG_CALL_MODE) != 0 &&
            (option->call_mode & FUNC_CALL_MODE_WAIT_RSP) != 0) {
            cb_arg = urpc_dbuf_calloc(URPC_DBUF_TYPE_DP, 1, sizeof(sync_req_cb_arg_t));
            if (cb_arg == NULL) {
                URPC_LIB_LIMIT_LOG_ERR("calloc cb_arg for req_entry failed\n");
                goto PUT_ENTRY;
            }
            int ret = sem_init(&cb_arg->rsp_sem, 0, 0);
            if (ret < 0) {
                errno = URPC_ERR_EINVAL;
                urpc_dbuf_free(cb_arg);
                URPC_LIB_LIMIT_LOG_ERR("Failed to init sem");
                goto PUT_ENTRY;
            }

            req_entry->cb = sync_req_cb;
            req_entry->cb_arg = cb_arg;
        }
    }

    sges_stats_t stats;
    cal_sges_total_size(wr->args, wr->args_num, &stats);
    uint8_t ack = (option->option_flag & FUNC_CALL_FLAG_CALL_MODE) && (option->call_mode & FUNC_CALL_MODE_ACK) ? 1 : 0;
    if (ack == 1) {
        URPC_LIB_LIMIT_LOG_ERR("urpc func call can't support ack\n");
        goto PUT_ENTRY;
    }
    uint8_t func_defined = (option->option_flag & FUNC_CALL_FLAG_FUNC_DEFINED) ? option->func_defined : FUNC_DEF_NULL;
    if (URPC_UNLIKELY(func_defined == FUNC_DEF_NULL && is_feature_enable(URPC_FEATURE_MULTIPLEX))) {
        URPC_LIB_LIMIT_LOG_ERR("non function can't support URPC_FEATURE_MULTIPLEX feature\n");
        goto PUT_ENTRY;
    }
    // callback to allow ext general to record req id and func cb, and start timeout timer
    if ((option->option_flag & FUNC_CALL_FLAG_CALL_MODE) != 0 && option->call_mode == FUNC_CALL_MODE_EARLY_RSP &&
        g_urpc_ext_ops[func_defined] != NULL && g_urpc_ext_ops[func_defined]->stream_send_process != NULL) {
        server_node_t *server_node = ((queue_remote_t *)(uintptr_t)r_queue)->cfg.server_node;
        uint32_t timeout = (option->option_flag & FUNC_CALL_FLAG_TIMEOUT) != 0 ? option->timeout : 0;
        if (g_urpc_ext_ops[func_defined]->stream_send_process(option, req_id, server_node->index, timeout) !=
            URPC_SUCCESS) {
            goto PUT_ENTRY;
        }
    }

    uint32_t channel_id;
    if (URPC_UNLIKELY(func_defined == FUNC_DEF_NULL && wr->func_id != URPC_KEEPALIVE_FUNCTION_ID)) {
        /* if function defined is not set or set to 0,
         * assign server channel id to the 'client_chid' field defined in req header */
        channel_id = ((queue_remote_t *)(uintptr_t)r_queue)->cfg.remote_chid;
    } else {
        channel_id = chid;
    }

    urpc_req_head_t *req_head = (urpc_req_head_t *)(uintptr_t)wr->args[0].addr;
    urpc_req_fill_basic_info(req_head, ack, channel_id);
    urpc_req_fill_req_info_without_dma(req_head, wr->func_id, stats.normal_len, req_id, func_defined);
    ext_proto_fill_extra_info(func_defined, req_head, (queue_local_t *)(uintptr_t)l_queue,
                              (queue_remote_t *)(uintptr_t)r_queue);
    fill_req_tx_ctx(ctx, chid, (uint64_t)(uintptr_t)l_queue, req_id, wr, option);

    // Normal wr without plog_ext_hdr has no room to storage encrypt hdr, skip the encryption of them.
    if (URPC_UNLIKELY(func_call_sge_encrypt(func_defined, channel, (queue_remote_t *)(uintptr_t)r_queue, req_entry,
        wr) != URPC_SUCCESS)) {
        errno = URPC_ERR_CIPHER_ERR;
        goto PUT_ENTRY;
    }

    queue_wr_t queue_wr;
    queue_wr.sge = wr->args;
    queue_wr.sge_num = wr->args_num;
    queue_wr.ctx = ctx;
    queue_wr.total_size = stats.normal_len;
    queue_wr.r_queue = r_queue;
    queue_wr.next = NULL;
    /*
     * If send failed after timeout create, req_entry will be invalid and timestamp will add 1
     * When timeout event trigger, it will ignore this req. So we don't need remove it.
     */
    if (URPC_UNLIKELY(timeout_create(option, req_entry, func_defined, wr) != URPC_SUCCESS)) {
        errno = URPC_ERR_EAGAIN;
        goto PUT_ENTRY;
    }
    errno = l_queue->ops->send(l_queue, &queue_wr);
    if (errno != 0) {
        queue_error_stats_record(l_queue, ERR_STATS_TYPE_CALL_SEND_FAILED);
        URPC_LIB_LIMIT_LOG_DEBUG("local queue send failed, errno:%d\n", errno);
        // destroy stream_ctx and timer
        if ((option->option_flag & FUNC_CALL_FLAG_CALL_MODE) != 0 && option->call_mode == FUNC_CALL_MODE_EARLY_RSP &&
            g_urpc_ext_ops[func_defined] != NULL && g_urpc_ext_ops[func_defined]->stream_send_fail_process != NULL &&
            g_urpc_ext_ops[func_defined]->stream_send_fail_process(option) != URPC_SUCCESS) {
            URPC_LIB_LIMIT_LOG_ERR("stream_send_fail_process failed\n");
        }
        goto PUT_ENTRY;
    }
    queue_dma_sge_stats_record(l_queue, STATS_TYPE_REQUEST_SEND, &stats);
    (void)pthread_rwlock_unlock(&channel->rw_lock);

    urpc_perf_record_end(PERF_RECORD_POINT_FUNC_CALL, func_call_start);

    return (uint64_t)req_id;

PUT_ENTRY:
    // cb_arg will be free in req_entry_put
    if (req_entry != NULL) {
        req_entry_put(req_entry);
    }

PUT_CTX:
    queue_ctx_put(QUEUE_CTX_TYPE_TX, ctx);

UNLOCK_CHANNEL:
    (void)pthread_rwlock_unlock(&channel->rw_lock);

RECORD_END:
    urpc_perf_record_end(PERF_RECORD_POINT_FUNC_CALL, func_call_start);
    return URPC_U64_FAIL;
}


static inline bool call_wr_invalid(urpc_call_wr_t *wr)
{
    return (URPC_UNLIKELY(wr == NULL || wr->args == NULL || wr->args_num == 0 ||
        wr->args[0].length < sizeof(urpc_req_head_t)) || wr->args[0].addr == 0);
}

static inline bool early_rsp_call_option_invalid(urpc_call_option_t *option)
{
    return (URPC_UNLIKELY(option == NULL || (option->option_flag & FUNC_CALL_FLAG_CALL_MODE) == 0 ||
            (option->option_flag & FUNC_CALL_FLAG_L_QH) == 0 || (option->option_flag & FUNC_CALL_FLAG_R_QH) == 0 ||
            (option->call_mode != FUNC_CALL_MODE_EARLY_RSP) || (option->l_qh == URPC_INVALID_HANDLE) ||
            (option->r_qh == URPC_INVALID_HANDLE)));
}

static int func_call_early_rsp_encrypt(
    uint8_t func_defined, uint64_t function, uint32_t server_chid, urpc_sge_t *sge, uint32_t sge_num)
{
    if (URPC_LIKELY(!is_sge_need_encrypt_and_decrypt(func_defined, function))) {
        return URPC_SUCCESS;
    }

    urpc_server_channel_info_t *channel = server_channel_get_with_rw_lock(server_chid, false);
    if (channel == NULL) {
        URPC_LIB_LIMIT_LOG_ERR("get server channel[%u] failed\n", server_chid);
        return URPC_FAIL;
    }

    if (channel->cipher_opt == NULL) {
        (void)pthread_rwlock_unlock(&channel->rw_lock);
        URPC_LIB_LIMIT_LOG_ERR("server channel[%u] cipher_opt is null\n", server_chid);
        return URPC_FAIL;
    }

    int ret = crypto_encrypt_keepalive_req(channel->cipher_opt, sge, sge_num);
    (void)pthread_rwlock_unlock(&channel->rw_lock);

    return ret;
}

// only used for server send early-rsp
int urpc_func_call_early_rsp(uint32_t server_chid, urpc_call_wr_t *wr, urpc_call_option_t *option)
{
    if (URPC_UNLIKELY(call_wr_invalid(wr) || early_rsp_call_option_invalid(option))) {
        errno = URPC_ERR_EINVAL;
        URPC_LIB_LIMIT_LOG_ERR("parameter invalid\n");
        return URPC_FAIL;
    }

    queue_t *l_queue = (queue_t *)(uintptr_t)option->l_qh;
    queue_t *r_queue = (queue_t *)(uintptr_t)option->r_qh;
    // alloc user_ctx
    tx_ctx_t *ctx = queue_ctx_get(l_queue, QUEUE_CTX_TYPE_TX);
    if (URPC_UNLIKELY(ctx == NULL)) {
        URPC_LIB_LIMIT_LOG_ERR("malloc tx info failed\n");
        return URPC_FAIL;
    }

    sges_stats_t stats;
    cal_sges_total_size(wr->args, wr->args_num, &stats);
    uint8_t func_defined = (option->option_flag & FUNC_CALL_FLAG_FUNC_DEFINED) ? option->func_defined : FUNC_DEF_NULL;
    urpc_req_head_t *req_head = (urpc_req_head_t *)(uintptr_t)wr->args[0].addr;
    urpc_req_fill_basic_info(req_head, 0, urpc_req_parse_client_channel(req_head));
    urpc_req_fill_req_info_without_dma(req_head, wr->func_id, stats.normal_len, 0, func_defined);
    fill_req_tx_ctx(ctx, server_chid, (uint64_t)(uintptr_t)l_queue, 0, wr, option);

    if (URPC_UNLIKELY(func_call_early_rsp_encrypt(func_defined, urpc_req_parse_function(req_head),
        server_channel_id_map_lookup(server_chid), wr->args, wr->args_num) != URPC_SUCCESS)) {
        goto PUT_CTX;
    }

    queue_wr_t queue_wr;
    queue_wr.sge = wr->args;
    queue_wr.sge_num = wr->args_num;
    queue_wr.ctx = ctx;
    queue_wr.total_size = stats.normal_len;
    queue_wr.r_queue = r_queue;
    queue_wr.next = NULL;

    errno = l_queue->ops->send(l_queue, &queue_wr);
    if (errno != 0) {
        URPC_LIB_LIMIT_LOG_ERR("local queue send failed, errno:%d\n", errno);
        goto PUT_CTX;
    }

    return URPC_SUCCESS;

PUT_CTX:
    queue_ctx_put(QUEUE_CTX_TYPE_TX, ctx);

    return URPC_FAIL;
}

static inline void fill_msg_req_rsped(urpc_poll_msg_t *msg, tx_ctx_t *ctx, urpc_sge_t *rsps, uint32_t rsps_sge_num)
{
    msg->event = POLL_EVENT_REQ_RSPED;
    msg->func_defined = ctx->func_defined;
    msg->req_rsped.args = ctx->sges;
    msg->req_rsped.args_sge_num = ctx->sge_num;
    msg->req_rsped.rsps = rsps;
    msg->req_rsped.rsps_sge_num = rsps_sge_num;
    msg->req_rsped.req_h = ctx->req_id;
    msg->req_rsped.urpc_chid = ctx->channel_id;
    msg->req_rsped.user_ctx = ctx->user_ctx;
}

static inline void fill_msg_req_sended(urpc_poll_msg_t *msg, tx_ctx_t *ctx)
{
    msg->event = POLL_EVENT_REQ_SENDED;
    msg->func_defined = ctx->func_defined;
    msg->req_sended.args = ctx->sges;
    msg->req_sended.args_sge_num = ctx->sge_num;
}

/* Ensure that the tx_ctx is safely released after ALL free event(TX CQE, ACK, RSP) have all been completed. */
void tx_ctx_try_put(tx_ctx_t *ctx)
{
    if (ctx->free_events_completed == URPC_FALSE) {
        ctx->free_events_completed = URPC_TRUE;
        return;
    }

    queue_ctx_put(QUEUE_CTX_TYPE_TX, ctx);
}

static int process_req_cqe(tx_ctx_t *ctx, queue_t *queue, urpc_poll_msg_t *msg, uint32_t urpc_chid)
{
    req_entry_t *req_entry;
    if (urpc_chid == URPC_INVALID_ID_U32 || urpc_chid == ctx->channel_id) {
        switch (ctx->call_mode & (FUNC_CALL_MODE_EARLY_RSP | FUNC_CALL_MODE_ACK | FUNC_CALL_MODE_WAIT_RSP)) {
            case FUNC_CALL_MODE_EARLY_RSP:                      /*  without ack, without rsp */
                fill_msg_req_rsped(msg, ctx, NULL, 0);
                queue_ctx_put(QUEUE_CTX_TYPE_TX, ctx);
                queue_stats_record(queue, STATS_TYPE_EARLY_RSP_WITHOUT_ACK_REQ_RSPED);
                return 1;
            case 0:                                             /* without ack, with rsp */
            case FUNC_CALL_MODE_ACK:                            /* with ack and rsp */
            case FUNC_CALL_MODE_EARLY_RSP | FUNC_CALL_MODE_ACK: /* with ack, without rsp */
                req_entry = req_entry_query(ctx->channel_id, ctx->req_id, true);
                tx_ctx_try_put(ctx);
                if (URPC_LIKELY(req_entry != NULL)) {
                    (void)pthread_mutex_unlock(&req_entry->lock);
                }
                return 0;
            case FUNC_CALL_MODE_WAIT_RSP:
                req_entry = req_entry_query(ctx->channel_id, ctx->req_id, true);
                fill_msg_req_sended(msg, ctx);
                ctx->sge_handover_completed = URPC_TRUE;
                tx_ctx_try_put(ctx);
                if (URPC_LIKELY(req_entry != NULL)) {
                    (void)pthread_mutex_unlock(&req_entry->lock);
                }
                return 1;
            default:
                break;
        }
    }
    queue_ctx_put(QUEUE_CTX_TYPE_TX, ctx);

    return 0;
}

static int process_rsp_cqe(queue_t *queue, tx_ctx_t *ctx, urpc_poll_msg_t *msg)
{
    if (ctx->internal_message == URPC_TRUE) {
        // internal error event, no need to report msg(tx cqe) to user.
        return 0;
    }

    msg->event = POLL_EVENT_RSP_SENDED;
    msg->rsp_sended.rsps = ctx->sges;
    msg->rsp_sended.rsps_sge_num = ctx->sge_num;

    return 1;
}

static ALWAYS_INLINE int process_error_queue(queue_t *queue,
    queue_msg_t *q_msg, urpc_poll_msg_t *msg, uint32_t urpc_chid)
{
    msg->event = POLL_EVENT_ERR;
    msg->event_err.err_event = POLL_ERR_EVENT_QUEUE_ERR;
    msg->event_err.args = NULL;
    msg->event_err.args_sge_num = 0;
    msg->event_err.err_code = q_msg->status;
    msg->event_err.urpc_qh = (uint64_t)(uintptr_t)queue;
    msg->event_err.urpc_chid = urpc_chid;

    return 1;
}

static ALWAYS_INLINE int process_error_ctx(queue_t *queue, queue_msg_t *q_msg, urpc_poll_msg_t *msg, uint32_t urpc_chid)
{
    msg->event = POLL_EVENT_ERR;
    msg->event_err.err_event = POLL_ERR_EVENT_CTX_ERR;
    msg->event_err.args = NULL;
    msg->event_err.args_sge_num = 0;
    msg->event_err.err_code = q_msg->status;
    msg->event_err.urpc_qh = (uint64_t)(uintptr_t)queue;
    msg->event_err.urpc_chid = urpc_chid;

    return 1;
}

static int process_read_error_msg(queue_t *queue, queue_msg_t *q_msg, urpc_poll_msg_t *msg, uint32_t urpc_chid)
{
    tx_ctx_t *ctx = (tx_ctx_t *)q_msg->data;

    ext_call_ctx_t ext_call_ctx = {
        .pos = EXT_CALL_POS_TX_READ_ERR,
        .func_defined = ctx->func_defined,
        .queue = queue,
        .q_msg = q_msg,
        .chid = urpc_chid,
    };

    int ret = ext_func_call(msg, NULL, &ext_call_ctx);
    if (ret == EXT_CALL_PROCESS_DONE_NONEED_REPORT) {
        return 0;
    } else if (ret == EXT_CALL_PROCESS_DONE_AND_REPORT) {
        return 1;
    } else if (ret == EXT_CALL_PROCESS_BACK_TO_NORMAL) {
        /* Currently, this process is not involved */
        msg->event = POLL_EVENT_READ_RET;
        msg->ref_read_result.l_sges = NULL;
        msg->ref_read_result.l_sges_num = 0;
        msg->ref_read_result.req_ctx = NULL;
        msg->ref_read_result.user_ctx = ctx->user_ctx;
        msg->ref_read_result.ret_code = (uint32_t)q_msg->status;
        return 1;
    }

    return 0;
}

static int process_tx_error_req_cqe(tx_ctx_t *ctx, queue_t *queue, queue_msg_t *q_msg, urpc_poll_msg_t *msg)
{
    req_entry_t *req_entry;
    switch (ctx->call_mode & (FUNC_CALL_MODE_EARLY_RSP | FUNC_CALL_MODE_ACK | FUNC_CALL_MODE_WAIT_RSP)) {
        case FUNC_CALL_MODE_EARLY_RSP:
            /*  without ack, without rsp, no req_entry */
            msg->event = POLL_EVENT_REQ_ERR;
            msg->req_err.args = ctx->sges;
            msg->req_err.args_sge_num = ctx->sge_num;
            msg->req_err.req_h = ctx->req_id;
            msg->req_err.user_ctx = ctx->user_ctx;
            msg->req_err.urpc_chid = ctx->channel_id;
            msg->req_err.err_code = (uint32_t)q_msg->status;
            queue_ctx_put(QUEUE_CTX_TYPE_TX, ctx);
            queue_error_stats_record(queue, ERR_STATS_TYPE_EARLY_RSP_WITHOUT_ACK_REQ);
            return 1;
        case 0:                                             /* without ack, with rsp */
        case FUNC_CALL_MODE_ACK:                            /* with ack and rsp */
        case FUNC_CALL_MODE_EARLY_RSP | FUNC_CALL_MODE_ACK: /* with ack, without rsp */
            req_entry = req_entry_query(ctx->channel_id, ctx->req_id, true);
            if (URPC_UNLIKELY(req_entry == NULL)) {
                /* ack/rsp has been reported to the user and req_entry has been put. release tx_ctx directly.
                 * currently, only prevent the same packet from being reported multiple times in the RX.
                 * If the same packet is reported repeatedly in the TX, tx_ctx may be released for multiple times. */
                URPC_LIB_LIMIT_LOG_WARN("reported repeatedly in the TX, chid[%u], req_id[%u]\n",
                    ctx->channel_id, ctx->req_id);
                tx_ctx_try_put(ctx);
                return 0;
            }

            if (ctx->cur_status != 0) {
                /* ack or rsp has been reported to the user before tx cqe.
                 * Assume tx message sent correctly and release tx_ctx directly. */
                tx_ctx_try_put(ctx);
                (void)pthread_mutex_unlock(&req_entry->lock);
                return 0;
            }

            /* No ack or rsp message is received. report error to user and release tx_ctx, req_entry directly. */
            msg->event = POLL_EVENT_REQ_ERR;
            msg->req_err.args = ctx->sges;
            msg->req_err.args_sge_num = ctx->sge_num;
            msg->req_err.req_h = ctx->req_id;
            msg->req_err.user_ctx = ctx->user_ctx;
            msg->req_err.urpc_chid = ctx->channel_id;
            msg->req_err.err_code = (uint32_t)q_msg->status;
            req_entry_put(req_entry);
            ctx->sge_handover_completed = URPC_TRUE;
            queue_io_req_error_stats_record(ctx->call_mode, queue);
            queue_ctx_put(QUEUE_CTX_TYPE_TX, ctx);
            (void)pthread_mutex_unlock(&req_entry->lock);
            return 1;
        case FUNC_CALL_MODE_WAIT_RSP:
            req_entry = req_entry_query(ctx->channel_id, ctx->req_id, true);
            if (URPC_UNLIKELY(req_entry == NULL)) {
                /* ack/rsp has been reported to the user and req_entry has been put. release tx_ctx directly. */
                URPC_LIB_LIMIT_LOG_WARN("reported repeatedly in the TX, chid[%u], req_id[%u]\n",
                                        ctx->channel_id, ctx->req_id);
                tx_ctx_try_put(ctx);
                return 0;
            }

            /* client in wait response mode received an error message from server.
             * user can poll this error message and func_poll_wait will stop waiting. */
            msg->event = POLL_EVENT_REQ_ERR;
            msg->req_err.args = ctx->sges;
            msg->req_err.args_sge_num = ctx->sge_num;
            msg->req_err.req_h = ctx->req_id;
            msg->req_err.user_ctx = ctx->user_ctx;
            msg->req_err.urpc_chid = ctx->channel_id;
            msg->req_err.err_code = (uint32_t)q_msg->status;
            ctx->sge_handover_completed = URPC_TRUE;
            urpc_process_rsp_callback(req_entry, q_msg->status);
            (void)pthread_mutex_unlock(&req_entry->lock);
            return 1;
        default:
            break;
    }

    queue_ctx_put(QUEUE_CTX_TYPE_TX, ctx);

    return 0;
}

static ALWAYS_INLINE int process_tx_error_msg(
    queue_t *queue, queue_msg_t *q_msg, urpc_poll_msg_t *msg, uint32_t urpc_chid)
{
    if (q_msg->status == URPC_ERR_CR_WR_SUSPEND_DONE || q_msg->status == URPC_ERR_CR_WR_FLUSH_ERR_DONE) {
        msg->event = POLL_EVENT_REQ_ERR;
        msg->req_err.args = NULL;
        msg->req_err.args_sge_num = 0;
        msg->req_err.req_h = 0;
        msg->req_err.urpc_chid = URPC_INVALID_ID_U32;
        msg->req_err.err_code = q_msg->status;
        return 1;
    }

    if (q_msg->data == NULL) {
        URPC_LIB_LIMIT_LOG_ERR("[DP] UDMA(UB)/URMA TX reports err_code: %d, with no data\n", q_msg->status);
        return 0;
    }

    int ret = 0;
    tx_ctx_t *ctx = (tx_ctx_t *)q_msg->data;
    msg->func_defined = ctx->func_defined;

    switch (ctx->msg_type) {
        case URPC_MSG_REQ:
            return process_tx_error_req_cqe(ctx, queue, q_msg, msg);
        case URPC_MSG_ACK:
            URPC_LIB_LIMIT_LOG_ERR("[DP] UDMA(UB)/URMA TX reports err_code: %d, reply ack failed\n", q_msg->status);
            break;
        case URPC_MSG_RSP:
        case URPC_MSG_ACK_AND_RSP:
            msg->event = POLL_EVENT_RSP_ERR;
            msg->rsp_err.rsps = ctx->sges;
            msg->rsp_err.rsps_sge_num = ctx->sge_num;
            msg->rsp_err.user_ctx = ctx->user_ctx;
            msg->rsp_err.err_code = (uint32_t)q_msg->status;
            ret = 1;
            queue_error_stats_record(queue, ERR_STATS_TYPE_RSP);
            break;
        case URPC_MSG_READ:
            URPC_LIB_LIMIT_LOG_ERR("[DP] UDMA(UB)/URMA TX reports err_code: %d, reply read failed\n", q_msg->status);
            queue_error_stats_record(queue, ERR_STATS_TYPE_REQ_READ_ERR_CQE);
            ret = process_read_error_msg(queue, q_msg, msg, urpc_chid);
            break;
        default:
            break;
    }
    queue_ctx_put(QUEUE_CTX_TYPE_TX, ctx);

    return ret;
}

static int process_read_cqe(queue_t *queue, tx_ctx_t *ctx, queue_msg_t *q_msg, urpc_poll_msg_t *msg, uint32_t urpc_chid)
{
    if (ctx->func_defined == FUNC_DEF_NULL) {
        tx_ctx_t *tx_ctx = (tx_ctx_t *)q_msg->data;
        msg->event = POLL_EVENT_READ_RET;
        msg->ref_read_result.l_sges = tx_ctx->sges;
        msg->ref_read_result.l_sges_num = tx_ctx->sge_num;
        msg->ref_read_result.req_ctx = NULL;
        msg->ref_read_result.user_ctx = ctx->user_ctx;
        msg->ref_read_result.ret_code = 0;
        queue_ctx_put(QUEUE_CTX_TYPE_TX, tx_ctx);
        return 1;
    }

    msg->func_defined = ctx->func_defined;
    ext_call_ctx_t ext_call_ctx = {
        .pos = EXT_CALL_POS_TX_READ,
        .func_defined = ctx->func_defined,
        .queue = queue,
        .q_msg = q_msg,
        .chid = urpc_chid,
    };

    int ret = ext_func_call(msg, NULL, &ext_call_ctx);
    if (ret == EXT_CALL_PROCESS_DONE_NONEED_REPORT) {
        return 0;
    } else if (ret == EXT_CALL_PROCESS_DONE_AND_REPORT) {
        return 1;
    }

    msg->event = POLL_EVENT_READ_RET;
    msg->ref_read_result.l_sges = NULL;
    msg->ref_read_result.l_sges_num = 0;
    msg->ref_read_result.req_ctx = NULL;
    msg->ref_read_result.user_ctx = ctx->user_ctx;
    msg->ref_read_result.ret_code = 0;

    return 1;
}

static ALWAYS_INLINE int process_tx_msg(queue_t *queue, queue_msg_t *q_msg, urpc_poll_msg_t *msg, uint32_t urpc_chid)
{
    if (q_msg->status != URPC_SUCCESS) {
        return process_tx_error_msg(queue, q_msg, msg, urpc_chid);
    }

    int ret = 0;
    tx_ctx_t *ctx = (tx_ctx_t *)q_msg->data;
    msg->func_defined = ctx->func_defined;
    uint32_t completion_len = q_msg->len > ctx->normal_len ? ctx->normal_len : q_msg->len;
    switch (ctx->msg_type) {
        case URPC_MSG_REQ:
            queue_io_sended_stats_record(ctx->call_mode, queue);
            queue_sge_stats_record(queue, STATS_TYPE_REQUEST_SEND_CONFIRMED, ctx->normal_sge_num, completion_len);
            ret = process_req_cqe(ctx, queue, msg, urpc_chid);
            break;
        case URPC_MSG_RSP:
            queue_sge_stats_record(queue, STATS_TYPE_RESPONSE_SEND_CONFIRMED, ctx->normal_sge_num, completion_len);
            ret = process_rsp_cqe(queue, ctx, msg);
            queue_ctx_put(QUEUE_CTX_TYPE_TX, ctx);
            break;
        case URPC_MSG_ACK_AND_RSP:
            queue_sge_stats_record(queue, STATS_TYPE_ACK_RESPONSE_SEND_CONFIRMED, ctx->normal_sge_num, completion_len);
            ret = process_rsp_cqe(queue, ctx, msg);
            queue_ctx_put(QUEUE_CTX_TYPE_TX, ctx);
            break;
        case URPC_MSG_READ:
            queue_sge_stats_record(queue, STATS_TYPE_READ_CONFIRMED, ctx->normal_sge_num, completion_len);
            ret = process_read_cqe(queue, ctx, q_msg, msg, urpc_chid);
            break;
        default:
            queue_ctx_put(QUEUE_CTX_TYPE_TX, ctx);
            break;
    }

    return ret;
}

queue_t *get_server_channel_real_r_queue(uint32_t server_chid, queue_t *l_queue, queue_t *q_src)
{
    if (is_server_support_quick_reply()) {
        return q_src;
    }

    return server_channel_search_remote_queue(server_chid, l_queue, q_src);
}

void put_server_channel_real_r_queue(uint32_t server_chid)
{
    if (is_server_support_quick_reply()) {
        return;
    }

    server_channel_unlock(server_chid);
}

static inline queue_t *query_remote_info(queue_t *l_queue, req_ctx_t *req_ctx)
{
    if (req_ctx->client_chid == URPC_INVALID_ID_U32) {
        // Non-PLOG Scenario
        urpc_server_channel_info_t *server_channel = server_channel_get_with_rw_lock(req_ctx->server_chid, false);
        if (server_channel == NULL) {
            return NULL;
        }
        req_ctx->client_chid = server_channel->client_chid[0];
        (void)pthread_rwlock_unlock(&server_channel->rw_lock);
    }

    return get_server_channel_real_r_queue(req_ctx->server_chid, l_queue, req_ctx->q_src);
}

static ALWAYS_INLINE tx_ctx_t *get_fill_ref_read_tx_ctx(queue_t *l_queue, urpc_sge_t *sges,
    uint32_t sge_num, req_ctx_t *req_ctx, urpc_ref_option_t *option)
{
    tx_ctx_t *tx_ctx = (tx_ctx_t *)queue_ctx_get(l_queue, QUEUE_CTX_TYPE_TX);
    if (URPC_UNLIKELY(tx_ctx == NULL)) {
        URPC_LIB_LIMIT_LOG_DEBUG("queue ctx get failed\n");
        return NULL;
    }

    tx_ctx->user_ctx = (option && (option->option_flag & FUNC_REF_FLAG_USER_CTX)) ? option->user_ctx : NULL;
    tx_ctx->sges = sges;
    tx_ctx->sge_num = sge_num;
    tx_ctx->normal_sge_num = 0;
    tx_ctx->normal_len = 0;
    tx_ctx->msg_type = URPC_MSG_READ;
    tx_ctx->req_id = req_ctx->req_id;
    tx_ctx->func_defined = FUNC_DEF_NULL;
    tx_ctx->channel_id = req_ctx->client_chid;
    tx_ctx->free_events_completed = URPC_TRUE;
    tx_ctx->sge_handover_completed = URPC_FALSE;
    tx_ctx->internal_message = URPC_FALSE;
    tx_ctx->l_qh = (uint64_t)(uintptr_t)l_queue;

    return tx_ctx;
}

static int check_ref_rw_param(queue_t *l_queue, req_ctx_t *req_ctx, urpc_ref_wr_t *wr)
{
    if (URPC_UNLIKELY(l_queue == NULL || req_ctx == NULL || wr == NULL || wr->r_ref_sges == NULL ||
                      wr->l_sges == NULL || wr->r_ref_sges->addr == 0 || wr->l_sges->addr == 0)) {
        queue_error_stats_record(l_queue, ERR_STATS_TYPE_INVALID_PARAM);
        URPC_LIB_LIMIT_LOG_DEBUG("invalid urpc_qh/req_ctx/wr\n");
        return -URPC_ERR_EINVAL;
    }
    if (URPC_UNLIKELY(wr->r_ref_sges_num != URPC_REF_READ_MAX_SGE_NUM || wr->r_ref_sges_num != wr->l_sges_num)) {
        queue_error_stats_record(l_queue, ERR_STATS_TYPE_INVALID_PARAM);
        URPC_LIB_LIMIT_LOG_DEBUG("invalid sge number, remote sges_num %u, local sges_num %u\n",
            wr->r_ref_sges_num, wr->l_sges_num);
        return -URPC_ERR_EINVAL;
    }

    if (URPC_UNLIKELY(wr->l_sges->length != wr->r_ref_sges->length)) {
        queue_error_stats_record(l_queue, ERR_STATS_TYPE_INVALID_PARAM);
        URPC_LIB_LIMIT_LOG_DEBUG("inconsistent sge length, src %u dst %u\n",
            wr->r_ref_sges->length, wr->l_sges->length);
        return -URPC_ERR_EINVAL;
    }

    return URPC_SUCCESS;
}

int urpc_ref_read(uint64_t urpc_qh, void *req_ctx, urpc_ref_wr_t *wr, urpc_ref_option_t *option)
{
    queue_t *l_queue = (queue_t *)(uintptr_t)urpc_qh;
    req_ctx_t *ctx = (req_ctx_t *)req_ctx;

    if (check_ref_rw_param(l_queue, ctx, wr) != URPC_SUCCESS) {
        URPC_LIB_LIMIT_LOG_DEBUG("invalid ref read param\n");
        return -URPC_ERR_EINVAL;
    }

    uint64_t read_start = urpc_perf_record_begin(PERF_RECORD_POINT_REF_READ);

    int ret = URPC_FAIL;
    tx_ctx_t *tx_ctx = get_fill_ref_read_tx_ctx(l_queue, wr->l_sges, wr->l_sges_num, ctx, option);
    if (tx_ctx == NULL) {
        queue_error_stats_record(l_queue, ERR_STATS_TYPE_REQ_READ_NO_TX_CTX);
        URPC_LIB_LIMIT_LOG_DEBUG("fill tx ctx failed\n");
        ret = -URPC_ERR_ENOMEM;
        goto RECORD_END;
    }

    queue_t *real_r_queue = (queue_t *)(uintptr_t)query_remote_info(l_queue, ctx);
    if (real_r_queue == NULL) {
        ret = -URPC_ERR_EINVAL;
        queue_error_stats_record(l_queue, ERR_STATS_TYPE_CALL_NO_R_QUEUE);
        URPC_LIB_LIMIT_LOG_DEBUG("get remote info failed\n");
        goto FREE_TX_CTX;
    }

    uint32_t l_sge_length = wr->l_sges->length;
    urpc_sge_t src_sge = {
        .addr = wr->r_ref_sges->addr,
        .length = wr->r_ref_sges->length,
        .flag = 0
    };
    urpc_sge_t dst_sge = {
        .addr = wr->l_sges->addr,
        .length = wr->l_sges->length,
        .flag = 0,
        .mem_h = wr->l_sges->mem_h
    };

    queue_wr_t q_wr = {
        .sge = &src_sge,
        .sge_num = wr->l_sges_num,
        .dst_sge = &dst_sge,
        .dst_sge_num = wr->r_ref_sges_num,
        .r_queue = real_r_queue,
        .total_size = wr->l_sges->length,
        .ctx = tx_ctx,
        .next = NULL,
        .server_chid = ctx->server_chid,
        .token_id = wr->r_ref_sges->token_id,
        .token_value = wr->r_ref_sges->token_value,
    };

    errno = l_queue->ops->read(l_queue, &q_wr);
    if (errno != 0) {
        if (errno != URMA_EAGAIN) {
            queue_error_stats_record(l_queue, ERR_STATS_TYPE_READ);
        }
        URPC_LIB_LIMIT_LOG_DEBUG("post read failed, ret %u\n", errno);
        ret = -errno;
        goto PUT_REMOTE_QUEUE;
    }

    put_server_channel_real_r_queue(ctx->server_chid);
    queue_sge_stats_record(l_queue, STATS_TYPE_READ, 1, l_sge_length);
    urpc_perf_record_end(PERF_RECORD_POINT_REF_READ, read_start);

    return URPC_SUCCESS;

PUT_REMOTE_QUEUE:
    put_server_channel_real_r_queue(ctx->server_chid);
FREE_TX_CTX:
    queue_ctx_put(QUEUE_CTX_TYPE_TX, tx_ctx);
RECORD_END:
    urpc_perf_record_end(PERF_RECORD_POINT_REF_READ, read_start);
    return ret;
}

static req_ctx_t *process_req_msg_normal(urpc_req_head_t *req_hdr, queue_msg_t *q_msg, queue_t *queue)
{
    req_ctx_t *req_ctx = queue_ctx_get(queue, QUEUE_CTX_TYPE_REQ);
    if (req_ctx == NULL) {
        queue_error_stats_record(queue, ERR_STATS_TYPE_NO_MEM);
        URPC_LIB_LOG_DEBUG("malloc request info failed\n");
        return NULL;
    }
    req_ctx->client_chid = URPC_INVALID_ID_U32;
    req_ctx->state = URPC_SERVER_STAT_REQ_RECVED;
    /* server channel id is set to the 'client_chid' field in req header if function defined is zero */
    req_ctx->server_chid = server_channel_id_map_lookup(urpc_req_parse_client_channel(req_hdr));
    qr_queue_info_t qr_qinfo = { .src_q_info = &q_msg->src_q_info, .qid = QUEUE_ID_INVALID };
    req_ctx->q_src = queue->ops->create_remote_queue(&qr_qinfo, 0, URPC_QUEUE_FLAG_QUICK_REPLY);
    req_ctx->req_id = urpc_req_parse_req_id(req_hdr);
    req_ctx->is_stream = false;
    req_ctx->ack = false;

    if (urpc_req_parse_ack(req_hdr) != 1) {
        /* No ACK message is required for requests not marked with ack */
        return req_ctx;
    }

    queue_t *real_r_queue = query_remote_info(queue, req_ctx);
    if (real_r_queue == NULL) {
        queue_error_stats_record(queue, ERR_STATS_TYPE_NO_REMOTE_QUEUE);
        queue_ctx_put(QUEUE_CTX_TYPE_REQ, req_ctx);
        URPC_LIB_LOG_DEBUG("get remote info failed\n");
        return NULL;
    }

    put_server_channel_real_r_queue(req_ctx->server_chid);

    return req_ctx;
}

static ALWAYS_INLINE int fill_sgl_length(urpc_sge_t *sges, uint32_t sge_num, uint32_t total_len)
{
    if (sge_num == 0) {
        URPC_LIB_LOG_DEBUG("sge_num num invalid\n");
        return -1;
    }

    uint32_t remain = total_len;

    for (uint32_t i = 0; i < sge_num; i++) {
        sges[i].length = remain < sges[i].length ? remain : sges[i].length;
        remain -= sges[i].length;
    }

    if (remain != 0) {
        URPC_LIB_LOG_DEBUG("rx sgl length invalid\n");
        return -1;
    }

    return 0;
}

static int func_poll_req_sge_decrypt(uint8_t func_defined, uint64_t function, urpc_sge_t *sge, uint32_t sge_num)
{
    if (URPC_LIKELY(!is_sge_need_encrypt_and_decrypt(func_defined, function))) {
        return URPC_SUCCESS;
    }

    int ret;
    if (function == URPC_KEEPALIVE_FUNCTION_ID) {
        if (URPC_UNLIKELY(sge_num != 1 || sge[0].length < URPC_KEEPALIVE_HDR_SIZE)) {
            return URPC_FAIL;
        }

        urpc_cipher_t *cipher_opt = NULL;
        urpc_keepalive_head_t *keepalive_hdr =
            (urpc_keepalive_head_t *)((uintptr_t)(sge[0].addr + sizeof(urpc_req_head_t)));
        // if client recv rsp, find cipher_opt from server_node
        bool is_rsp = urpc_keepalive_parse_rsp(keepalive_hdr);
        if (is_rsp) {
            urpc_req_head_t *req_hdr = (urpc_req_head_t *)(uintptr_t)sge[0].addr;
            uint32_t urpc_chid = urpc_req_parse_client_channel(req_hdr);
            // prevent that client manage channel is deleted concurrently
            urpc_client_manage_channel_ctx_lock();
            urpc_channel_info_t *channel = channel_get(urpc_chid);
            if (URPC_UNLIKELY(channel == NULL)) {
                urpc_client_manage_channel_ctx_unlock();
                URPC_LIB_LIMIT_LOG_ERR("decrypt keepalive get channel failed, client chid[%u] server_chid[%u]\n",
                    urpc_chid, urpc_keepalive_parse_server_channel(keepalive_hdr));
                return URPC_FAIL;
            }
            server_node_t *server_node =
                channel_get_server_node_by_chid(channel, urpc_keepalive_parse_server_channel(keepalive_hdr));
            if (URPC_UNLIKELY(server_node == NULL)) {
                urpc_client_manage_channel_ctx_unlock();
                URPC_LIB_LIMIT_LOG_ERR("decrypt keepalive get server_node failed, client chid[%u] server_chid[%u]\n",
                    urpc_chid, urpc_keepalive_parse_server_channel(keepalive_hdr));
                return URPC_FAIL;
            }

            cipher_opt = server_node->cipher_opt;
        }

        ret = crypto_decrypt_keepalive_req(cipher_opt, sge, sge_num);
        is_rsp ? urpc_client_manage_channel_ctx_unlock() : 0;
    } else {
        if (URPC_UNLIKELY(g_urpc_ext_ops[func_defined] == NULL || g_urpc_ext_ops[func_defined]->decrypt == NULL)) {
            return URPC_FAIL;
        }
        ret = g_urpc_ext_ops[func_defined]->decrypt(URPC_REQ, NULL, sge, sge_num);
    }

    return ret;
}

static int process_req_msg(
    struct rx_user_ctx *ctx, queue_t *queue, queue_msg_t *q_msg, urpc_poll_msg_t *msg, uint32_t urpc_chid)
{
    urpc_req_head_t *req_hdr = (urpc_req_head_t *)(uintptr_t)ctx->sges[0].addr;
    req_ctx_t *req_ctx = NULL;

    if (fill_sgl_length(ctx->sges, ctx->sge_num, urpc_req_parse_req_total_size(req_hdr)) < 0) {
        queue_error_stats_record(queue, ERR_STATS_TYPE_INVALID_HEADER_LENGTH);
        goto ERROR_EXIT;
    }

    msg->func_defined = urpc_req_parse_function_defined(req_hdr);
    if (!ext_func_defined_validate(msg->func_defined)) {
        queue_error_stats_record(queue, ERR_STATS_TYPE_INVALID_HEADER_FUNC_DEFINED);
        URPC_LIB_LIMIT_LOG_DEBUG("function defined[%u](request) is invalid\n", msg->func_defined);
        goto ERROR_EXIT;
    }

    if (URPC_UNLIKELY(func_poll_req_sge_decrypt(msg->func_defined, urpc_req_parse_function(req_hdr), ctx->sges,
        ctx->sge_num) != URPC_SUCCESS)) {
        goto ERROR_EXIT;
    }

    if (msg->func_defined == FUNC_DEF_NULL) {
        /* only normal req will go this scene. */
        req_ctx = process_req_msg_normal(req_hdr, q_msg, queue);
        if (req_ctx == NULL) {
            goto ERROR_EXIT;
        }

        goto NORMAL_EXIT;
    }

    ext_call_ctx_t ext_call_ctx = {
        .pos = EXT_CALL_POS_RX_REQ,
        .func_defined = msg->func_defined,
        .queue = queue,
        .q_msg = q_msg,
        .chid = urpc_chid,
    };

    int ret = ext_func_call(msg, &req_ctx, &ext_call_ctx);
    if (ret == EXT_CALL_PROCESS_DONE_NONEED_REPORT) {
        return 0;
    } else if (ret == EXT_CALL_PROCESS_DONE_AND_REPORT) {
        return 1;
    }

NORMAL_EXIT:
    msg->event = POLL_EVENT_REQ_RECVED;
    msg->req_recved.args = ctx->sges;
    msg->req_recved.args_sge_num = ctx->sge_num;
    msg->req_recved.arg_valid_total_size = urpc_req_parse_req_total_size(req_hdr);
    msg->req_recved.func_id = urpc_req_parse_function(req_hdr);
    msg->req_recved.req_ctx = req_ctx;

    return 1;

ERROR_EXIT:
    msg->event = POLL_EVENT_REQ_ERR;
    msg->req_err.args = ctx->sges;
    msg->req_err.args_sge_num = ctx->sge_num;
    msg->rsp_err.err_code = (uint32_t)q_msg->status;
    return 1;
}

void urpc_process_rsp_callback(req_entry_t *entry, int err_code)
{
    if (entry->cb == NULL) {
        return;
    }

    entry->cb(NULL, 0, err_code, entry->cb_arg, &entry->req_id);
}

static int process_rsp_msg(struct rx_user_ctx *ctx, queue_t *queue, queue_msg_t *q_msg, urpc_poll_msg_t *msg)
{
    urpc_rsp_head_t *rsp_hdr = (urpc_rsp_head_t *)(uintptr_t)ctx->sges[0].addr;
    if (fill_sgl_length(ctx->sges, ctx->sge_num, urpc_rsp_parse_response_total_size(rsp_hdr)) < 0) {
        queue_error_stats_record(queue, ERR_STATS_TYPE_INVALID_HEADER_LENGTH);
        goto PUT_BUF;
    }

    uint32_t req_h = urpc_rsp_parse_req_id(rsp_hdr);
    uint32_t urpc_chid = urpc_rsp_parse_client_channel(rsp_hdr);
    uint8_t func_defined = urpc_rsp_parse_function_defined(rsp_hdr);

    req_entry_t *req_entry = req_entry_query(urpc_chid, req_h, true);
    if (req_entry == NULL) {
        queue_error_stats_record(queue, ERR_STATS_TYPE_INVALID_HEADER_RSN);
        URPC_LIB_LIMIT_LOG_DEBUG("get query entry failed\n");
        goto PUT_BUF;
    }

    tx_ctx_t *tx_ctx = (tx_ctx_t *)req_entry->ctx;
    if (func_defined != tx_ctx->func_defined) {
        if ((tx_ctx->call_mode & FUNC_CALL_MODE_WAIT_RSP) != 0) {
            urpc_process_rsp_callback(req_entry, URPC_ERR_URPC_HDR_ERR);
            (void)pthread_mutex_unlock(&req_entry->lock);
            goto PUT_BUF;
        }
        queue_error_stats_record(queue, ERR_STATS_TYPE_INVALID_HEADER_FUNC_DEFINED);
        URPC_LIB_LIMIT_LOG_DEBUG("function defined[%u](response) is different from the record value[%u]\n",
            func_defined,
            tx_ctx->func_defined);
        req_entry_put(req_entry);
        tx_ctx_try_put(tx_ctx);
        (void)pthread_mutex_unlock(&req_entry->lock);
        goto PUT_BUF;
    }
    msg->func_defined = func_defined;
    if ((tx_ctx->call_mode & FUNC_CALL_MODE_EARLY_RSP) != 0) {
        /* early rsp mode, don't need rsp */
        URPC_LIB_LIMIT_LOG_DEBUG("ignore rsp\n");
        (void)pthread_mutex_unlock(&req_entry->lock);
        goto PUT_BUF;
    }

    if (is_ssl_enabled(func_defined)) {
        urpc_channel_info_t *channel = channel_get(urpc_chid);
        server_node_t *server_node = channel_get_server_node_by_index(channel, req_entry->server_node_idx);
        if (server_node == NULL || g_urpc_ext_ops[func_defined] == NULL ||
            g_urpc_ext_ops[func_defined]->decrypt == NULL ||
            g_urpc_ext_ops[func_defined]->decrypt(URPC_RSP, server_node->cipher_opt, ctx->sges, ctx->sge_num) !=
            URPC_SUCCESS) {
            URPC_LIB_LIMIT_LOG_ERR("decrypt response failed\n");
            goto PUT_BUF;
        }
    }

    if (tx_ctx->call_mode == FUNC_CALL_MODE_ACK) {
        if (tx_ctx->cur_status == 0) {
            /* now rsp is received, but ack is not received, Waiting for the ack. */
            tx_ctx->cur_status = REQ_RSPED_WAIT_ACK;
            tx_ctx->rsps = ctx->sges;
            tx_ctx->rsps_sge_num = ctx->sge_num;
            tx_ctx->rsp_valid_total_size = urpc_rsp_parse_response_total_size(rsp_hdr);
            (void)pthread_mutex_unlock(&req_entry->lock);
            URPC_LIB_LIMIT_LOG_DEBUG("wait for the ack\n");
            return 0;
        } else if ((tx_ctx->cur_status & REQ_RSPED_WAIT_ACK) != 0) {
            URPC_LIB_LIMIT_LOG_DEBUG("Already received one rsp message, channel id: %u, req id: %u\n",
                tx_ctx->channel_id, tx_ctx->req_id);
            (void)pthread_mutex_unlock(&req_entry->lock);
            goto PUT_BUF;
        }
        /* now rsp is received, and ack is already received. */
        msg->event = POLL_EVENT_REQ_ACKED_RSPED;
        msg->req_acked_rsped.args = NULL;
        msg->req_acked_rsped.args_sge_num = 0;
        msg->req_acked_rsped.rsps = ctx->sges;
        msg->req_acked_rsped.rsps_sge_num = ctx->sge_num;
        msg->req_acked_rsped.rsp_valid_total_size = urpc_rsp_parse_response_total_size(rsp_hdr);
        msg->req_acked_rsped.req_h = req_h;
        msg->req_acked_rsped.user_ctx = tx_ctx->user_ctx;
        msg->req_acked_rsped.urpc_chid = urpc_chid;
        queue_stats_record(queue, STATS_TYPE_NORMAL_WITH_ACK_REQ_ACKED_RSPED);
    } else {
        /* now rsp is received, and no need ack */
        msg->event = POLL_EVENT_REQ_RSPED;
        msg->req_rsped.args = tx_ctx->sges;
        msg->req_rsped.args_sge_num = tx_ctx->sge_num;
        msg->req_rsped.rsps = ctx->sges;
        msg->req_rsped.rsps_sge_num = ctx->sge_num;
        msg->req_rsped.rsp_valid_total_size = urpc_rsp_parse_response_total_size(rsp_hdr);
        msg->req_rsped.req_h = req_h;
        msg->req_rsped.user_ctx = tx_ctx->user_ctx;
        msg->req_rsped.urpc_chid = urpc_chid;
        queue_stats_record(queue, STATS_TYPE_NORMAL_WITHOUT_ACK_REQ_RSPED);
    }

    // user call urpc_func_poll_wait(), notify user the rsp is received, req_entry & tx_ctx will be freed by user
    if ((tx_ctx->call_mode & FUNC_CALL_MODE_WAIT_RSP) != 0) {
        tx_ctx->rsps = ctx->sges;
        tx_ctx->rsps_sge_num = ctx->sge_num;
        tx_ctx->rsp_valid_total_size = urpc_rsp_parse_response_total_size(rsp_hdr);
        urpc_process_rsp_callback(req_entry, 0);
        (void)pthread_mutex_unlock(&req_entry->lock);
        return 0;
    } else {
        req_entry_put(req_entry);
        tx_ctx->sge_handover_completed = URPC_TRUE;
        tx_ctx_try_put(tx_ctx);
        (void)pthread_mutex_unlock(&req_entry->lock);
        return 1;
    }

PUT_BUF:
    msg->event = POLL_EVENT_RSP_ERR;
    msg->rsp_err.rsps = ctx->sges;
    msg->rsp_err.rsps_sge_num = ctx->sge_num;
    msg->rsp_err.err_code = (uint32_t)q_msg->status;
    return 1;
}

/* transform */
static uint32_t transform_rsp_status(uint8_t status)
{
    uint32_t err_code;
    switch (status) {
        case URPC_STAT_SERVER_DECLINE :
            err_code = URPC_ERR_SERVER_DROP;
            break;
        case URPC_STAT_FUNCTION_ERR :
            err_code = URPC_ERR_FUNC_NULL;
            break;
        case URPC_STAT_REMOTE_LEN_ERR :
            err_code = URPC_ERR_REM_LEN_ERR;
            break;
        case URPC_STAT_TIMEOUT :
            err_code = URPC_ERR_TIMEOUT;
            break;
        case URPC_STAT_VERSION_ERR :
            err_code = URPC_ERR_VERSION_ERR;
            break;
        case URPC_STAT_URPC_HDR_ERR :
            err_code = URPC_ERR_URPC_HDR_ERR;
            break;
        default :
            err_code = status;
            break;
    }

    return err_code;
}

static int process_ack_and_rsp_msg(struct rx_user_ctx *ctx, queue_t *queue, queue_msg_t *q_msg, urpc_poll_msg_t *msg)
{
    urpc_rsp_head_t *rsp_hdr = (urpc_rsp_head_t *)(uintptr_t)ctx->sges[0].addr;
    if (fill_sgl_length(ctx->sges, ctx->sge_num, urpc_rsp_parse_response_total_size(rsp_hdr)) < 0) {
        queue_error_stats_record(queue, ERR_STATS_TYPE_INVALID_HEADER_LENGTH);
        goto PUT_BUF;
    }

    uint32_t req_h = urpc_rsp_parse_req_id(rsp_hdr);
    uint32_t urpc_chid = urpc_rsp_parse_client_channel(rsp_hdr);
    uint8_t func_defined = urpc_rsp_parse_function_defined(rsp_hdr);

    req_entry_t *req_entry = req_entry_query(urpc_chid, req_h, true);
    if (req_entry == NULL) {
        queue_error_stats_record(queue, ERR_STATS_TYPE_INVALID_HEADER_RSN);
        URPC_LIB_LIMIT_LOG_DEBUG("get query entry failed\n");
        goto PUT_BUF;
    }

    tx_ctx_t *tx_ctx = (tx_ctx_t *)req_entry->ctx;
    if (func_defined != tx_ctx->func_defined) {
        queue_error_stats_record(queue, ERR_STATS_TYPE_INVALID_HEADER_FUNC_DEFINED);
        URPC_LIB_LIMIT_LOG_DEBUG("function defined[%u](response & acknowledge) is"
            "different from the record value[%u]\n", func_defined, tx_ctx->func_defined);
        req_entry_put(req_entry);
        tx_ctx_try_put(tx_ctx);
        (void)pthread_mutex_unlock(&req_entry->lock);
        goto PUT_BUF;
    }

    msg->func_defined = func_defined;

    uint8_t rsp_status = urpc_rsp_parse_status(rsp_hdr);
    if (rsp_status != URPC_SUCCESS) {
        // when plog read failed, will send ack & rsp back, it will tell user to release read resource
        msg->event = POLL_EVENT_REQ_ERR;
        msg->req_err.args = tx_ctx->sges;
        msg->req_err.args_sge_num = tx_ctx->sge_num;
        msg->req_err.req_h = req_h;
        msg->req_err.user_ctx = tx_ctx->user_ctx;
        msg->req_err.urpc_chid = urpc_chid;
        msg->req_err.err_code = transform_rsp_status(rsp_status);
    } else {
        msg->event = POLL_EVENT_REQ_ACKED_RSPED;
        msg->req_acked_rsped.args = tx_ctx->sges;
        msg->req_acked_rsped.args_sge_num = tx_ctx->sge_num;
        msg->req_acked_rsped.rsps = ctx->sges;
        msg->req_acked_rsped.rsps_sge_num = ctx->sge_num;
        msg->req_acked_rsped.rsp_valid_total_size = urpc_rsp_parse_response_total_size(rsp_hdr);
        msg->req_acked_rsped.req_h = req_h;
        msg->req_acked_rsped.user_ctx = tx_ctx->user_ctx;
        msg->req_acked_rsped.urpc_chid = urpc_chid;
    }

    /*
     * If ack-rsp status is incorrect, the reported event convert to req err.
     * However, URPC still receives the ACK rsp message.
     * Therefore, the statistics of the received ACK rsp message are added.
     */
    if ((tx_ctx->call_mode & FUNC_CALL_MODE_EARLY_RSP) == FUNC_CALL_MODE_EARLY_RSP) {
        queue_stats_record(queue, STATS_TYPE_EARLY_RSP_WITH_ACK_REQ_ACKED_RSPED);
    } else {
        queue_stats_record(queue, STATS_TYPE_NORMAL_WITH_ACK_REQ_ACKED_RSPED);
    }

    req_entry_put(req_entry);
    tx_ctx->sge_handover_completed = URPC_TRUE;
    tx_ctx_try_put(tx_ctx);
    (void)pthread_mutex_unlock(&req_entry->lock);
    return 1;

PUT_BUF:
    msg->event = POLL_EVENT_RSP_ERR;
    msg->rsp_err.rsps = ctx->sges;
    msg->rsp_err.rsps_sge_num = ctx->sge_num;
    msg->rsp_err.err_code = (uint32_t)q_msg->status;
    return 1;
}

static ALWAYS_INLINE int process_rx_error_msg(
    queue_t *queue, queue_msg_t *q_msg, urpc_poll_msg_t *msg, uint32_t urpc_chid)
{
    struct rx_user_ctx *ctx = (struct rx_user_ctx *)q_msg->data;
    msg->event = POLL_EVENT_ERR;
    msg->event_err.err_event = POLL_ERR_EVENT_POLL_ERR;
    msg->event_err.args = ctx->sges;
    msg->event_err.args_sge_num = ctx->sge_num;
    msg->event_err.err_code = q_msg->status;
    msg->event_err.urpc_qh = (uint64_t)(uintptr_t)queue;
    msg->event_err.urpc_chid = urpc_chid;
    rx_user_ctx_put(ctx);
    queue_local_t *local_q = CONTAINER_OF_FIELD(queue, queue_local_t, queue);
    rx_wr_cnt_dec(local_q);

    URPC_LIB_LIMIT_LOG_ERR("[DP] UDMA(UB)/URMA RX reports err_code: %d\n", q_msg->status);
    return 1;
}

static ALWAYS_INLINE int process_rx_protocol_error_msg(
    queue_t *queue, queue_msg_t *q_msg, urpc_poll_msg_t *msg, uint32_t urpc_chid)
{
    struct rx_user_ctx *ctx = (struct rx_user_ctx *)q_msg->data;
    msg->event = POLL_EVENT_ERR;
    msg->event_err.err_event = POLL_ERR_EVENT_PROTOCOL_ERR;
    msg->event_err.args = ctx->sges;
    msg->event_err.args_sge_num = ctx->sge_num;
    msg->event_err.err_code = q_msg->status;
    msg->event_err.urpc_qh = (uint64_t)(uintptr_t)queue;
    msg->event_err.urpc_chid = urpc_chid;
    rx_user_ctx_put(ctx);
    queue_local_t *local_q = CONTAINER_OF_FIELD(queue, queue_local_t, queue);
    rx_wr_cnt_dec(local_q);

    return 1;
}

static int process_rx_msg(queue_t *queue, queue_msg_t *q_msg, urpc_poll_msg_t *msg, uint32_t urpc_chid)
{
    if (q_msg->data == NULL) {
        URPC_LIB_LIMIT_LOG_ERR("[DP] UDMA(UB)/URMA RX reports err_code: %d, with no data\n", q_msg->status);
        return 0;
    }

    int ret = 0;
    struct rx_user_ctx *ctx = (struct rx_user_ctx *)q_msg->data;
    if (q_msg->status != URPC_SUCCESS) {
        return process_rx_error_msg(queue, q_msg, msg, urpc_chid);
    }

    urpc_req_head_t *head = (urpc_req_head_t *)(uintptr_t)ctx->sges[0].addr;
    uint8_t version = urpc_req_parse_version(head);
    if (version > URPC_PROTO_VERSION) {
        queue_error_stats_record(queue, ERR_STATS_TYPE_INVALID_HEADER_VERSION);
        URPC_LIB_LIMIT_LOG_DEBUG("protocol version(%u) is not supported\n", version);
        goto PROTO_ERR;
    }

    uint8_t type = urpc_req_parse_type(head);
    // rx sges is valid here
    uint32_t cnt = get_normal_sge_cnt(ctx->sges, ctx->sge_num, q_msg->len);
    switch (type) {
        case URPC_MSG_REQ:
            queue_sge_stats_record(queue, STATS_TYPE_REQUEST_RECEIVE, cnt, q_msg->len);
            ret = process_req_msg(ctx, queue, q_msg, msg, urpc_chid);
            break;
        case URPC_MSG_RSP:
            queue_sge_stats_record(queue, STATS_TYPE_RESPONSE_RECEIVE, cnt, q_msg->len);
            ret = process_rsp_msg(ctx, queue, q_msg, msg);
            break;
        case URPC_MSG_ACK_AND_RSP:
            queue_sge_stats_record(queue, STATS_TYPE_ACK_RESPONSE_RECEIVE, cnt, q_msg->len);
            ret = process_ack_and_rsp_msg(ctx, queue, q_msg, msg);
            break;
        default:
            URPC_LIB_LIMIT_LOG_DEBUG("protocol type(%u) is invalid\n", type);
            goto PROTO_ERR;
    }

    rx_user_ctx_put(ctx);
    queue_local_t *local_q = CONTAINER_OF_FIELD(queue, queue_local_t, queue);
    rx_wr_cnt_dec(local_q);

    return ret;

PROTO_ERR:
    return process_rx_protocol_error_msg(queue, q_msg, msg, urpc_chid);
}

static int poll_queue_notify_msg(queue_t *queue, urpc_poll_msg_t *msgs, int num)
{
    if (URPC_LIKELY(!is_feature_enable(URPC_FEATURE_TIMEOUT) || is_manager_queue(queue->flag))) {
        return 0;
    }

    return poll_notify_msg((uint64_t)(uintptr_t)queue, msgs, num);
}

static int process_read_cache(uint32_t urpc_chid, queue_t *queue, urpc_poll_msg_t *msgs, int num)
{
    if (URPC_UNLIKELY(queue->status != QUEUE_STATUS_READY)) {
        return 0;
    }

    queue_local_t *local_q = (queue_local_t *)(uintptr_t)queue;
    if (URPC_LIKELY(!queue_read_cache_list_need_process(&local_q->rcache_list))) {
        return 0;
    }

    read_cache_t *read_cache = NULL;
    plog_read_cache_ret_msg_t ret_msg = { .msg = msgs, .msg_cnt = 0 };
    while (ret_msg.msg_cnt < (uint32_t)num &&
        (read_cache = queue_read_cache_list_pop_front(&local_q->rcache_list)) != NULL) {
        if (read_cache->err_code != 0) {
            /* read cache is in error(timeout), execute exception directly */
            read_cache->exception_callback(read_cache, urpc_chid, read_cache->err_code, &ret_msg);
            urpc_dbuf_free(read_cache);
            continue;
        }

        int ret = read_cache->process_callback(read_cache, urpc_chid, &ret_msg);
        switch (ret) {
            case URPC_SUCCESS:
            case URPC_FAIL:
                urpc_dbuf_free(read_cache);
                break;
            case URPC_PARTIAL_SUCCESS:
                queue_read_cache_list_push_front(&local_q->rcache_list, read_cache);
                goto EXIT;
            default:
                URPC_LIB_LIMIT_LOG_ERR("Invalid process read cache callback return value: %d\n", ret);
                break;
        }
    }

EXIT:
    return ret_msg.msg_cnt;
}

static int poll_one_queue(uint32_t urpc_chid, urpc_poll_option_t *option, urpc_poll_msg_t *msgs, int num)
{
    queue_t *queue = (queue_t *)(uintptr_t)option->urpc_qh;
    /* poll abort msg first */
    int abort_msg_cnt = poll_queue_notify_msg(queue, msgs, num);
    if (abort_msg_cnt == num) {
        return abort_msg_cnt;
    }

    queue_msg_t q_msgs[num - abort_msg_cnt];
    queue_msgs_t q_msg;
    q_msg.msg = q_msgs;
    q_msg.msg_num = num - abort_msg_cnt;
    int msg_num = abort_msg_cnt;

    int cr_num = queue->ops->poll(queue, &q_msg, option->poll_direction);

    queue_msg_t *queue_msg;
    for (int i = 0; i < cr_num; i++) {
        queue_msg = &q_msgs[i];
        switch (queue_msg->ev) {
            case TX_SEND:
                msg_num += process_tx_msg(queue, queue_msg, &msgs[msg_num], urpc_chid);
                break;
            case RX_RECV:
                msg_num += process_rx_msg(queue, queue_msg, &msgs[msg_num], urpc_chid);
                break;
            case QUEUE_ERR:
                msg_num += process_error_queue(queue, queue_msg, &msgs[msg_num], urpc_chid);
                break;
            case CTX_ERR:
                msg_num += process_error_ctx(queue, queue_msg, &msgs[msg_num], urpc_chid);
                break;
            default:
                break;
        }
    }

    msg_num += process_read_cache(urpc_chid, queue, &msgs[msg_num], num - msg_num);

    return msg_num;
}

static int poll_channel_all_queue(urpc_channel_info_t *channel, urpc_poll_option_t *option,
    urpc_poll_msg_t *msg, int num)
{
    int poll_num = 0;
    int fill_num = 0;
    uint32_t local_num = channel->l_qnum;
    urpc_poll_option_t _option = {
        .poll_direction = option->poll_direction
    };
    queue_t *queue = NULL;
    while (local_num > 0) {
        queue = channel_get_cur_poll_queue(channel);
        if (queue == NULL) {
            queue_error_stats_record(NULL, ERR_STATS_TYPE_NO_LOCAL_QUEUE);
            URPC_LIB_LIMIT_LOG_DEBUG("get queue failed\n");
            break;
        }
        _option.urpc_qh = (uint64_t)(uintptr_t)queue;
        poll_num = poll_one_queue(channel->id, &_option, msg + fill_num, num - fill_num);
        if (poll_num < 0) {
            break;
        }
        fill_num += poll_num;
        poll_num = 0;
        if (fill_num == num) {
            break;
        }

        local_num--;
    }

    if (fill_num == 0) {
        return poll_num;
    } else {
        return fill_num;
    }
}

int urpc_func_poll(uint32_t urpc_chid, urpc_poll_option_t *option, urpc_poll_msg_t msg[], uint32_t max_msg_num)
{
    if (URPC_UNLIKELY(msg == NULL || max_msg_num == 0 || option == NULL)) {
        queue_error_stats_record(NULL, ERR_STATS_TYPE_INVALID_PARAM);
        URPC_LIB_LIMIT_LOG_DEBUG("parameter invalid\n");
        return -URPC_ERR_EINVAL;
    }
    int msg_num = max_msg_num > POLL_MAX_NUM ? POLL_MAX_NUM : (int)max_msg_num;
    uint64_t func_poll_start = urpc_perf_record_begin(PERF_RECORD_POINT_FUNC_POLL);

    int ret = 0;
    if (option->urpc_qh != URPC_INVALID_HANDLE) {
        ret = poll_one_queue(urpc_chid, option, msg, msg_num);
    } else {
        urpc_channel_info_t *channel = channel_get(urpc_chid);
        if (channel == NULL) {
            queue_error_stats_record(NULL, ERR_STATS_TYPE_NO_CHANNEL);
            URPC_LIB_LIMIT_LOG_DEBUG("get channel[%u] failed\n", urpc_chid);
            ret = -URPC_ERR_SESSION_CLOSE;
            goto RECORD_END;
        }
        ret = poll_channel_all_queue(channel, option, msg, msg_num);
    }

RECORD_END:
    urpc_perf_record_end(PERF_RECORD_POINT_FUNC_POLL, func_poll_start);
    return ret;
}

int urpc_func_poll_wait(uint32_t urpc_chid, uint64_t req_h, urpc_poll_option_t *option,
                        urpc_poll_msg_t msg[], uint32_t max_msg_num)
{
    if (URPC_UNLIKELY(msg == NULL || max_msg_num == 0 || option == NULL)) {
        URPC_LIB_LIMIT_LOG_DEBUG("parameter invalid\n");
        return -URPC_ERR_EINVAL;
    }

    req_entry_t *req_entry = req_entry_query(urpc_chid, req_h, false);
    if (req_entry == NULL) {
        URPC_LIB_LIMIT_LOG_DEBUG("get req entry table failed\n");
        return -URPC_ERR_EINVAL;
    }

    if (req_entry->ctx == NULL) {
        req_entry_put(req_entry);
        URPC_LIB_LIMIT_LOG_DEBUG("get error req entry\n");
        return -URPC_ERR_EINVAL;
    }

    sync_req_cb_arg_t *req_cb_arg = (sync_req_cb_arg_t *)req_entry->cb_arg;
    while (req_cb_arg->rsp_received == 0) {
        int err_code = req_cb_arg->err;
        if (err_code != URPC_SUCCESS) {
            // timeout or receive an error message from server
            req_entry = req_entry_query(urpc_chid, req_h, true);
            if (req_entry == NULL) {
                URPC_LIB_LIMIT_LOG_DEBUG("get req entry table failed\n");
                return -err_code;
            }
            tx_ctx_t *tx_ctx = (tx_ctx_t *)req_entry->ctx;
            if (err_code == URPC_ERR_TIMEOUT || err_code == URPC_ERR_URPC_HDR_ERR) {
                // rsp was received invalid or timeout, need the confirmation of tx cr to put the ctx.
                tx_ctx_try_put(tx_ctx);
            } else {
                // receive a req cqe with error code, and no rsp will be received, can put ctx directly.
                queue_ctx_put(QUEUE_CTX_TYPE_TX, tx_ctx);
            }
            req_entry_put(req_entry);
            (void)pthread_mutex_unlock(&req_entry->lock);
            return -err_code;
        }
        (void)sem_wait(&req_cb_arg->rsp_sem);
    }

    // get req_entry with lock here, avoid concurrency with polling worker threads
    req_entry = req_entry_query(urpc_chid, req_h, true);
    if (req_entry == NULL) {
        URPC_LIB_LIMIT_LOG_DEBUG("get req entry table failed\n");
        return -URPC_ERR_EINVAL;
    }
    tx_ctx_t *tx_ctx = (tx_ctx_t *)req_entry->ctx;
    urpc_poll_msg_t *rsp_msg = &msg[0];
    rsp_msg->event = POLL_EVENT_REQ_RSPED;
    rsp_msg->req_rsped.args = NULL;
    rsp_msg->req_rsped.args_sge_num = 0;
    rsp_msg->req_rsped.rsps = tx_ctx->rsps;
    rsp_msg->req_rsped.rsps_sge_num = tx_ctx->rsps_sge_num;
    rsp_msg->req_rsped.rsp_valid_total_size = tx_ctx->rsp_valid_total_size;
    rsp_msg->req_rsped.req_h = req_h;
    rsp_msg->req_rsped.urpc_chid = urpc_chid;

    int ret = req_cb_arg->err;
    tx_ctx->sge_handover_completed = URPC_TRUE;
    tx_ctx_try_put(tx_ctx);
    req_entry_put(req_entry);
    (void)pthread_mutex_unlock(&req_entry->lock);

    return ret;
}

static void fill_rsp_tx_ctx(tx_ctx_t *tx_ctx,
    urpc_return_wr_t *wr, uint32_t normal_len, uint32_t server_chid, uint64_t l_qh)
{
    tx_ctx->msg_type = URPC_MSG_RSP;
    tx_ctx->sges = wr->rsps;
    tx_ctx->sge_num = wr->rsps_sge_num;
    tx_ctx->normal_len = normal_len;
    tx_ctx->normal_sge_num = get_normal_sge_cnt(wr->rsps, wr->rsps_sge_num, normal_len);
    tx_ctx->free_events_completed = URPC_FALSE;
    tx_ctx->sge_handover_completed = URPC_FALSE;
    tx_ctx->internal_message = URPC_FALSE;
    tx_ctx->l_qh = l_qh;
}

int urpc_func_return(uint64_t urpc_qh, void *req_ctx, urpc_return_wr_t *wr, urpc_return_option_t *option)
{
    int ret;
    if (urpc_qh == URPC_INVALID_HANDLE || req_ctx == NULL) {
        queue_error_stats_record(NULL, ERR_STATS_TYPE_INVALID_PARAM);
        URPC_LIB_LOG_DEBUG("queue handle invalid or request context info is null\n");
        return -URPC_ERR_EINVAL;
    }

    uint64_t func_return_start = urpc_perf_record_begin(PERF_RECORD_POINT_FUNC_RETURN);

    queue_t *queue = (queue_t *)(uintptr_t)urpc_qh;
    // if wr is null, put req ctx
    req_ctx_t *ctx = req_ctx;
    queue_t *q_src = ctx->q_src;
    if (wr == NULL) {
        ret = URPC_SUCCESS;
        goto EXIT;
    }

    // wr is not null, send rsp
    if (wr->rsps == NULL || wr->rsps_sge_num == 0 || wr->rsps_sge_num > URPC_SGE_NUM || wr->rsps[0].addr == 0) {
        queue_error_stats_record(queue, ERR_STATS_TYPE_INVALID_PARAM);
        URPC_LIB_LOG_DEBUG("function response sge array is empty or rsps addr invalid\n");
        ret = -URPC_ERR_EINVAL;
        goto RECORD_END;
    }

    queue_t *real_r_queue = query_remote_info(queue, ctx);
    if (real_r_queue == NULL) {
        ret = -URPC_ERR_REMOTE_QUEUE_ERR;
        queue_error_stats_record(queue, ERR_STATS_TYPE_NO_REMOTE_QUEUE);
        URPC_LIB_LOG_DEBUG("get remote info failed\n");
        goto EXIT;
    }

    tx_ctx_t *rsp_tx_ctx = queue_ctx_get(queue, QUEUE_CTX_TYPE_TX);
    if (rsp_tx_ctx == NULL) {
        ret = -URPC_ERR_ENOMEM;
        queue_error_stats_record(queue, ERR_STATS_TYPE_NO_MEM);
        URPC_LIB_LOG_DEBUG("malloc tx info failed\n");
        goto PUT_RQ;
    }

    sges_stats_t stats;
    cal_sges_total_size(wr->rsps, wr->rsps_sge_num, &stats);

    fill_rsp_tx_ctx(rsp_tx_ctx, wr, stats.normal_len, ctx->server_chid, (uint64_t)(uintptr_t)queue);
    urpc_rsp_head_t *rsp_hdr = (urpc_rsp_head_t *)(uintptr_t)wr->rsps[0].addr;
    urpc_rsp_fill_basic_info(rsp_hdr, wr->status, ctx->client_chid, ctx->ack);
    urpc_rsp_fill_one_req_info(rsp_hdr, ctx->req_id, stats.normal_len, option);

    uint8_t func_defined = (option != NULL && (option->option_flag & FUNC_RETURN_FLAG_FUNC_DEFINED) != 0) ?
                           option->func_defined : FUNC_DEF_NULL;
    if (is_ssl_enabled(func_defined)) {
        // The server channel is read locked by query remote queue, it's safe to use it
        urpc_server_channel_info_t *server_channel = server_channel_get(ctx->server_chid);
        if (server_channel == NULL || g_urpc_ext_ops[func_defined] == NULL ||
            g_urpc_ext_ops[func_defined]->encrypt == NULL ||
            g_urpc_ext_ops[func_defined]->encrypt(URPC_RSP, server_channel->cipher_opt, wr->rsps,
            wr->rsps_sge_num) != URPC_SUCCESS) {
            URPC_LIB_LOG_ERR("encrypt response failed\n");
            queue_ctx_put(QUEUE_CTX_TYPE_TX, rsp_tx_ctx);
            ret = -URPC_ERR_CIPHER_ERR;
            goto PUT_RQ;
        }
    }

    queue_wr_t qwr = {.r_queue = real_r_queue,
        .sge = wr->rsps,
        .sge_num = wr->rsps_sge_num,
        .ctx = rsp_tx_ctx,
        .next = NULL,
        .total_size = stats.normal_len,
    };
    ret = queue->ops->send(queue, &qwr);
    if (ret != URPC_SUCCESS) {
        URPC_LIB_LOG_DEBUG("send wr failed\n");
        queue_ctx_put(QUEUE_CTX_TYPE_TX, rsp_tx_ctx);
        if (ret == URMA_EAGAIN || ret == URPC_ERR_EAGAIN) {
            put_server_channel_real_r_queue(ctx->server_chid);
            /* if return value is eagain, do not release resource and return directly to let user retry */
            ret = -ret;
            goto RECORD_END;
        }
        /* should invert ret for send() method return positive err_code */
        ret = -ret;
    } else {
        queue_dma_sge_stats_record(queue, STATS_TYPE_RESPONSE_SEND, &stats);
    }

PUT_RQ:
    put_server_channel_real_r_queue(ctx->server_chid);

EXIT:
    if (URPC_LIKELY(q_src != NULL)) {
        (void)q_src->ops->unimport_remote_queue(q_src);
        q_src->ops->delete_remote_queue(q_src);
    }
    queue_ctx_put(QUEUE_CTX_TYPE_REQ, ctx);

RECORD_END:
    urpc_perf_record_end(PERF_RECORD_POINT_FUNC_RETURN, func_return_start);

    return ret;
}

void ext_process_register_ops(ext_ops_t *ext_ops)
{
    if (ext_ops->func_defined == 0 || ext_ops->func_defined > MAX_FUNC_DEFINED - 1) {
        URPC_LIB_LOG_ERR("func_defined invalid\n");
        return;
    }

    if (g_urpc_ext_ops[ext_ops->func_defined] != NULL) {
        URPC_LIB_LOG_ERR("g_urpc_ext_ops already exists\n");
        return;
    }

    g_urpc_ext_ops[ext_ops->func_defined] = ext_ops;
}

bool ext_func_defined_validate(uint8_t func_defined)
{
    return (func_defined == FUNC_DEF_NULL) || (g_urpc_ext_ops[func_defined] != NULL);
}

int urpc_func_poll_cb_register(urpc_func_poll_cb_t poll_cb)
{
    if (poll_cb == NULL) {
        return URPC_FAIL;
    }
    
    g_func_poll_cb = poll_cb;
    return URPC_SUCCESS;
}

int urpc_func_poll_cb_unregister(void)
{
    g_func_poll_cb = NULL;
    return URPC_SUCCESS;
}

void urpc_poll_process(urpc_poll_msg_t msg[], uint32_t msg_num, uint64_t l_qh)
{
    if (g_func_poll_cb == NULL) {
        URPC_LIB_LIMIT_LOG_ERR("call poll msg callback failed, no cb_func");
        return;
    }
    g_func_poll_cb(URPC_INVALID_ID_U32, l_qh, msg, msg_num);
}

void process_cr_err(uint64_t qh, uint32_t err_code)
{
    switch (err_code) {
        case URPC_ERR_CR_UNSUPPORTED_OPCODE_ERR:
        case URPC_ERR_CR_REM_RESP_LEN_ERR:
        case URPC_ERR_CR_REM_UNSUPPORTED_REQ_ERR:
        case URPC_ERR_CR_REM_OPERATION_ERR:
        case URPC_ERR_CR_REM_ACCESS_ABORT_ERR:
        case URPC_ERR_CR_ACK_TIMEOUT_ERR:
        case URPC_ERR_CR_RNR_RETRY_CNT_EXC_ERR:
        case URPC_ERR_CR_LOC_LEN_ERR:
        case URPC_ERR_CR_LOC_OPERATION_ERR:
        case URPC_ERR_CR_LOC_ACCESS_ERR:
            // above states may be able to be restored. try to restore jetty.
        case URPC_ERR_CR_WR_FLUSH_ERR:
            // fatal error, udma flush wqe directly. still needs to modify state.
            (void)urpc_queue_modify(qh, QUEUE_STATUS_FAULT);
            break;
        case URPC_ERR_CR_WR_SUSPEND_DONE:
        case URPC_ERR_CR_WR_FLUSH_ERR_DONE:
            (void)urpc_queue_modify(qh, QUEUE_STATUS_READY);
            URPC_LIB_LIMIT_LOG_WARN("queue done, err code: %u\n", err_code);
            break;
        default:
            URPC_LIB_LIMIT_LOG_WARN("queue done, err code: %u\n", err_code);
            break;
    }
}

URPC_CONSTRUCTOR(dp_init, CONSTRUCTOR_PRIORITY_DRIVER)
{
    queue_ctx_info_t ctx_infos[] = {
        {
            .type = QUEUE_CTX_TYPE_TX,
            .direction = QUEUE_CTX_TX,
            .size = sizeof(tx_ctx_t),
        },
        {
            .type = QUEUE_CTX_TYPE_REQ,
            .direction = QUEUE_CTX_RX,
            .size = sizeof(req_ctx_t),
        },
    };

    queue_ctx_infos_set(ctx_infos, sizeof(ctx_infos) / sizeof(queue_ctx_info_t));
}
