/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2025-2025. All rights reserved.
 * Description: UMQ UB
 * Create: 2025-12-22
 * Note:
 * History: 2025-12-22
 */

#include <sys/epoll.h>
#include "perf.h"
#include "urpc_tlv.h"
#include "umq_qbuf_pool.h"
#include "umq_huge_qbuf_pool.h"
#include "umq_ub_flow_control.h"
#include "qbuf_list.h"
#include "umq_ub_api.h"
#include "umq_symbol_private.h"

#define DEFAULT_RNR_RETRY 6      // Retry 6 times
#define DEFAULT_ERR_TIMEOUT 2
#define DEFAULT_MIN_RNR_TIMER 19 // RNR single retransmission time: 2us*2^19 = 1.049s
#define UMQ_MAX_SGE_NUM 6
#define UMQ_MAX_QBUF_NUM 1
#define UMQ_ENABLE_INLINE_LIMIT_SIZE 32
#define UMQ_INLINE_ENABLE 1
#define UMQ_LEN_ALIGNMENT_4 4

static util_id_allocator_t g_umq_ub_id_allocator = {0};
static ub_queue_ctx_list_t g_umq_ub_queue_ctx_list;
static const char *g_umq_ub_tp_type_str[UMQ_TP_TYPE_MAX + 1] = {"rtp", "ctp", "utp", "unknown"};

static inline uint32_t umq_ub_bind_fature_allowlist_get(void)
{
    return UMQ_FEATURE_ENABLE_STATS | UMQ_FEATURE_ENABLE_PERF;
}

static inline bool umq_ub_bind_feature_check(uint32_t local_feature, uint32_t remote_feature)
{
    return ((local_feature ^ remote_feature) & (~umq_ub_bind_fature_allowlist_get())) == 0;
}

umq_tp_mode_t umq_tp_mode_convert(urma_transport_mode_t tp_mode)
{
    switch (tp_mode) {
        case URMA_TM_RC:
            return UMQ_TM_RC;
        case URMA_TM_RM:
            return UMQ_TM_RM;
        case URMA_TM_UM:
            return UMQ_TM_UM;
        default:
            return UMQ_TM_RC;
    };
}

umq_tp_type_t umq_tp_type_convert(urma_tp_type_t tp_type)
{
    switch (tp_type) {
        case URMA_RTP:
            return UMQ_TP_TYPE_RTP;
        case URMA_CTP:
            return UMQ_TP_TYPE_CTP;
        case URMA_UTP:
            return UMQ_TP_TYPE_UTP;
        default:
            return UMQ_TP_TYPE_RTP;
    };
}

int umq_ub_bind_info_check(ub_queue_t *queue, umq_ub_bind_info_t *info)
{
    urma_eid_t *eid = &queue->jetty[UB_QUEUE_JETTY_IO]->jetty_id.eid;
    uint32_t id = queue->jetty[UB_QUEUE_JETTY_IO]->jetty_id.id;
    if (info->version_info == NULL) {
        UMQ_VLOG_ERR(VLOG_UMQ, "eid: " EID_FMT ", jetty_id: %u, verion_info not exist\n", EID_ARGS(*eid), id);
        return -UMQ_ERR_EINVAL;
    }

    umq_ub_bind_dev_info_t *dev_info = (umq_ub_bind_dev_info_t *)(uintptr_t)info->dev_info;
    if (dev_info == NULL) {
        UMQ_VLOG_ERR(VLOG_UMQ, "eid: " EID_FMT ", jetty_id: %u, dev_info not exist\n", EID_ARGS(*eid), id);
        return -UMQ_ERR_EINVAL;
    }

    umq_ub_bind_queue_info_t *queue_info = (umq_ub_bind_queue_info_t *)(uintptr_t)info->queue_info;
    if (queue_info == NULL) {
        UMQ_VLOG_ERR(VLOG_UMQ, "eid: " EID_FMT ", jetty_id: %u, queue_info not exist\n", EID_ARGS(*eid), id);
        return -UMQ_ERR_EINVAL;
    }

    if (queue->flow_control.enabled && info->fc_info == NULL) {
        UMQ_VLOG_ERR(VLOG_UMQ, "eid: " EID_FMT ", jetty_id: %u, fc_info not exist\n", EID_ARGS(*eid), id);
        return -UMQ_ERR_EINVAL;
    }

    if (dev_info->umq_trans_mode != UMQ_TRANS_MODE_UB && dev_info->umq_trans_mode != UMQ_TRANS_MODE_UB_PLUS &&
        dev_info->umq_trans_mode != UMQ_TRANS_MODE_UBMM && dev_info->umq_trans_mode != UMQ_TRANS_MODE_UBMM_PLUS) {
        UMQ_VLOG_ERR(VLOG_UMQ, "eid: " EID_FMT ", jetty_id: %u, trans mode %d is not UB\n", EID_ARGS(*eid), id,
            dev_info->umq_trans_mode);
        return -UMQ_ERR_EINVAL;
    }

    if (queue->state > QUEUE_STATE_READY || queue_info->state > QUEUE_STATE_READY) {
        UMQ_VLOG_ERR(VLOG_UMQ, "eid: " EID_FMT ", jetty_id: %u, queue state is not ready or idle, local is %u, "
            "remote is %u\n", EID_ARGS(*eid), id, queue->state, queue_info->state);
        return -UMQ_ERR_EINVAL;
    }

    if (queue->dev_ctx->trans_info.trans_mode != dev_info->umq_trans_mode) {
        UMQ_VLOG_ERR(VLOG_UMQ, "eid: " EID_FMT ", jetty_id: %u, trans mode misatch, local is %u but remote %u\n",
            EID_ARGS(*eid), id, queue->dev_ctx->trans_info.trans_mode, dev_info->umq_trans_mode)
        return -UMQ_ERR_EINVAL;
    }

    if (queue->tp_mode != queue_info->tp_mode) {
        UMQ_VLOG_ERR(VLOG_UMQ, "eid: " EID_FMT ", jetty_id: %u, tp_mode misatch, local is %u but remote %u\n",
            EID_ARGS(*eid), id, umq_tp_mode_convert(queue->tp_mode), umq_tp_mode_convert(queue_info->tp_mode));
        return -UMQ_ERR_EINVAL;
    }

    if (queue->tp_type != queue_info->tp_type) {
        UMQ_VLOG_ERR(VLOG_UMQ, "eid: " EID_FMT ", jetty_id: %u, tp_type misatch, local is %u but remote %u\n",
            EID_ARGS(*eid), id, umq_tp_type_convert(queue->tp_type), umq_tp_type_convert(queue_info->tp_type));
        return -UMQ_ERR_EINVAL;
    }

    if (!umq_ub_bind_feature_check(queue->dev_ctx->feature, dev_info->feature)) {
        UMQ_VLOG_ERR(VLOG_UMQ, "eid: " EID_FMT ", jetty_id: %u, feature misatch, local is %u but remote %u\n",
            EID_ARGS(*eid), id, queue->dev_ctx->feature, dev_info->feature);
        return -UMQ_ERR_EINVAL;
    }

    if (dev_info->buf_pool_mode != umq_qbuf_mode_get()) {
        UMQ_VLOG_ERR(VLOG_UMQ, "eid: " EID_FMT ", jetty_id: %u, buf pool mode negotiation inconsistency, "
            "recv mode: %d\n", EID_ARGS(*eid), id, dev_info->buf_pool_mode);
        return -UMQ_ERR_EINVAL;
    }

    if (queue->bind_ctx != NULL || queue_info->is_binded != 0) {
        UMQ_VLOG_ERR(VLOG_UMQ, "eid: " EID_FMT ", jetty_id: %u, umq has already been binded\n", EID_ARGS(*eid), id);
        return -UMQ_ERR_EEXIST;
    }

    if (memcmp(eid, &queue_info->jetty_id.eid, sizeof(urma_eid_t)) == 0 && id == queue_info->jetty_id.id) {
        UMQ_VLOG_ERR(VLOG_UMQ, "eid: " EID_FMT ", jetty_id: %u, the queue cannot bind itself\n", EID_ARGS(*eid), id);
        return -UMQ_ERR_EINVAL;
    }
    return UMQ_SUCCESS;
}

static int umq_ub_prefill_rx_buf(ub_queue_t *queue)
{
    uint32_t require_rx_count = queue->rx_depth;
    uint32_t cur_batch_count = 0;
    int ret = UMQ_SUCCESS;

    umq_inc_ref(queue->dev_ctx->io_lock_free, &queue->ref_cnt, 1);
    do {
        cur_batch_count = require_rx_count > UMQ_POST_POLL_BATCH ? UMQ_POST_POLL_BATCH : require_rx_count;
        umq_buf_t *qbuf = umq_buf_alloc(queue->rx_buf_size, cur_batch_count, 0, NULL);
        if (qbuf == NULL) {
            UMQ_VLOG_ERR(VLOG_UMQ, "eid: " EID_FMT ", jetty_id: %u, alloc rx failed\n",
                EID_ARGS(queue->jetty[UB_QUEUE_JETTY_IO]->jetty_id.eid), queue->jetty[UB_QUEUE_JETTY_IO]->jetty_id.id);
            ret = UMQ_ERR_ENOMEM;
            goto DEC_REF;
        }

        umq_buf_t *bad_buf = NULL;
        ret = umq_ub_post_rx_inner_impl(queue, qbuf, &bad_buf);
        if (ret != UMQ_SUCCESS) {
            umq_buf_free(bad_buf);
            goto DEC_REF;
        }
        require_rx_count -= cur_batch_count;
    } while (require_rx_count > 0);

DEC_REF:
    umq_dec_ref(queue->dev_ctx->io_lock_free, &queue->ref_cnt, 1);
    return ret;
}

static urma_target_seg_t *import_mem(urma_context_t *urma_ctx, xchg_mem_info_t *xchg_mem)
{
    if (xchg_mem == NULL) {
        UMQ_VLOG_ERR(VLOG_UMQ, "xchg_mem invalid\n");
        return NULL;
    }

    urma_seg_t remote_seg = {
        .attr.value = xchg_mem->seg_flag.value,
        .len = xchg_mem->seg_len,
        .token_id = xchg_mem->seg_token_id
    };
    urma_token_t token = xchg_mem->token;
    (void)memcpy(&remote_seg.ubva, &xchg_mem->ubva, sizeof(urma_ubva_t));
    urma_import_seg_flag_t flag = {
        .bs.cacheable = URMA_NON_CACHEABLE,
        .bs.mapping = URMA_SEG_NOMAP,
        .bs.reserved = 0,
        .bs.access = URMA_ACCESS_READ | URMA_ACCESS_WRITE | URMA_ACCESS_ATOMIC
    };

    urma_target_seg_t *import_tseg = umq_symbol_urma()->urma_import_seg(urma_ctx, &remote_seg, &token, 0, flag);
    if (import_tseg == NULL) {
        UMQ_VLOG_ERR(VLOG_UMQ_URMA_API, "urma_import_seg failed, errno: %d\n", errno);
        return NULL;
    }
    return import_tseg;
}

static ALWAYS_INLINE uint32_t umq_ub_eid_id_hash_get(
    urma_eid_t *remote_eid, uint32_t pid, char *remote_namespace, uint32_t namespace_len)
{
    uint32_t hash_namespce = urpc_hash_bytes(remote_namespace, namespace_len, 0);
    uint32_t hash_eid = urpc_hash_bytes(remote_eid, sizeof(urma_eid_t), 0);
    uint32_t hash_eid_pid = urpc_hash_add(hash_eid, pid);
    return urpc_hash_add(hash_eid_pid, hash_namespce);
}

static int umq_ub_eid_id_get(ub_queue_t *queue, umq_ub_bind_info_t *info, uint32_t *remote_eid_id)
{
    int ret = UMQ_SUCCESS;
    remote_imported_tseg_info_t *remote_imported_info = queue->dev_ctx->remote_imported_info;
    urma_eid_t *eid = &queue->jetty[UB_QUEUE_JETTY_IO]->jetty_id.eid;
    uint32_t id = queue->jetty[UB_QUEUE_JETTY_IO]->jetty_id.id;
    urma_eid_t *remote_eid = &info->queue_info->jetty_id.eid;
    uint32_t hash = umq_ub_eid_id_hash_get(remote_eid,
        info->dev_info->pid, info->dev_info->bind_namespace, strlen(info->dev_info->bind_namespace));
    bool find = false;
    remote_eid_hmap_node_t *eid_node;
    (void)util_mutex_lock(remote_imported_info->remote_eid_id_table_lock);
    URPC_HMAP_FOR_EACH_WITH_HASH(eid_node, node, hash, &remote_imported_info->remote_eid_id_table) {
        if ((memcmp(&eid_node->eid, remote_eid, sizeof(urma_eid_t)) == 0) && (info->dev_info->pid == eid_node->pid) &&
            strcmp(info->dev_info->bind_namespace, eid_node->remote_namespace) == 0) {
            find = true;
            break;
        }
    }

    if (find) {
        *remote_eid_id = eid_node->remote_eid_id;
        eid_node->ref_cnt++;
        (void)util_mutex_unlock(remote_imported_info->remote_eid_id_table_lock);
        return UMQ_SUCCESS;
    }

    // The jetty for a bind operation originates from a new EID
    eid_node = (remote_eid_hmap_node_t *)malloc(sizeof(remote_eid_hmap_node_t));
    if (eid_node == NULL) {
        (void)util_mutex_unlock(remote_imported_info->remote_eid_id_table_lock);
        UMQ_VLOG_ERR(VLOG_UMQ, "eid: " EID_FMT ", jetty_id: %u, malloc eid node failed\n", EID_ARGS(*eid), id);
        return -UMQ_ERR_ENOMEM;
    }

    // allocating EID ID
    uint32_t eid_id = util_id_allocator_get(&remote_imported_info->eid_id_allocator);
    if (eid_id >= UMQ_UB_MAX_REMOTE_EID_NUM) {
        UMQ_VLOG_ERR(VLOG_UMQ, "eid: " EID_FMT ", jetty_id: %u, remote eid cnt exceed maxinum limit\n",
            EID_ARGS(*eid), id);
        ret = -UMQ_ERR_ENODEV;
        goto FREE_EID_NODE;
    }
    remote_imported_info->imported_tseg_list_mutex[eid_id] = util_mutex_lock_create(UTIL_MUTEX_ATTR_EXCLUSIVE);
    if (remote_imported_info->imported_tseg_list_mutex[eid_id] == NULL) {
        UMQ_VLOG_ERR(VLOG_UMQ, "eid: " EID_FMT ", jetty_id: %u, imported tseg list mutex create failed\n",
            EID_ARGS(*eid), id);
        ret = -UMQ_ERR_ENOMEM;
        goto ID_ALLOCATOR_RELEASE;
    }

    // importing the remote memory
    urma_target_seg_t *tseg = &info->dev_info->tseg;
    urma_seg_t *seg = &tseg->seg;
    xchg_mem_info_t mem_info = {
        .seg_len = seg->len,
        .seg_token_id = seg->token_id,
        .seg_flag = (urma_import_seg_flag_t)seg->attr.value,
        .token.token = (uint32_t)tseg->user_ctx
    };
    (void)memcpy(&mem_info.ubva, &seg->ubva, sizeof(urma_ubva_t));
    memset(remote_imported_info->imported_tseg_list[eid_id], 0, sizeof(urma_target_seg_t **) * UMQ_MAX_TSEG_NUM);

    remote_imported_info->imported_tseg_list[eid_id][UMQ_QBUF_DEFAULT_MEMPOOL_ID] =
        import_mem(queue->dev_ctx->urma_ctx, &mem_info);
    if (remote_imported_info->imported_tseg_list[eid_id][UMQ_QBUF_DEFAULT_MEMPOOL_ID] == NULL) {
        UMQ_VLOG_ERR(VLOG_UMQ, "local eid: " EID_FMT ", local jetty_id: %u, remote eid " EID_FMT ", remote jetty_id: "
            "%u, import mem failed\n", EID_ARGS(*eid), id, EID_ARGS(info->queue_info->jetty_id.eid),
            info->queue_info->jetty_id.id);
        ret = -UMQ_ERR_ENODEV;
        goto MUTEX_DESTROY;
    }

    eid_node->pid = info->dev_info->pid;
    eid_node->remote_eid_id = eid_id;
    eid_node->ref_cnt = 1;
    strcpy(eid_node->remote_namespace, info->dev_info->bind_namespace);
    *remote_eid_id = eid_id;
    (void)memset(remote_imported_info->tesg_imported[eid_id], 0, sizeof(bool) * UMQ_MAX_TSEG_NUM);
    remote_imported_info->tesg_imported[eid_id][UMQ_QBUF_DEFAULT_MEMPOOL_ID] = true;
    (void)memcpy(&eid_node->eid, remote_eid, sizeof(urma_eid_t));
    urpc_hmap_insert(&remote_imported_info->remote_eid_id_table, &eid_node->node, hash);
    (void)util_mutex_unlock(remote_imported_info->remote_eid_id_table_lock);
    return UMQ_SUCCESS;

MUTEX_DESTROY:
    (void)util_mutex_lock_destroy(remote_imported_info->imported_tseg_list_mutex[eid_id]);
    remote_imported_info->imported_tseg_list_mutex[eid_id] = NULL;
ID_ALLOCATOR_RELEASE:
    util_id_allocator_release(&remote_imported_info->eid_id_allocator, eid_id);

FREE_EID_NODE:
    free(eid_node);
    (void)util_mutex_unlock(remote_imported_info->remote_eid_id_table_lock);
    return ret;
}

int umq_ub_eid_id_release(remote_imported_tseg_info_t *remote_imported_info, ub_bind_ctx_t *ctx)
{
    if (remote_imported_info == NULL || ctx == NULL || ctx->tjetty[UB_QUEUE_JETTY_IO] == NULL) {
        UMQ_VLOG_ERR(VLOG_UMQ, "invalid parameter\n");
        return -UMQ_ERR_EINVAL;
    }
    urma_eid_t *remote_eid = &ctx->tjetty[UB_QUEUE_JETTY_IO]->id.eid;
    uint32_t hash = umq_ub_eid_id_hash_get(remote_eid,
        ctx->remote_pid, ctx->remote_namespace, strlen(ctx->remote_namespace));
    bool find = false;
    remote_eid_hmap_node_t *eid_node;
    (void)util_mutex_lock(remote_imported_info->remote_eid_id_table_lock);
    URPC_HMAP_FOR_EACH_WITH_HASH(eid_node, node, hash, &remote_imported_info->remote_eid_id_table) {
        if (memcmp(&eid_node->eid, remote_eid, sizeof(urma_eid_t)) == 0 && (ctx->remote_pid == eid_node->pid) &&
            eid_node->remote_eid_id == ctx->remote_eid_id &&
            strcmp(ctx->remote_namespace, eid_node->remote_namespace) == 0) {
            find = true;
            break;
        }
    }

    if (!find) {
        (void)util_mutex_unlock(remote_imported_info->remote_eid_id_table_lock);
        UMQ_VLOG_ERR(VLOG_UMQ, "not find eid node %u\n", ctx->remote_eid_id);
        return -UMQ_ERR_ENODEV;
    }

    eid_node->ref_cnt--;
    if (eid_node->ref_cnt == 0) {
        (void)util_mutex_lock_destroy(remote_imported_info->imported_tseg_list_mutex[eid_node->remote_eid_id]);
        remote_imported_info->imported_tseg_list_mutex[eid_node->remote_eid_id] = NULL;
        for (uint32_t i = 0; i < UMQ_MAX_TSEG_NUM; i++) {
            if (remote_imported_info->imported_tseg_list[eid_node->remote_eid_id][i] == NULL) {
                continue;
            }
            umq_symbol_urma()->urma_unimport_seg(
                remote_imported_info->imported_tseg_list[eid_node->remote_eid_id][i]);
            remote_imported_info->imported_tseg_list[eid_node->remote_eid_id][i] = NULL;
        }
        util_id_allocator_release(&remote_imported_info->eid_id_allocator, eid_node->remote_eid_id);
        urpc_hmap_remove(&remote_imported_info->remote_eid_id_table, &eid_node->node);
        free(eid_node);
    }
    (void)util_mutex_unlock(remote_imported_info->remote_eid_id_table_lock);
    return UMQ_SUCCESS;
}

static urma_target_jetty_t *umq_ub_connect_jetty(ub_queue_t *queue, umq_ub_bind_info_t *info, ub_queue_jetty_index_t i)
{
    urma_rjetty_t rjetty = {.jetty_id = i == UB_QUEUE_JETTY_IO ? info->queue_info->jetty_id : info->fc_info->jetty_id,
                            .trans_mode = info->queue_info->tp_mode,
                            .type = info->queue_info->type,
                            .flag.bs.token_policy =
                                token_policy_get((queue->dev_ctx->feature & UMQ_FEATURE_ENABLE_TOKEN_POLICY) != 0),
                            .flag.bs.order_type = info->queue_info->order_type,
                            .flag.bs.share_tp = 1,
                            .tp_type = info->queue_info->tp_type};
    urma_token_t token = i == UB_QUEUE_JETTY_IO ? info->queue_info->token : info->fc_info->token;
    urma_target_jetty_t *tjetty = umq_symbol_urma()->urma_import_jetty(queue->dev_ctx->urma_ctx, &rjetty, &token);
    if (tjetty == NULL) {
        UMQ_VLOG_ERR(VLOG_UMQ_URMA_API, "local eid: " EID_FMT ", local jetty_id: %u, remote eid: " EID_FMT ", "
            "remote jetty_id: %u, urma_import_jetty failed, jetty[%d], errno: %d\n",
            EID_ARGS(queue->jetty[i]->jetty_id.eid), queue->jetty[i]->jetty_id.id,
            EID_ARGS(rjetty.jetty_id.eid), rjetty.jetty_id.id, i, errno);
        return NULL;
    }
    if (queue->tp_mode != URMA_TM_RC) {
        return tjetty;
    }

    urma_status_t status = umq_symbol_urma()->urma_bind_jetty(queue->jetty[i], tjetty);
    if (status != URMA_SUCCESS && status != URMA_EEXIST) {
        UMQ_VLOG_ERR(VLOG_UMQ_URMA_API, "local eid: " EID_FMT ", local jetty_id: %u, remote eid: " EID_FMT ", "
            "remote jetty_id: %u, urma_bind_jetty failed, jetty[%d], status: %d\n",
            EID_ARGS(queue->jetty[i]->jetty_id.eid), queue->jetty[i]->jetty_id.id,
            EID_ARGS(rjetty.jetty_id.eid), rjetty.jetty_id.id, i, (int)status);
        goto UNIMPORT_JETTY;
    }

    return tjetty;

UNIMPORT_JETTY:
    umq_symbol_urma()->urma_unimport_jetty(tjetty);
    return NULL;
}

static void umq_ub_disconnect_jetty(ub_queue_t *queue, ub_bind_ctx_t *ctx, ub_queue_jetty_index_t i)
{
    umq_symbol_urma()->urma_unbind_jetty(queue->jetty[i]);
    umq_symbol_urma()->urma_unimport_jetty(ctx->tjetty[i]);
    ctx->tjetty[i] = NULL;
}

int umq_ub_bind_inner_impl(ub_queue_t *queue, umq_ub_bind_info_t *info)
{
    urma_eid_t *eid = &queue->jetty[UB_QUEUE_JETTY_IO]->jetty_id.eid;
    uint32_t id = queue->jetty[UB_QUEUE_JETTY_IO]->jetty_id.id;
    int ret = UMQ_SUCCESS;
    ub_bind_ctx_t *ctx = (ub_bind_ctx_t *)calloc(1, sizeof(ub_bind_ctx_t));
    if (ctx == NULL) {
        UMQ_VLOG_ERR(VLOG_UMQ, "eid: " EID_FMT ", jetty_id: %u, bind ctx calloc failed\n", EID_ARGS(*eid), id);
        return -UMQ_ERR_ENOMEM;
    }

    ctx->remote_notify_addr = info->queue_info->notify_buf;
    ctx->tjetty[UB_QUEUE_JETTY_IO] = umq_ub_connect_jetty(queue, info, UB_QUEUE_JETTY_IO);
    if (ctx->tjetty[UB_QUEUE_JETTY_IO] == NULL) {
        ret = UMQ_FAIL;
        goto FREE_CTX;
    }

    if (queue->flow_control.enabled) {
        ctx->tjetty[UB_QUEUE_JETTY_FLOW_CONTROL] = umq_ub_connect_jetty(queue, info, UB_QUEUE_JETTY_FLOW_CONTROL);
        if (ctx->tjetty[UB_QUEUE_JETTY_FLOW_CONTROL] == NULL) {
            ret = UMQ_FAIL;
            goto DISCONNECT_IO_JETTY;
        }
    }
    // if mode is UB, post rx here. if mode is UB PRO, no need to post rx
    if ((queue->dev_ctx->feature & UMQ_FEATURE_API_PRO) == 0) {
        ret = umq_ub_prefill_rx_buf(queue);
        if (ret != UMQ_SUCCESS) {
            goto DISCONNECT_FC_JETTY;
        }
    }

    ctx->remote_pid = info->dev_info->pid;
    if (info->dev_info->namespace_len > UMQ_UB_NAMESPACE_SIZE) {
        UMQ_VLOG_ERR(VLOG_UMQ, "dev info namespace len %u exceeds the maximum length %u\n",
            info->dev_info->namespace_len, UMQ_UB_NAMESPACE_SIZE);
        goto RESET_BIND_CTX;
    }
    memcpy(ctx->remote_namespace, info->dev_info->bind_namespace, info->dev_info->namespace_len);
    queue->bind_ctx = ctx;

    ret = umq_ub_eid_id_get(queue, info, &ctx->remote_eid_id);
    if (ret != UMQ_SUCCESS) {
        UMQ_VLOG_ERR(VLOG_UMQ, "eid: " EID_FMT ", jetty_id: %u, get eid id failed, status: %d\n",
            EID_ARGS(*eid), id, ret);
        goto RESET_BIND_CTX;
    }

    queue->imported_tseg_list = queue->dev_ctx->remote_imported_info->imported_tseg_list[ctx->remote_eid_id];
    uint32_t max_msg_size = queue->dev_ctx->dev_attr.dev_cap.max_msg_size;
    queue->remote_rx_buf_size =
        (max_msg_size > info->queue_info->rx_buf_size) ? info->queue_info->rx_buf_size : max_msg_size;
    if (queue->flow_control.enabled) {
        for (uint32_t i = 0; i < UMQ_UB_FLOW_CONTORL_JETTY_DEPTH; i++) {
            ret = umq_ub_fill_fc_rx_buf(queue);
            if (ret != UMQ_SUCCESS) {
                goto PUT_EID_ID;
            }
        }
        umq_ub_fc_depth_exchange(queue, &queue->flow_control);
    }

    UMQ_VLOG_INFO(VLOG_UMQ, "local eid: " EID_FMT ", local jetty_id: %u, remote eid: " EID_FMT ", "
                  "remote jetty_id: %u, remote eid id: %u, remote pid: %u, remote namespace: %s, bind jetty success\n",
                  EID_ARGS(*eid), id, EID_ARGS(ctx->tjetty[UB_QUEUE_JETTY_IO]->id.eid),
                  ctx->tjetty[UB_QUEUE_JETTY_IO]->id.id,
                  ctx->remote_eid_id, info->dev_info->pid, info->dev_info->bind_namespace);
    return UMQ_SUCCESS;

PUT_EID_ID:
    (void)umq_ub_eid_id_release(queue->dev_ctx->remote_imported_info, queue->bind_ctx);

RESET_BIND_CTX:
    queue->bind_ctx = NULL;

DISCONNECT_FC_JETTY:
    if (queue->flow_control.enabled) {
        umq_ub_disconnect_jetty(queue, ctx, UB_QUEUE_JETTY_FLOW_CONTROL);
    }

DISCONNECT_IO_JETTY:
    umq_ub_disconnect_jetty(queue, ctx, UB_QUEUE_JETTY_IO);

FREE_CTX:
    free(ctx);
    return ret;
}

static ALWAYS_INLINE uint32_t umq_ub_version_info_serialize(uint8_t *bind_info_buf, uint32_t left_buf_size)
{
    if (left_buf_size < (uint32_t)sizeof(umq_ub_bind_version_info_t) + (uint32_t)sizeof(urpc_tlv_head_t)) {
        errno = UMQ_ERR_ENOMEM;
        UMQ_VLOG_ERR(VLOG_UMQ, "bind info size insufficient, version info cannot serialize, errno: %d\n", errno);
        return 0;
    }
    urpc_tlv_head_t *info_tlv_head = (urpc_tlv_head_t *)(uintptr_t)bind_info_buf;
    umq_ub_bind_version_info_t *version_info = (umq_ub_bind_version_info_t *)(uintptr_t)info_tlv_head->value;
    version_info->version = UMQ_UB_BIND_VERSION;
    info_tlv_head->type = UMQ_UB_BIND_INFO_TYPE_VERSION;
    info_tlv_head->len = (uint32_t)sizeof(umq_ub_bind_version_info_t);
    return urpc_tlv_get_total_len(info_tlv_head);
}

static int umq_ub_get_namespace(char *remote_namespace, uint32_t namespace_buf_size)
{
    char buf[UMQ_UB_NAMESPACE_SIZE] = {0};
    ssize_t len = readlink(UMQ_UB_NAMESPACE_PATH, buf, sizeof(buf) - 1);
    if (len == -1 || len >= UMQ_UB_NAMESPACE_SIZE) {
        if (errno != ENOENT) {
            UMQ_VLOG_ERR(VLOG_UMQ, "readlink failed %d, %s\n", errno, strerror(errno));
            return UMQ_FAIL;
        }
        len = 0;
        UMQ_VLOG_WARN(VLOG_UMQ, "%s file not exist\n", UMQ_UB_NAMESPACE_PATH);
    }

    buf[len++] = '\0';
    if (len > namespace_buf_size) {
        errno = UMQ_ERR_ENOMEM;
        UMQ_VLOG_ERR(VLOG_UMQ, "namespace buf size insufficient, max buf size: %u, but real namespace size: %u\n",
            namespace_buf_size, len);
        return UMQ_FAIL;
    }
    memcpy(remote_namespace, buf, len);
    if ((uint32_t)len < namespace_buf_size) {
        // clean remote_namespace
        (void)memset(remote_namespace + len, 0, namespace_buf_size - (uint32_t)len);
    }
    return (int)len;
}

static ALWAYS_INLINE uint32_t umq_ub_dev_info_serialize(
    umq_ub_ctx_t *dev_ctx, uint8_t *bind_info_buf, uint32_t left_buf_size)
{
    if (left_buf_size <
        (uint32_t)sizeof(umq_ub_bind_dev_info_t) + (uint32_t)sizeof(urpc_tlv_head_t) + UMQ_UB_NAMESPACE_SIZE) {
        errno = UMQ_ERR_ENOMEM;
        UMQ_VLOG_ERR(VLOG_UMQ, "bind info size insufficient, dev info cannot serialize, errno: %d\n", errno);
        return 0;
    }
    urpc_tlv_head_t *info_tlv_head = (urpc_tlv_head_t *)(uintptr_t)bind_info_buf;
    umq_ub_bind_dev_info_t *dev_info = (umq_ub_bind_dev_info_t *)(uintptr_t)info_tlv_head->value;
    dev_info->umq_trans_mode = dev_ctx->trans_info.trans_mode;
    (void)memcpy(&dev_info->tseg, dev_ctx->tseg_list[UMQ_QBUF_DEFAULT_MEMPOOL_ID], sizeof(urma_target_seg_t));
    dev_info->buf_pool_mode = umq_qbuf_mode_get();
    dev_info->feature = dev_ctx->feature;
    dev_info->pid = (uint32_t)getpid();

    int ret = umq_ub_get_namespace(dev_info->bind_namespace, UMQ_UB_NAMESPACE_SIZE);
    if (ret < 0) {
        UMQ_VLOG_ERR(VLOG_UMQ, "get remote_namespace failed\n")
        return 0;
    }

    // namespace len alignment 4 byte
    dev_info->namespace_len = (((uint32_t)ret + UMQ_LEN_ALIGNMENT_4 - 1) & ~(UMQ_LEN_ALIGNMENT_4 - 1));
    info_tlv_head->type = UMQ_UB_BIND_INFO_TYPE_DEV;
    info_tlv_head->len = (uint32_t)sizeof(umq_ub_bind_dev_info_t) + dev_info->namespace_len;
    return urpc_tlv_get_total_len(info_tlv_head);
}

static ALWAYS_INLINE uint32_t umq_ub_queue_info_serialize(
    ub_queue_t *queue, uint8_t *bind_info_buf, uint32_t left_buf_size)
{
    if (left_buf_size < (uint32_t)sizeof(umq_ub_bind_queue_info_t) + (uint32_t)sizeof(urpc_tlv_head_t)) {
        errno = UMQ_ERR_ENOMEM;
        UMQ_VLOG_ERR(VLOG_UMQ, "eid: " EID_FMT ", jetty_id: %u, bind info size insufficient, version info cannot "
            "serialize, errno: %d\n", EID_ARGS(queue->jetty[UB_QUEUE_JETTY_IO]->jetty_id.eid),
            queue->jetty[UB_QUEUE_JETTY_IO]->jetty_id.id, errno);
        return 0;
    }
    urpc_tlv_head_t *info_tlv_head = (urpc_tlv_head_t *)(uintptr_t)bind_info_buf;
    umq_ub_bind_queue_info_t *queue_info = (umq_ub_bind_queue_info_t *)(uintptr_t)info_tlv_head->value;
    queue_info->is_binded = queue->bind_ctx != NULL ? 1 : 0;
    queue_info->jetty_id = queue->jetty[UB_QUEUE_JETTY_IO]->jetty_id;
    queue_info->type = URMA_JETTY;
    queue_info->token = queue->jetty[UB_QUEUE_JETTY_IO]->jetty_cfg.shared.jfr->jfr_cfg.token_value;
    queue_info->notify_buf = umq_ub_notify_buf_addr_get(queue, OFFSET_MEM_IMPORT);
    queue_info->order_type = queue->order_type;
    queue_info->tp_mode = queue->tp_mode;
    queue_info->tp_type = queue->tp_type;
    queue_info->rx_depth = queue->rx_depth;
    queue_info->tx_depth = queue->tx_depth;
    queue_info->rx_buf_size = queue->rx_buf_size;
    queue_info->state = queue->state;
    info_tlv_head->type = UMQ_UB_BIND_INFO_TYPE_QUEUE;
    info_tlv_head->len = sizeof(umq_ub_bind_queue_info_t);
    return urpc_tlv_get_total_len(info_tlv_head);
}

static ALWAYS_INLINE uint32_t umq_ub_fc_info_serialize(
    ub_queue_t *queue, uint8_t *bind_info_buf, uint32_t left_buf_size)
{
    if (left_buf_size < (uint32_t)sizeof(umq_ub_bind_fc_info_t) + (uint32_t)sizeof(urpc_tlv_head_t)) {
        errno = UMQ_ERR_ENOMEM;
        UMQ_VLOG_ERR(VLOG_UMQ, "eid: " EID_FMT ", jetty_id: %u, bind info size insufficient, version info cannot "
            "serialize, errno: %d\n", EID_ARGS(queue->jetty[UB_QUEUE_JETTY_IO]->jetty_id.eid),
            queue->jetty[UB_QUEUE_JETTY_IO]->jetty_id.id, errno);
        return 0;
    }
    urpc_tlv_head_t *info_tlv_head = (urpc_tlv_head_t *)(uintptr_t)bind_info_buf;
    umq_ub_bind_fc_info_t *fc_info = (umq_ub_bind_fc_info_t *)(uintptr_t)info_tlv_head->value;
    if (queue->flow_control.enabled) {
        fc_info->jetty_id = queue->jetty[UB_QUEUE_JETTY_FLOW_CONTROL]->jetty_id;
        fc_info->token = queue->jetty[UB_QUEUE_JETTY_FLOW_CONTROL]->jetty_cfg.shared.jfr->jfr_cfg.token_value;
        fc_info->win_buf_addr = umq_ub_notify_buf_addr_get(queue, OFFSET_FLOW_CONTROL);
        fc_info->win_buf_len = UMQ_UB_RW_SEGMENT_LEN;
    } else {
        memset(&fc_info->jetty_id, 0, sizeof(urma_jetty_id_t));
        fc_info->token.token = 0;
        fc_info->win_buf_addr = 0;
        fc_info->win_buf_len = 0;
    }
    info_tlv_head->type = UMQ_UB_BIND_INFO_TYPE_FC;
    info_tlv_head->len = (uint64_t)sizeof(umq_ub_bind_fc_info_t);
    return urpc_tlv_get_total_len(info_tlv_head);
}

uint32_t umq_ub_bind_info_serialize(ub_queue_t *queue, uint8_t *bind_info, uint32_t bind_info_size)
{
    uint32_t info_data_size = 0;
    urma_eid_t *eid = &queue->jetty[UB_QUEUE_JETTY_IO]->jetty_id.eid;
    uint32_t id = queue->jetty[UB_QUEUE_JETTY_IO]->jetty_id.id;
    // fill version info
    uint32_t data_size = umq_ub_version_info_serialize(bind_info, bind_info_size);
    if (data_size == 0) {
        UMQ_VLOG_ERR(VLOG_UMQ, "eid: " EID_FMT ", jetty_id: %u, serialize version info failed\n",
            EID_ARGS(*eid), id);
        return 0;
    }
    info_data_size += data_size;

    // fill dev info
    data_size = umq_ub_dev_info_serialize(queue->dev_ctx, bind_info + info_data_size, bind_info_size - info_data_size);
    if (data_size == 0) {
        UMQ_VLOG_ERR(VLOG_UMQ, "eid: " EID_FMT ", jetty_id: %u, serialize dev info failed\n", EID_ARGS(*eid), id);
        return 0;
    }
    info_data_size += data_size;

    // fill queue info
    data_size = umq_ub_queue_info_serialize(queue, bind_info + info_data_size, bind_info_size - info_data_size);
    if (data_size == 0) {
        UMQ_VLOG_ERR(VLOG_UMQ, "eid: " EID_FMT ", jetty_id: %u, serialize queue info failed\n",
            EID_ARGS(*eid), id);
        return 0;
    }
    info_data_size += data_size;

    // fill fc info
    data_size = umq_ub_fc_info_serialize(queue, bind_info + info_data_size, bind_info_size - info_data_size);
    if (data_size == 0) {
        UMQ_VLOG_ERR(VLOG_UMQ, "eid: " EID_FMT ", jetty_id: %u, serialize fc info failed\n", EID_ARGS(*eid), id);
        return 0;
    }
    info_data_size += data_size;
    return info_data_size;
}

int umq_ub_bind_info_deserialize(uint8_t *bind_info_buf, uint32_t bind_info_size, umq_ub_bind_info_t *bind_info)
{
    if (bind_info_size < (uint32_t)sizeof(urpc_tlv_head_t)) {
        UMQ_VLOG_ERR(VLOG_UMQ, "bind info size %u insufficient\n", bind_info_size);
        return -UMQ_ERR_EINVAL;
    }

    uint32_t left_info_size = bind_info_size;
    urpc_tlv_head_t *info_tlv_head = (urpc_tlv_head_t *)(uintptr_t)bind_info_buf;
    if (info_tlv_head->len > (UINT32_MAX - (uint32_t)sizeof(urpc_tlv_head_t))) {
        UMQ_VLOG_ERR(VLOG_UMQ, "bind info size %u exceeds the maximum value\n", info_tlv_head->len);
        return -UMQ_ERR_EINVAL;
    }
    while (left_info_size >= urpc_tlv_get_total_len(info_tlv_head)) {
        switch (info_tlv_head->type) {
            case UMQ_UB_BIND_INFO_TYPE_VERSION:
                if (info_tlv_head->len < (uint32_t)sizeof(umq_ub_bind_version_info_t)) {
                    UMQ_VLOG_ERR(VLOG_UMQ, "bind version info size %u insufficient\n", info_tlv_head->len);
                    return -UMQ_ERR_EINVAL;
                }
                bind_info->version_info = (umq_ub_bind_version_info_t *)(uintptr_t)info_tlv_head->value;
                break;
            case UMQ_UB_BIND_INFO_TYPE_DEV:
                if (info_tlv_head->len < (uint32_t)sizeof(umq_ub_bind_dev_info_t)) {
                    UMQ_VLOG_ERR(VLOG_UMQ, "bind dev info size %u insufficient\n", info_tlv_head->len);
                    return -UMQ_ERR_EINVAL;
                }
                bind_info->dev_info = (umq_ub_bind_dev_info_t *)(uintptr_t)info_tlv_head->value;
                if (info_tlv_head->len != (sizeof(umq_ub_bind_dev_info_t) + bind_info->dev_info->namespace_len)) {
                    UMQ_VLOG_ERR(VLOG_UMQ, "bind dev info namespace_len %u insufficient\n", info_tlv_head->len);
                    return -UMQ_ERR_EINVAL;
                }
                size_t len = strnlen(bind_info->dev_info->bind_namespace, bind_info->dev_info->namespace_len);
                if (len == bind_info->dev_info->namespace_len) {
                    UMQ_VLOG_ERR(VLOG_UMQ, "bind dev info namespace not be null-terminated\n");
                    return -UMQ_ERR_EINVAL;
                }
                break;
            case UMQ_UB_BIND_INFO_TYPE_QUEUE:
                if (info_tlv_head->len < (uint32_t)sizeof(umq_ub_bind_queue_info_t)) {
                    UMQ_VLOG_ERR(VLOG_UMQ, "bind queue info size %u insufficient\n", info_tlv_head->len);
                    return -UMQ_ERR_EINVAL;
                }
                bind_info->queue_info = (umq_ub_bind_queue_info_t *)(uintptr_t)info_tlv_head->value;
                break;
            case UMQ_UB_BIND_INFO_TYPE_FC:
                if (info_tlv_head->len < (uint32_t)sizeof(umq_ub_bind_fc_info_t)) {
                    UMQ_VLOG_ERR(VLOG_UMQ, "bind flow control info size %u insufficient\n", info_tlv_head->len);
                    return -UMQ_ERR_EINVAL;
                }
                bind_info->fc_info = (umq_ub_bind_fc_info_t *)(uintptr_t)info_tlv_head->value;
                break;
            default:
                UMQ_VLOG_WARN(VLOG_UMQ, "unknown type %u\n", info_tlv_head->type);
                break;
        }

        left_info_size -= urpc_tlv_get_total_len(info_tlv_head);
        if (left_info_size < (uint32_t)sizeof(urpc_tlv_head_t)) {
            break;
        }
        info_tlv_head = urpc_tlv_get_next_element(info_tlv_head);
        if (info_tlv_head->len > (UINT32_MAX - (uint32_t)sizeof(urpc_tlv_head_t))) {
            UMQ_VLOG_ERR(VLOG_UMQ, "bind info size %u exceeds the maximum value\n", info_tlv_head->len);
            return -UMQ_ERR_EINVAL;
        }
    }
    return UMQ_SUCCESS;
}

int umq_modify_ubq_to_err(ub_queue_t *queue, umq_io_direction_t direction, ub_queue_jetty_index_t jetty_idx)
{
    urma_status_t urma_status = URMA_EINVAL;
    if (direction == UMQ_IO_ALL || direction == UMQ_IO_TX) {
        urma_jetty_attr_t jetty_attr = {
            .mask = JETTY_STATE,
            .state = URMA_JETTY_STATE_ERROR,
        };
        urma_status = umq_symbol_urma()->urma_modify_jetty(queue->jetty[jetty_idx], &jetty_attr);
        if (urma_status != URMA_SUCCESS) {
            UMQ_VLOG_ERR(VLOG_UMQ_URMA_API, "eid: " EID_FMT ", jetty_id: %u, urma_modify_jetty to "
                "URMA_JETTY_STATE_ERROR failed, status: %u\n",  EID_ARGS(queue->jetty[jetty_idx]->jetty_id.eid),
                queue->jetty[jetty_idx]->jetty_id.id, (int)urma_status);
        }
    }

    if (direction == UMQ_IO_ALL || direction == UMQ_IO_RX) {
        urma_jfr_attr_t jfr_attr = {
            .mask = JETTY_STATE,
            .state = URMA_JFR_STATE_ERROR,
        };
        urma_status = umq_symbol_urma()->urma_modify_jfr(queue->jfr_ctx[jetty_idx]->jfr, &jfr_attr);
        if (urma_status != URMA_SUCCESS) {
            UMQ_VLOG_ERR(VLOG_UMQ_URMA_API, "eid: " EID_FMT ", jetty_id: %u, urma_modify_jfr to URMA_JFR_STATE_ERROR"
                " failed, status: %u\n", EID_ARGS(queue->jetty[jetty_idx]->jetty_id.eid),
                queue->jetty[jetty_idx]->jetty_id.id, (int)urma_status);
        }
    }

    queue->state = QUEUE_STATE_ERR;
    return umq_status_convert(urma_status);
}

static int umq_find_ub_dev_by_ip_addr(umq_dev_assign_t *dev_info, umq_ub_raw_dev_t *out)
{
    const char *ip_addr =
        dev_info->assign_mode == UMQ_DEV_ASSIGN_MODE_IPV4 ? dev_info->ipv4.ip_addr : dev_info->ipv6.ip_addr;
    umq_eid_t eid;
    int ret = umq_symbol_urma()->urma_str_to_eid(ip_addr, (urma_eid_t *)(uintptr_t)&eid);
    if (ret != UMQ_SUCCESS) {
        UMQ_VLOG_ERR(VLOG_UMQ_URMA_API, "urma_str_to_eid for format ip addr to eid failed, ip_addr %s, status: %d\n",
            ip_addr, ret);
        return ret;
    }
    return umq_ub_dev_lookup_by_eid(&eid, out);
}

int umq_ub_get_urma_dev(umq_dev_assign_t *dev_info, urma_device_t **urma_dev, umq_eid_t *eid, uint32_t *eid_index)
{
    int ret;
    umq_ub_raw_dev_t out;
    if (dev_info->assign_mode == UMQ_DEV_ASSIGN_MODE_DEV) {
        ret = umq_ub_dev_lookup_by_name(dev_info->dev.dev_name, dev_info->dev.eid_idx, &out);
    } else if (dev_info->assign_mode == UMQ_DEV_ASSIGN_MODE_EID) {
        ret = umq_ub_dev_lookup_by_eid(&dev_info->eid.eid, &out);
    } else if (dev_info->assign_mode == UMQ_DEV_ASSIGN_MODE_IPV4 ||
               dev_info->assign_mode == UMQ_DEV_ASSIGN_MODE_IPV6) {
        ret = umq_find_ub_dev_by_ip_addr(dev_info, &out);
    } else {
        ret = -UMQ_ERR_EINVAL;
        UMQ_VLOG_ERR(VLOG_UMQ, "assign mode: %d not supported\n", dev_info->assign_mode);
    }

    if (ret != UMQ_SUCCESS) {
        return ret;
    }

    *urma_dev = out.urma_dev;
    *eid = out.eid;
    *eid_index = out.eid_index;

    return UMQ_SUCCESS;
}

int umq_ub_create_urma_ctx(urma_device_t *urma_dev, uint32_t eid_index, umq_ub_ctx_t *ub_ctx)
{
    urma_device_attr_t dev_attr;
    urma_status_t status = umq_symbol_urma()->urma_query_device(urma_dev, &dev_attr);
    if (status != URMA_SUCCESS) {
        UMQ_VLOG_ERR(VLOG_UMQ_URMA_API, "urma_query_device failed, device name: %s, status: %d\n", *urma_dev->name,
            (int)status);
        return umq_status_convert(status);
    }
    ub_ctx->dev_attr = dev_attr;

    ub_ctx->urma_ctx = umq_symbol_urma()->urma_create_context(urma_dev, eid_index);
    if (ub_ctx->urma_ctx == NULL) {
        UMQ_VLOG_ERR(VLOG_UMQ_URMA_API, "urma_create_context failed, errno: %d\n", errno);
        return -UMQ_ERR_ENODEV;
    }
    return UMQ_SUCCESS;
}

int umq_ub_delete_urma_ctx(umq_ub_ctx_t *ub_ctx)
{
    if (ub_ctx == NULL || ub_ctx->urma_ctx) {
        UMQ_VLOG_ERR(VLOG_UMQ, "invalid parameter\n");
        return -UMQ_ERR_EINVAL;
    }

    urma_status_t urma_status = umq_symbol_urma()->urma_delete_context(ub_ctx->urma_ctx);
    if (urma_status != URMA_SUCCESS) {
        UMQ_VLOG_ERR(VLOG_UMQ_URMA_API, "urma_delete_context failed, status: %d\n", (int)urma_status);
        return umq_status_convert(urma_status);
    }

    ub_ctx->urma_ctx = NULL;
    return UMQ_SUCCESS;
}

umq_ub_ctx_t *umq_ub_get_ub_ctx_by_dev_info(umq_ub_ctx_t *ub_ctx_list, uint32_t ub_ctx_cnt, umq_dev_assign_t *dev_info)
{
    umq_ub_ctx_t *ub_ctx = NULL;
    urma_device_t *urma_dev;
    umq_dev_assign_t eid_dev_info = {.assign_mode = UMQ_DEV_ASSIGN_MODE_EID};
    uint32_t eid_index = 0;

    // get ub dev eid
    if (dev_info->assign_mode != UMQ_DEV_ASSIGN_MODE_EID) {
        int ret = umq_ub_get_urma_dev(dev_info, &urma_dev, &eid_dev_info.eid.eid, &eid_index);
        if (ret != UMQ_SUCCESS) {
            char dev_str[UMQ_UB_DEV_STR_LENGTH] = {0};
            (void)umq_ub_dev_str_get(dev_info, dev_str, UMQ_UB_DEV_STR_LENGTH);
            UMQ_VLOG_ERR(VLOG_UMQ, "failed to get urma_dev: %s, status: %d\n", dev_str, ret);
            return NULL;
        }
    } else {
        eid_dev_info.eid.eid = dev_info->eid.eid;
    }

    for (uint32_t i = 0; i < ub_ctx_cnt; i++) {
        if (ub_ctx_list[i].trans_info.dev_info.assign_mode == eid_dev_info.assign_mode &&
            memcmp(&ub_ctx_list[i].trans_info.dev_info.eid.eid, &eid_dev_info.eid.eid, sizeof(umq_eid_t)) == 0) {
            ub_ctx = &ub_ctx_list[i];
            break;
        }
    }
    return ub_ctx;
}

remote_imported_tseg_info_t *umq_ub_ctx_imported_info_create(void)
{
    remote_imported_tseg_info_t *remote_imported_tseg_info =
        (remote_imported_tseg_info_t *)calloc(1, sizeof(remote_imported_tseg_info_t));
    if (remote_imported_tseg_info == NULL) {
        UMQ_VLOG_ERR(VLOG_UMQ, "calloc imported info failed\n");
        return NULL;
    }

    int ret = urpc_hmap_init(&remote_imported_tseg_info->remote_eid_id_table, UMQ_UB_MAX_REMOTE_EID_NUM);
    if (ret != UMQ_SUCCESS) {
        UMQ_VLOG_ERR(VLOG_UMQ, "remote eid map init failed, status: %d\n", ret);
        goto FREE_INFO;
    }

    ret = util_id_allocator_init(&remote_imported_tseg_info->eid_id_allocator,
        UMQ_UB_MAX_REMOTE_EID_NUM, UMQ_UB_MIN_EID_ID);
    if (ret != UMQ_SUCCESS) {
        UMQ_VLOG_ERR(VLOG_UMQ, "bind id allocator init failed, status: %d\n", ret);
        goto REMOTE_EID_MAP_UNINIT;
    }

    remote_imported_tseg_info->remote_eid_id_table_lock = util_mutex_lock_create(UTIL_MUTEX_ATTR_EXCLUSIVE);
    if (remote_imported_tseg_info->remote_eid_id_table_lock == NULL) {
        UMQ_VLOG_ERR(VLOG_UMQ, "remote eid_id_table mutex create failed\n");
        goto ID_ALLOCATOR_UNINIT;
    }
    return remote_imported_tseg_info;

ID_ALLOCATOR_UNINIT:
    util_id_allocator_uninit(&remote_imported_tseg_info->eid_id_allocator);

REMOTE_EID_MAP_UNINIT:
    urpc_hmap_uninit(&remote_imported_tseg_info->remote_eid_id_table);

FREE_INFO:
    free(remote_imported_tseg_info);
    return NULL;
}

void umq_ub_ctx_imported_info_destroy(umq_ub_ctx_t *ub_ctx)
{
    if (ub_ctx == NULL || ub_ctx->remote_imported_info == NULL) {
        return;
    }

    remote_imported_tseg_info_t *remote_imported_tseg_info = ub_ctx->remote_imported_info;
    remote_eid_hmap_node_t *cur = NULL;
    remote_eid_hmap_node_t *next = NULL;
    URPC_HMAP_FOR_EACH_SAFE(cur, next, node, &remote_imported_tseg_info->remote_eid_id_table) {
        urpc_hmap_remove(&remote_imported_tseg_info->remote_eid_id_table, &cur->node);
        free(cur);
    }
    (void)util_mutex_lock_destroy(remote_imported_tseg_info->remote_eid_id_table_lock);
    remote_imported_tseg_info->remote_eid_id_table_lock = NULL;
    urpc_hmap_uninit(&remote_imported_tseg_info->remote_eid_id_table);
    util_id_allocator_uninit(&ub_ctx->remote_imported_info->eid_id_allocator);
    free(ub_ctx->remote_imported_info);
    ub_ctx->remote_imported_info = NULL;
}

urma_jetty_t *umq_create_jetty(ub_queue_t *queue, umq_ub_ctx_t *dev_ctx, ub_queue_jetty_index_t jetty_idx)
{
    urma_jetty_cfg_t jetty_cfg = {
        .jfs_cfg = {
            .flag.bs.order_type = queue->order_type,
            .trans_mode = queue->tp_mode,
            .depth = jetty_idx == UB_QUEUE_JETTY_IO ? queue->tx_depth : UMQ_UB_FLOW_CONTORL_JETTY_DEPTH,
            .priority = queue->priority,
            .max_sge = queue->max_tx_sge,
            .max_inline_data = dev_ctx->dev_attr.dev_cap.max_jfs_inline_len,
            .jfc = queue->jfs_jfc[jetty_idx],
            .rnr_retry = queue->rnr_retry,
            .err_timeout = queue->err_timeout,
        },
        .id = 0,
    };
    jetty_cfg.flag.bs.share_jfr = true;
    jetty_cfg.shared.jfr = queue->jfr_ctx[jetty_idx]->jfr;

    urma_jetty_t *jetty = umq_symbol_urma()->urma_create_jetty(dev_ctx->urma_ctx, &jetty_cfg);
    if (jetty == NULL) {
        UMQ_VLOG_ERR(VLOG_UMQ_URMA_API, "urma_create_jetty failed, errno: %d\n", errno);
        return NULL;
    }
    UMQ_VLOG_INFO(VLOG_UMQ, "eid: " EID_FMT ", jetty_id: %u, create jetty[%d] success\n",
                  EID_ARGS(jetty->jetty_id.eid), jetty->jetty_id.id, jetty_idx);
    return jetty;
}

static urma_transport_mode_t umq_tp_mode_convert_to_urma(umq_tp_mode_t tp_mode)
{
    switch (tp_mode) {
        case UMQ_TM_RC:
            return URMA_TM_RC;
        case UMQ_TM_RM:
            return URMA_TM_RM;
        case UMQ_TM_UM:
            return URMA_TM_UM;
        default:
            return URMA_TM_RC;
    };
}

static urma_tp_type_t umq_tp_type_convert_to_urma(umq_tp_type_t tp_type)
{
    switch (tp_type) {
        case UMQ_TP_TYPE_RTP:
            return URMA_RTP;
        case UMQ_TP_TYPE_CTP:
            return URMA_CTP;
        case UMQ_TP_TYPE_UTP:
            return URMA_UTP;
        default:
            return URMA_RTP;
    };
}

static umq_tp_type_t umq_tp_type_get(union urma_tp_type_en tp_type)
{
    if (tp_type.bs.rtp == 1 && tp_type.bs.ctp == 0 && tp_type.bs.utp == 0) {
        return UMQ_TP_TYPE_RTP;
    }
    if (tp_type.bs.rtp == 0 && tp_type.bs.ctp == 1 && tp_type.bs.utp == 0) {
        return UMQ_TP_TYPE_CTP;
    }
    if (tp_type.bs.rtp == 0 && tp_type.bs.ctp == 0 && tp_type.bs.utp == 1) {
        return UMQ_TP_TYPE_UTP;
    }
    return UMQ_TP_TYPE_MAX;
}

static int umq_default_priority_get(umq_ub_ctx_t *dev_ctx, umq_tp_type_t actual_tp_type)
{
    for (int i = 0; i < URMA_MAX_PRIORITY_CNT; i++) {
        umq_tp_type_t tp_type = umq_tp_type_get(dev_ctx->dev_attr.dev_cap.priority_info[i].tp_type);
        if (tp_type == actual_tp_type) {
            return i;
        }
    }
   return UMQ_FAIL;
}

int check_and_set_param(umq_ub_ctx_t *dev_ctx, umq_create_option_t *option, ub_queue_t *queue)
{
    if (option->create_flag & UMQ_CREATE_FLAG_RX_BUF_SIZE) {
        if (option->rx_buf_size > dev_ctx->dev_attr.dev_cap.max_msg_size) {
            UMQ_VLOG_ERR(VLOG_UMQ, "rx buf size [%u] exceed max buf size [%d]\n", option->rx_buf_size,
                         dev_ctx->dev_attr.dev_cap.max_msg_size);
            return -UMQ_ERR_EINVAL;
        }
        queue->rx_buf_size = option->rx_buf_size;
    } else {
        queue->rx_buf_size = dev_ctx->dev_attr.dev_cap.max_msg_size < UMQ_DEFAULT_BUF_SIZE ?
                             dev_ctx->dev_attr.dev_cap.max_msg_size : UMQ_DEFAULT_BUF_SIZE;
    }
    if (option->create_flag & UMQ_CREATE_FLAG_TX_BUF_SIZE) {
        if (option->tx_buf_size > dev_ctx->dev_attr.dev_cap.max_msg_size) {
            UMQ_VLOG_ERR(VLOG_UMQ, "tx buf size [%u] exceed max buf size [%d]\n", option->tx_buf_size,
                         dev_ctx->dev_attr.dev_cap.max_msg_size);
            return -UMQ_ERR_EINVAL;
        }
        queue->tx_buf_size = option->tx_buf_size;
    } else {
        queue->tx_buf_size = dev_ctx->dev_attr.dev_cap.max_msg_size < UMQ_DEFAULT_BUF_SIZE ?
                             dev_ctx->dev_attr.dev_cap.max_msg_size : UMQ_DEFAULT_BUF_SIZE;
    }

    uint32_t min_dev_rx = dev_ctx->dev_attr.dev_cap.max_jfr_depth < dev_ctx->dev_attr.dev_cap.max_jfc_depth ?
        dev_ctx->dev_attr.dev_cap.max_jfr_depth : dev_ctx->dev_attr.dev_cap.max_jfc_depth;
    if (option->create_flag & UMQ_CREATE_FLAG_RX_DEPTH) {
        if (option->rx_depth > min_dev_rx) {
            UMQ_VLOG_ERR(VLOG_UMQ, "rx depth [%u] exceed max depth [%d]\n", option->rx_depth, min_dev_rx);
            return -UMQ_ERR_EINVAL;
        }
        queue->rx_depth = option->rx_depth;
    } else {
        queue->rx_depth = min_dev_rx < UMQ_DEFAULT_DEPTH ? min_dev_rx : UMQ_DEFAULT_DEPTH;
    }

    // tx flush_done consumes one tx_cqe
    uint32_t min_dev_tx = dev_ctx->dev_attr.dev_cap.max_jfs_depth < dev_ctx->dev_attr.dev_cap.max_jfc_depth - 1 ?
        dev_ctx->dev_attr.dev_cap.max_jfs_depth : dev_ctx->dev_attr.dev_cap.max_jfc_depth - 1;
    if (option->create_flag & UMQ_CREATE_FLAG_TX_DEPTH) {
        if (option->tx_depth > min_dev_tx) {
            UMQ_VLOG_ERR(VLOG_UMQ, "tx depth [%u] exceed max depth [%d]\n", option->tx_depth, min_dev_tx);
            return -UMQ_ERR_EINVAL;
        }
        queue->tx_depth = option->tx_depth;
    } else {
        queue->tx_depth = min_dev_tx < UMQ_DEFAULT_DEPTH ? min_dev_tx : UMQ_DEFAULT_DEPTH;
    }

    if ((dev_ctx->feature & UMQ_FEATURE_ENABLE_FLOW_CONTROL) != 0 &&
        (queue->tx_depth > UINT16_MAX || (queue->rx_depth > UINT16_MAX))) {
        UMQ_VLOG_ERR(VLOG_UMQ, "queue tx depth %u, rx depth %u exceed %u\n", queue->tx_depth,
            queue->rx_depth, UINT16_MAX);
        return -UMQ_ERR_EINVAL;
    }
    if (option->create_flag & UMQ_CREATE_FLAG_QUEUE_MODE) {
        if (option->mode < 0 || option->mode >= UMQ_MODE_MAX) {
            UMQ_VLOG_ERR(VLOG_UMQ, "queue mode[%d] is invalid\n", option->mode);
            return -UMQ_ERR_EINVAL;
        }
        queue->mode = option->mode;
    }
    if (((option->create_flag & UMQ_CREATE_FLAG_SHARE_RQ) != 0 && (option->create_flag &
        UMQ_CREATE_FLAG_SUB_UMQ) == 0) || ((option->create_flag & UMQ_CREATE_FLAG_SHARE_RQ) == 0 &&
        (option->create_flag & UMQ_CREATE_FLAG_SUB_UMQ) != 0)) {
        UMQ_VLOG_ERR(VLOG_UMQ, "queue create_flag[%u] is invalid\n", option->create_flag);
        return -UMQ_ERR_EINVAL;
    }

    if (option->create_flag & UMQ_CREATE_FLAG_TP_MODE) {
        if (option->tp_mode > UMQ_TM_RM) {
            UMQ_VLOG_ERR(VLOG_UMQ, "tp_mode[%d] is invalid\n", option->tp_mode);
            return -UMQ_ERR_EINVAL;
        }
        queue->tp_mode = umq_tp_mode_convert_to_urma(option->tp_mode);
    } else {
        queue->tp_mode = umq_tp_mode_convert_to_urma(UMQ_TM_RC);
    }

    if (option->create_flag & UMQ_CREATE_FLAG_TP_TYPE) {
        if (option->tp_type != UMQ_TP_TYPE_RTP) {
            UMQ_VLOG_ERR(VLOG_UMQ, "tp_type[%d] is invalid\n", option->tp_type);
            return -UMQ_ERR_EINVAL;
        }
        queue->tp_type = umq_tp_type_convert_to_urma(option->tp_type);
    } else {
        queue->tp_type = umq_tp_type_convert_to_urma(UMQ_TP_TYPE_RTP);
    }

    umq_tp_type_t actual_tp_type = (option->create_flag & UMQ_CREATE_FLAG_TP_TYPE) != 0 ?
        option->tp_type : UMQ_TP_TYPE_RTP;
    if (option->create_flag & UMQ_CREATE_FLAG_PRIORITY) {
        if (option->priority > URMA_MAX_PRIORITY) {
            UMQ_VLOG_ERR(VLOG_UMQ, "priority[%u] is invalid\n", option->priority);
            return -UMQ_ERR_EINVAL;
        }
        umq_tp_type_t tp_type = umq_tp_type_get(dev_ctx->dev_attr.dev_cap.priority_info[option->priority].tp_type);
        if (tp_type != actual_tp_type) {
            UMQ_VLOG_ERR(VLOG_UMQ, "priority[%u] is invalid, associated tp_type is %s, actual tp_type is %s\n",
                option->priority, g_umq_ub_tp_type_str[tp_type], g_umq_ub_tp_type_str[actual_tp_type]);
            return -UMQ_ERR_EINVAL;
        }
        queue->priority = option->priority;
    } else {
        int ret = umq_default_priority_get(dev_ctx, actual_tp_type);
        if (ret < 0) {
            UMQ_VLOG_ERR(VLOG_UMQ, "there is no priority for tp_type %s\n", g_umq_ub_tp_type_str[actual_tp_type]);
            return -UMQ_ERR_EINVAL;
        }
        queue->priority = (uint8_t)ret;
    }

    queue->max_rx_sge = dev_ctx->dev_attr.dev_cap.max_jfr_sge < UMQ_MAX_SGE_NUM ?
                        dev_ctx->dev_attr.dev_cap.max_jfr_sge : UMQ_MAX_SGE_NUM;
    queue->max_tx_sge = dev_ctx->dev_attr.dev_cap.max_jfs_sge < UMQ_MAX_SGE_NUM ?
                        dev_ctx->dev_attr.dev_cap.max_jfs_sge : UMQ_MAX_SGE_NUM;
    queue->err_timeout = DEFAULT_ERR_TIMEOUT;
    queue->rnr_retry = DEFAULT_RNR_RETRY;
    queue->min_rnr_timer = DEFAULT_MIN_RNR_TIMER;
    (void)memcpy(queue->name, option->name, UMQ_NAME_MAX_LEN);
    queue->dev_ctx = dev_ctx;
    queue->umq_trans_mode = option->trans_mode;
    queue->order_type = URMA_DEF_ORDER;
    queue->remote_rx_buf_size = dev_ctx->dev_attr.dev_cap.max_msg_size;
    queue->create_flag = option->create_flag;
    return UMQ_SUCCESS;
}

int share_rq_param_check(ub_queue_t *queue, ub_queue_t *share_rq)
{
    if (share_rq->state == QUEUE_STATE_ERR) {
        UMQ_VLOG_ERR(VLOG_UMQ, "the share_rq is invalid\n");
        goto ERR;
    }
    if (share_rq->create_flag & UMQ_CREATE_FLAG_SUB_UMQ) {
        UMQ_VLOG_ERR(VLOG_UMQ, "sub umq cannot be used as share_rq\n");
        goto ERR;
    }
    if (share_rq->dev_ctx != queue->dev_ctx) {
        UMQ_VLOG_ERR(VLOG_UMQ, "the dev_ctx of share_rq and creating_queue is different\n");
        goto ERR;
    }
    if (queue->create_flag & UMQ_CREATE_FLAG_RX_BUF_SIZE) {
        if (share_rq->rx_buf_size != queue->rx_buf_size) {
            UMQ_VLOG_ERR(VLOG_UMQ, "share_rq rx_buf_size %u and creating_queue rx_buf_size %u is different\n",
                share_rq->rx_buf_size, queue->rx_buf_size);
            goto ERR;
        }
    } else {
        queue->rx_buf_size = share_rq->rx_buf_size;
    }
    if (queue->create_flag & UMQ_CREATE_FLAG_RX_DEPTH) {
        if (share_rq->rx_depth != queue->rx_depth) {
            UMQ_VLOG_ERR(VLOG_UMQ, "share_rq rx_depth %u and creating_queue rx_depth %u is different\n",
                share_rq->rx_depth, queue->rx_depth);
            goto ERR;
        }
    } else {
        queue->rx_depth = share_rq->rx_depth;
    }
    if (queue->create_flag & UMQ_CREATE_FLAG_QUEUE_MODE) {
        if (share_rq->mode != queue->mode) {
            UMQ_VLOG_ERR(VLOG_UMQ, "share_rq mode %u and creating_queue mode %u is different\n",
                         share_rq->mode, queue->mode);
            goto ERR;
        }
    } else {
        queue->mode = share_rq->mode;
    }
    return UMQ_SUCCESS;
ERR:
    errno = UMQ_ERR_EINVAL;
    return -UMQ_ERR_EINVAL;
}

void umq_ub_jfr_ctx_destroy(ub_queue_t *queue, ub_queue_jetty_index_t jetty_idx)
{
    UMQ_VLOG_INFO(VLOG_UMQ, "eid: " EID_FMT ", jfr_id: %u, destroy jfr_ctx\n",
                  EID_ARGS(queue->jfr_ctx[jetty_idx]->jfr->jfr_id.eid), queue->jfr_ctx[jetty_idx]->jfr->jfr_id.id);
    urma_status_t status = umq_symbol_urma()->urma_delete_jfr(queue->jfr_ctx[jetty_idx]->jfr);
    if (status != URMA_SUCCESS) {
        UMQ_VLOG_ERR(VLOG_UMQ_URMA_API, "urma_delete_jfr failed, status: %d\n", (int)status);
    }
    status = umq_symbol_urma()->urma_delete_jfc(queue->jfr_ctx[jetty_idx]->jfr_jfc);
    if (status != URMA_SUCCESS) {
        UMQ_VLOG_ERR(VLOG_UMQ_URMA_API, "urma_delete_jfc failed, status: %d\n", (int)status);
    }

    // only delete the jfce of io and the jfce of sub_umq flow control
    if (queue->mode == UMQ_MODE_INTERRUPT &&
        (jetty_idx == UB_QUEUE_JETTY_IO || (queue->create_flag & UMQ_CREATE_FLAG_SUB_UMQ) != 0)) {
        status = umq_symbol_urma()->urma_delete_jfce(queue->jfr_ctx[jetty_idx]->jfr_jfce);
        if (status != URMA_SUCCESS) {
            UMQ_VLOG_ERR(VLOG_UMQ_URMA_API, "urma_delete_jfce failed, status: %d\n", (int)status);
        }
    }
    rx_buf_ctx_list_uninit(&queue->jfr_ctx[jetty_idx]->rx_buf_ctx_list);
    free(queue->jfr_ctx[jetty_idx]);
    queue->jfr_ctx[jetty_idx] = NULL;
}

void umq_ub_jfr_ctx_put(ub_queue_t *queue)
{
    uint32_t new_value = __atomic_sub_fetch(&queue->jfr_ctx[UB_QUEUE_JETTY_IO]->ref_cnt, 1, __ATOMIC_RELAXED);
    UMQ_VLOG_DEBUG(VLOG_UMQ, "jfr_ctx ref_cnt %u\n", new_value);
    if (new_value > 0) {
        return;
    }
    umq_ub_jfr_ctx_destroy(queue, UB_QUEUE_JETTY_IO);
}

jfr_ctx_t *umq_ub_jfr_ctx_create(ub_queue_t *queue, umq_ub_ctx_t *dev_ctx, ub_queue_jetty_index_t jetty_idx)
{
    bool enable_token = (dev_ctx->feature & UMQ_FEATURE_ENABLE_TOKEN_POLICY) != 0;
    uint32_t jetty_token;
    int ret = umq_ub_token_generate(enable_token, &jetty_token);
    if (ret != UMQ_SUCCESS) {
        UMQ_VLOG_ERR(VLOG_UMQ, "generate jetty token failed, status: %d\n", ret);
        return NULL;
    }

    jfr_ctx_t *jfr_ctx = calloc(1, sizeof(jfr_ctx_t));
    if (jfr_ctx == NULL) {
        UMQ_VLOG_ERR(VLOG_UMQ, "calloc jfr_ctx failed\n");
        return NULL;
    }
    // create jfce
    if (queue->mode == UMQ_MODE_INTERRUPT) {
        if (jetty_idx == UB_QUEUE_JETTY_IO || (queue->create_flag & UMQ_CREATE_FLAG_SUB_UMQ) != 0) {
            jfr_ctx->jfr_jfce = umq_symbol_urma()->urma_create_jfce(dev_ctx->urma_ctx);
        } else {
            jfr_ctx->jfr_jfce = queue->jfr_ctx[UB_QUEUE_JETTY_IO]->jfr_jfce;
        }
        if (jfr_ctx->jfr_jfce == NULL) {
            UMQ_VLOG_ERR(VLOG_UMQ, "create jfr_jfce failed\n");
            goto FREE_JFR_CTX;
        }
    }
    // create jfr_jfc
    urma_jfc_cfg_t jfr_jfc_cfg = {
        .depth = jetty_idx == UB_QUEUE_JETTY_IO ? queue->rx_depth : UMQ_UB_FLOW_CONTORL_JETTY_DEPTH,
        .jfce = jfr_ctx->jfr_jfce
    };
    jfr_ctx->jfr_jfc = umq_symbol_urma()->urma_create_jfc(dev_ctx->urma_ctx, &jfr_jfc_cfg);
    if (jfr_ctx->jfr_jfc == NULL) {
        UMQ_VLOG_ERR(VLOG_UMQ_URMA_API, "urma_create_jfc failed, errno: %d\n", errno);
        goto DELETE_JFR_JFCE;
    }
    // create jfr
    urma_jfr_cfg_t jfr_cfg = {
        .flag.bs.token_policy = token_policy_get(enable_token),
        .trans_mode = queue->tp_mode,
        .depth = jetty_idx == UB_QUEUE_JETTY_IO ? queue->rx_depth : UMQ_UB_FLOW_CONTORL_JETTY_DEPTH,
        .max_sge = queue->max_rx_sge,
        .min_rnr_timer = queue->min_rnr_timer,
        .jfc = jfr_ctx->jfr_jfc,
        .token_value = { .token = jetty_token }
    };
    jfr_cfg.flag.bs.order_type = queue->order_type;
    jfr_ctx->jfr = umq_symbol_urma()->urma_create_jfr(dev_ctx->urma_ctx, &jfr_cfg);
    if (jfr_ctx->jfr == NULL) {
        UMQ_VLOG_ERR(VLOG_UMQ_URMA_API, "urma_create_jfr failed, errno: %d\n", errno);
        goto DELETE_JFR_JFC;
    }

    // fc not use rx buf list
    if (jetty_idx == UB_QUEUE_JETTY_IO &&
        rx_buf_ctx_list_init(&jfr_ctx->rx_buf_ctx_list, queue->rx_depth) != UMQ_SUCCESS) {
        UMQ_VLOG_ERR(VLOG_UMQ, "rx buf ctx list init failed\n");
        goto DELETE_JFR;
    }

    jfr_ctx->ref_cnt = 1;
    UMQ_VLOG_INFO(VLOG_UMQ, "create jfr_ctx success, eid: " EID_FMT ", jfr_id: %u\n",
                  EID_ARGS(jfr_ctx->jfr->jfr_id.eid), jfr_ctx->jfr->jfr_id.id);
    return jfr_ctx;

DELETE_JFR:
    (void)umq_symbol_urma()->urma_delete_jfr(jfr_ctx->jfr);

DELETE_JFR_JFC:
    (void)umq_symbol_urma()->urma_delete_jfc(jfr_ctx->jfr_jfc);

DELETE_JFR_JFCE:
    if (queue->mode == UMQ_MODE_INTERRUPT &&
        (jetty_idx == UB_QUEUE_JETTY_IO || (queue->create_flag & UMQ_CREATE_FLAG_SUB_UMQ) != 0)) {
        (void)umq_symbol_urma()->urma_delete_jfce(jfr_ctx->jfr_jfce);
    }

FREE_JFR_CTX:
    free(jfr_ctx);
    return NULL;
}

int umq_ub_jfr_ctx_get(ub_queue_t *queue, umq_ub_ctx_t *dev_ctx, umq_create_option_t *option,
                       ub_queue_t *share_queue)
{
    if ((option->create_flag & UMQ_CREATE_FLAG_SHARE_RQ) != 0) {
        queue->jfr_ctx[UB_QUEUE_JETTY_IO] = share_queue->jfr_ctx[UB_QUEUE_JETTY_IO];
        (void)__atomic_add_fetch(&queue->jfr_ctx[UB_QUEUE_JETTY_IO]->ref_cnt, 1, __ATOMIC_RELEASE);
        return UMQ_SUCCESS;
    }

    queue->jfr_ctx[UB_QUEUE_JETTY_IO] = umq_ub_jfr_ctx_create(queue, dev_ctx, UB_QUEUE_JETTY_IO);
    if (queue->jfr_ctx[UB_QUEUE_JETTY_IO] == NULL) {
        UMQ_VLOG_ERR(VLOG_UMQ, "umq create jfr ctx failed\n");
        return UMQ_FAIL;
    }
    return UMQ_SUCCESS;
}

uint32_t token_policy_get(bool enable)
{
    return enable ? URMA_TOKEN_PLAIN_TEXT : URMA_TOKEN_NONE;
}

int umq_ub_token_generate(bool enable_token, uint32_t *token)
{
    if (!enable_token) {
        *token = get_timestamp();
        return 0;
    }

    return urpc_rand_generate((uint8_t *)token, sizeof(uint32_t));
}

int umq_ub_register_seg(umq_ub_ctx_t *ctx, uint16_t mempool_id, void *addr, uint64_t size)
{
    if (ctx->tseg_list[mempool_id] != NULL) {
        UMQ_VLOG_WARN(VLOG_UMQ, "seg already registered, mempool_id: %u\n", mempool_id);
        return UMQ_SUCCESS;
    }
    bool enable_token = (ctx->feature & UMQ_FEATURE_ENABLE_TOKEN_POLICY) != 0;
    uint32_t mem_token;
    int ret = umq_ub_token_generate(enable_token, &mem_token);
    if (ret != UMQ_SUCCESS) {
        UMQ_VLOG_ERR(VLOG_UMQ, "generate memory token failed, status: %d\n", ret);
        return ret;
    }

    urma_reg_seg_flag_t flag = {
        .bs.token_policy = token_policy_get(enable_token),
        .bs.cacheable = URMA_NON_CACHEABLE,
        .bs.reserved = 0,
        .bs.access = URMA_ACCESS_READ | URMA_ACCESS_WRITE | URMA_ACCESS_ATOMIC
    };
    urma_token_t token = { .token = mem_token };
    urma_seg_cfg_t seg_cfg = {
        .va = (uint64_t)(uintptr_t)addr,
        .len = size,
        .token_id = NULL,
        .token_value = token,
        .flag = flag,
        .user_ctx = token.token,
        .iova = 0
    };

    ctx->tseg_list[mempool_id] = umq_symbol_urma()->urma_register_seg(ctx->urma_ctx, &seg_cfg);
    if (ctx->tseg_list[mempool_id] == NULL) {
        UMQ_VLOG_ERR(VLOG_UMQ_URMA_API, "urma_register_seg failed, errno: %d\n", errno);
        return -UMQ_ERR_ENODEV;
    }

    return UMQ_SUCCESS;
}

void umq_ub_unregister_seg(umq_ub_ctx_t *ctx_list, uint32_t ctx_cnt, uint16_t mempool_id)
{
    for (uint32_t i = 0; i < ctx_cnt; i++) {
        if (ctx_list[i].tseg_list[mempool_id] != NULL) {
            urma_status_t status = umq_symbol_urma()->urma_unregister_seg(ctx_list[i].tseg_list[mempool_id]);
            if (status != URMA_SUCCESS) {
                UMQ_VLOG_ERR(VLOG_UMQ_URMA_API, "urma_unregister_seg for ub ctx[%u] failed, status: %d\n", i, status);
            }
        }
        ctx_list[i].tseg_list[mempool_id] = NULL;
    }
}

void handle_async_event_jfc_err(urma_async_event_t *urma_event, umq_async_event_t *umq_event)
{
    bool find = false;
    ub_queue_t *local = NULL;
    umq_event->event_type = UMQ_EVENT_QH_ERR;
    umq_event->element.umqh = UMQ_INVALID_HANDLE;

    (void)util_rwlock_rdlock(g_umq_ub_queue_ctx_list.lock);
    URPC_LIST_FOR_EACH(local, qctx_node, &g_umq_ub_queue_ctx_list.queue_list) {
        if (local->jfs_jfc[UB_QUEUE_JETTY_IO] == urma_event->element.jfc || (local->flow_control.enabled &&
            local->jfs_jfc[UB_QUEUE_JETTY_FLOW_CONTROL] == urma_event->element.jfc)) {
            find = true;
            umq_event->event_type = UMQ_EVENT_QH_SQ_CQ_ERR;
            umq_event->element.umqh = local->umqh;
            break;
        }

        if (local->jfr_ctx[UB_QUEUE_JETTY_IO]->jfr_jfc == urma_event->element.jfc || (local->flow_control.enabled &&
            local->jfr_ctx[UB_QUEUE_JETTY_FLOW_CONTROL]->jfr_jfc == urma_event->element.jfc)) {
            find = true;
            umq_event->event_type = UMQ_EVENT_QH_RQ_CQ_ERR;
            /* sub umq submit main_qh to user */
            if (local->create_flag & UMQ_CREATE_FLAG_SUB_UMQ) {
                umq_event->element.umqh = local->share_rq_umqh;
                break;
            }
            umq_event->element.umqh = local->umqh;
            break;
        }
    }
    (void)util_rwlock_unlock(g_umq_ub_queue_ctx_list.lock);

    if (!find) {
        UMQ_VLOG_WARN(VLOG_UMQ_URMA_AE, "find jfc id %u in all umq failed\n", urma_event->element.jfc->jfc_id.id);
    } else {
        UMQ_VLOG_INFO(VLOG_UMQ_URMA_AE, "find jfc id %u success, urma event_type %d, umq event_type %d\n",
            urma_event->element.jfc->jfc_id.id, urma_event->event_type, umq_event->event_type);
    }
}

void handle_async_event_jfr_err(urma_async_event_t *urma_event, umq_async_event_t *umq_event)
{
    bool find = false;
    ub_queue_t *local = NULL;
    umq_event->event_type = UMQ_EVENT_QH_RQ_ERR;
    umq_event->element.umqh = UMQ_INVALID_HANDLE;

    (void)util_rwlock_rdlock(g_umq_ub_queue_ctx_list.lock);
    URPC_LIST_FOR_EACH(local, qctx_node, &g_umq_ub_queue_ctx_list.queue_list) {
        if (local->jfr_ctx[UB_QUEUE_JETTY_IO]->jfr == urma_event->element.jfr || (local->flow_control.enabled &&
            local->jfr_ctx[UB_QUEUE_JETTY_FLOW_CONTROL]->jfr == urma_event->element.jfr)) {
            find = true;
            /* sub umq submit main_qh to user */
            if (local->create_flag & UMQ_CREATE_FLAG_SUB_UMQ) {
                umq_event->element.umqh = local->share_rq_umqh;
                break;
            }
            umq_event->element.umqh = local->umqh;
            break;
        }
    }
    (void)util_rwlock_unlock(g_umq_ub_queue_ctx_list.lock);

    if (!find) {
        UMQ_VLOG_WARN(VLOG_UMQ_URMA_AE, "find jfr id %u in all umq failed\n", urma_event->element.jfr->jfr_id.id);
    } else {
        UMQ_VLOG_INFO(VLOG_UMQ_URMA_AE, "find jfr id %u success, urma event_type %d, umq event_type %d\n",
            urma_event->element.jfr->jfr_id.id, urma_event->event_type, umq_event->event_type);
    }
}

void handle_async_event_jfr_limit(urma_async_event_t *urma_event, umq_async_event_t *umq_event)
{
    bool find = false;
    ub_queue_t *local = NULL;
    umq_event->event_type = UMQ_EVENT_QH_RQ_LIMIT;
    umq_event->element.umqh = UMQ_INVALID_HANDLE;

    (void)util_rwlock_rdlock(g_umq_ub_queue_ctx_list.lock);
    URPC_LIST_FOR_EACH(local, qctx_node, &g_umq_ub_queue_ctx_list.queue_list) {
        if (local->jfr_ctx[UB_QUEUE_JETTY_IO]->jfr == urma_event->element.jfr || (local->flow_control.enabled &&
            local->jfr_ctx[UB_QUEUE_JETTY_FLOW_CONTROL]->jfr == urma_event->element.jfr)) {
            find = true;
            if (local->create_flag & UMQ_CREATE_FLAG_SUB_UMQ) {
                umq_event->element.umqh = local->share_rq_umqh;
                break;
            }
            umq_event->element.umqh = local->umqh;
            break;
        }
    }
    (void)util_rwlock_unlock(g_umq_ub_queue_ctx_list.lock);

    if (!find) {
        UMQ_VLOG_WARN(VLOG_UMQ_URMA_AE, "find jfr id %u in all umq failed\n", urma_event->element.jfr->jfr_id.id);
    } else {
        UMQ_VLOG_INFO(VLOG_UMQ_URMA_AE, "find jfr id %u success, urma event_type %d, umq event_type %d\n",
            urma_event->element.jfr->jfr_id.id, urma_event->event_type, umq_event->event_type);
    }
}

void handle_async_event_jetty_err(urma_async_event_t *urma_event, umq_async_event_t *umq_event)
{
    bool find = false;
    ub_queue_t *local = NULL;
    umq_event->event_type = UMQ_EVENT_QH_ERR;
    umq_event->element.umqh = UMQ_INVALID_HANDLE;

    (void)util_rwlock_rdlock(g_umq_ub_queue_ctx_list.lock);
    URPC_LIST_FOR_EACH(local, qctx_node, &g_umq_ub_queue_ctx_list.queue_list) {
        if (local->jetty[UB_QUEUE_JETTY_IO] == urma_event->element.jetty || (local->flow_control.enabled &&
            local->jetty[UB_QUEUE_JETTY_FLOW_CONTROL] == urma_event->element.jetty)) {
            find = true;
            umq_event->element.umqh = local->umqh;
            break;
        }
    }
    (void)util_rwlock_unlock(g_umq_ub_queue_ctx_list.lock);

    if (!find) {
        UMQ_VLOG_WARN(VLOG_UMQ_URMA_AE, "find jetty id %u in all umq failed\n",
            urma_event->element.jetty->jetty_id.id);
    } else {
        UMQ_VLOG_INFO(VLOG_UMQ_URMA_AE, "find jetty id %u success, urma event_type %d, umq event_type %d\n",
            urma_event->element.jetty->jetty_id.id, urma_event->event_type, umq_event->event_type);
    }
}

void handle_async_event_jetty_limit(urma_async_event_t *urma_event, umq_async_event_t *umq_event)
{
    bool find = false;
    ub_queue_t *local = NULL;
    umq_event->event_type = UMQ_EVENT_QH_LIMIT;
    umq_event->element.umqh = UMQ_INVALID_HANDLE;

    (void)util_rwlock_rdlock(g_umq_ub_queue_ctx_list.lock);
    URPC_LIST_FOR_EACH(local, qctx_node, &g_umq_ub_queue_ctx_list.queue_list) {
        if (local->jetty[UB_QUEUE_JETTY_IO] == urma_event->element.jetty || (local->flow_control.enabled &&
            local->jetty[UB_QUEUE_JETTY_FLOW_CONTROL] == urma_event->element.jetty)) {
            find = true;
            umq_event->element.umqh = local->umqh;
            break;
        }
    }
    (void)util_rwlock_unlock(g_umq_ub_queue_ctx_list.lock);

    if (!find) {
        UMQ_VLOG_WARN(VLOG_UMQ_URMA_AE, "find jetty id %u in all umq failed\n",
            urma_event->element.jetty->jetty_id.id);
    } else {
        UMQ_VLOG_INFO(VLOG_UMQ_URMA_AE, "find jetty id %u success, urma event_type %d, umq event_type %d\n",
            urma_event->element.jetty->jetty_id.id, urma_event->event_type, umq_event->event_type);
    }
}

int umq_ub_queue_ctx_list_init(void)
{
    urpc_list_init(&g_umq_ub_queue_ctx_list.queue_list);
    g_umq_ub_queue_ctx_list.lock = util_rwlock_create();
    if (g_umq_ub_queue_ctx_list.lock == NULL) {
        UMQ_VLOG_ERR(VLOG_UMQ, "ub queue ctx list lock create failed\n");
        return -UMQ_ERR_ENOMEM;
    }
    return UMQ_SUCCESS;
}

void umq_ub_queue_ctx_list_uninit(void)
{
    ub_queue_t *cur_node, *next_node;
    URPC_LIST_FOR_EACH_SAFE(cur_node, next_node, qctx_node, &g_umq_ub_queue_ctx_list.queue_list) {
        urpc_list_remove(&cur_node->qctx_node);
    }
    (void)util_rwlock_destroy(g_umq_ub_queue_ctx_list.lock);
    g_umq_ub_queue_ctx_list.lock = NULL;
}

void umq_ub_queue_ctx_list_push(urpc_list_t *qctx_node)
{
    (void)util_rwlock_wrlock(g_umq_ub_queue_ctx_list.lock);
    urpc_list_push_back(&g_umq_ub_queue_ctx_list.queue_list, qctx_node);
    (void)util_rwlock_unlock(g_umq_ub_queue_ctx_list.lock);
}

void umq_ub_queue_ctx_list_remove(urpc_list_t *qctx_node)
{
    (void)util_rwlock_wrlock(g_umq_ub_queue_ctx_list.lock);
    urpc_list_remove(qctx_node);
    (void)util_rwlock_unlock(g_umq_ub_queue_ctx_list.lock);
}

int umq_ub_id_allocator_init(void)
{
    return util_id_allocator_init(&g_umq_ub_id_allocator, UMQ_MAX_MSG_ID_NUM, 1);
}

void umq_ub_id_allocator_uninit(void)
{
    util_id_allocator_uninit(&g_umq_ub_id_allocator);
}

util_id_allocator_t *umq_ub_id_allocator_get(void)
{
    return &g_umq_ub_id_allocator;
}

static uint32_t umq_read_alloc_mem_size(umq_size_interval_t size_interval)
{
    if (size_interval >= UMQ_SIZE_INTERVAL_MAX || size_interval < 0) {
        UMQ_LIMIT_VLOG_ERR(VLOG_UMQ, "size_interval: %d is invalid\n", size_interval);
        return UINT32_MAX;
    }
    if (size_interval == UMQ_SIZE_0K_SMALL_INTERVAL) {
        return umq_buf_size_small();
    }
    return umq_huge_qbuf_get_size_by_type(size_interval - 1);
}

static ALWAYS_INLINE uint32_t umq_ub_get_read_pre_allocate_max_total_size(
    umq_size_interval_t size_interval, uint16_t buf_num)
{
    uint32_t read_alloc_mem_size = umq_read_alloc_mem_size(size_interval);
    if (read_alloc_mem_size == UINT32_MAX) {
        return UINT32_MAX;
    }

    umq_buf_mode_t buf_mode = umq_qbuf_mode_get();
    uint64_t temp_size = read_alloc_mem_size * buf_num;
    if (temp_size >= UINT32_MAX || temp_size < umq_qbuf_headroom_get()) {
        return UINT32_MAX;
    }
    if (buf_mode == UMQ_BUF_SPLIT) {
        return temp_size - umq_qbuf_headroom_get();
    } else if (buf_mode == UMQ_BUF_COMBINE) {
        return temp_size - sizeof(umq_buf_t) * buf_num - umq_qbuf_headroom_get();
    }

    UMQ_LIMIT_VLOG_ERR(VLOG_UMQ, "buf mode: %d is invalid\n", buf_mode);
    return UINT32_MAX;
}

umq_buf_t *umq_ub_read_ctx_create(ub_queue_t *queue, umq_imm_head_t *umq_imm_head, uint16_t buf_num, uint16_t msg_id)
{
    umq_buf_t *ctx_buf = umq_buf_alloc(sizeof(user_ctx_t), 1, UMQ_INVALID_HANDLE, NULL);
    urma_eid_t *eid = &queue->jetty[UB_QUEUE_JETTY_IO]->jetty_id.eid;
    uint32_t id = queue->jetty[UB_QUEUE_JETTY_IO]->jetty_id.id;
    if (ctx_buf == NULL) {
        UMQ_LIMIT_VLOG_ERR(VLOG_UMQ, "eid: " EID_FMT ", jetty_id: %u, ctx_buf malloc failed\n", EID_ARGS(*eid), id);
        return NULL;
    }
    umq_buf_pro_t *buf_pro = (umq_buf_pro_t *)ctx_buf->qbuf_ext;
    umq_ub_imm_t imm_temp = {.ub_plus = {.type = IMM_TYPE_REVERSE_PULL_MEM_DONE}};
    buf_pro->imm_data = imm_temp.value;
    user_ctx_t *user_ctx = (user_ctx_t *)ctx_buf->buf_data;

    uint32_t total_size = umq_ub_get_read_pre_allocate_max_total_size(umq_imm_head->mem_interval, buf_num);
    if (total_size == UINT32_MAX) {
        umq_buf_free(ctx_buf);
        UMQ_LIMIT_VLOG_ERR(VLOG_UMQ, "eid: " EID_FMT ", jetty_id: %u, get total data size failed\n",
            EID_ARGS(*eid), id);
        return NULL;
    }

    user_ctx->dst_buf = umq_buf_alloc(total_size, 1, UMQ_INVALID_HANDLE, NULL);
    if (user_ctx->dst_buf == NULL) {
        umq_buf_free(ctx_buf);
        UMQ_LIMIT_VLOG_ERR(VLOG_UMQ, "eid: " EID_FMT ", jetty_id: %u, dst_buf malloc failed\n", EID_ARGS(*eid), id);
        return NULL;
    }

    user_ctx->wr_total = buf_num;
    user_ctx->msg_id = msg_id;
    user_ctx->wr_cnt = 0;
    return ctx_buf;
}

static ALWAYS_INLINE int umq_ub_import_mem_done(ub_queue_t *queue, uint16_t mempool_id)
{
    umq_ub_imm_t imm = { .mem_import ={.type = IMM_TYPE_MEM_IMPORT_DONE, .mempool_id = mempool_id} };
    uint16_t max_tx = umq_ub_window_dec(&queue->flow_control, queue, 1);
    if (max_tx == 0) {
        UMQ_LIMIT_VLOG_ERR(VLOG_UMQ, "eid: " EID_FMT ", jetty_id: %u, flow control window lack\n",
            EID_ARGS(queue->jetty[UB_QUEUE_JETTY_IO]->jetty_id.eid),
            queue->jetty[UB_QUEUE_JETTY_IO]->jetty_id.id);
        return -UMQ_ERR_EAGAIN;
    }
    int ret = umq_ub_write_imm((uint64_t)(uintptr_t)queue, queue->bind_ctx->remote_notify_addr, 1, imm.value);
    if (ret != UMQ_SUCCESS) {
        umq_ub_window_inc(&queue->flow_control, max_tx);
    }
    return ret;
}

static ALWAYS_INLINE void umq_ub_return_import_result(ub_queue_t *queue, uint16_t mempool_id, bool send_ack)
{
    urma_eid_t *eid = &queue->jetty[UB_QUEUE_JETTY_IO]->jetty_id.eid;
    uint32_t id = queue->jetty[UB_QUEUE_JETTY_IO]->jetty_id.id;
    if (send_ack) {
        if (umq_ub_import_mem_done(queue, mempool_id) != UMQ_SUCCESS) {
            // send import mem done failed not cause the data plane to be unavailable
            UMQ_LIMIT_VLOG_WARN(VLOG_UMQ, "eid: " EID_FMT ", jetty_id: %u, send import mem done imm failed",
                EID_ARGS(*eid), id);
        }
        return;
    }
    (void)util_rwlock_wrlock(queue->wait_ack_import.lock);
    if (queue->wait_ack_import.wait_ack_idx != UMQ_MAX_TSEG_NUM) {
        if (queue->wait_ack_import.wait_ack_pool_id == NULL) {
            queue->wait_ack_import.wait_ack_pool_id = (uint16_t *)(uintptr_t)calloc(UMQ_MAX_TSEG_NUM, sizeof(uint16_t));
            if (queue->wait_ack_import.wait_ack_pool_id == NULL) {
                (void)util_rwlock_unlock(queue->wait_ack_import.lock);
                UMQ_LIMIT_VLOG_WARN(VLOG_UMQ, "eid: " EID_FMT ", jetty_id: %u, calloc wait ack pool id failed",
                    EID_ARGS(*eid), id);
                return;
            }
        }
        queue->wait_ack_import.wait_ack_pool_id[queue->wait_ack_import.wait_ack_idx++] = mempool_id;
        (void)util_rwlock_unlock(queue->wait_ack_import.lock);
    } else {
        (void)util_rwlock_unlock(queue->wait_ack_import.lock);
        UMQ_LIMIT_VLOG_WARN(VLOG_UMQ, "eid: " EID_FMT ", jetty_id: %u, wait ack import table is full",
            EID_ARGS(*eid), id);
    }
}

// The rx buf contains metadata including the IMM header, reference SGE and import memory details.
int umq_ub_data_plan_import_mem(uint64_t umqh_tp, umq_buf_t *rx_buf, uint32_t ref_seg_num, bool send_ack)
{
    umq_imm_head_t *umq_imm_head = (umq_imm_head_t *)rx_buf->buf_data;
    if (umq_imm_head->type == IMM_PROTOCAL_TYPE_NONE) {
        return UMQ_SUCCESS;
    }

    size_t temp_size = sizeof(umq_imm_head_t) + ref_seg_num * sizeof(ub_ref_sge_t);
    if (umq_imm_head->mempool_num >= UMQ_MAX_TSEG_NUM) {
        UMQ_LIMIT_VLOG_INFO(VLOG_UMQ, "mempool num invalid, mempool_num %u\n", umq_imm_head->mempool_num);
        return -UMQ_ERR_EINVAL;
    }

    if (rx_buf->data_size < (uint32_t)(temp_size + umq_imm_head->mempool_num * sizeof(ub_import_mempool_info_t))) {
        UMQ_LIMIT_VLOG_INFO(VLOG_UMQ, "rx_buf data size invalid, size %u\n", rx_buf->data_size);
        return -UMQ_ERR_EINVAL;
    }
    ub_queue_t *queue = (ub_queue_t *)(uintptr_t)umqh_tp;
    if (queue == NULL) {
        UMQ_LIMIT_VLOG_INFO(VLOG_UMQ, "umq has been destroy\n");
        return -UMQ_ERR_EINVAL;
    }

    urma_eid_t *eid = &queue->jetty[UB_QUEUE_JETTY_IO]->jetty_id.eid;
    uint32_t id = queue->jetty[UB_QUEUE_JETTY_IO]->jetty_id.id;
    if (queue->bind_ctx == NULL) {
        UMQ_LIMIT_VLOG_INFO(VLOG_UMQ, "eid: " EID_FMT ", jetty_id: %u, the queue has been unbind\n",
            EID_ARGS(*eid), id);
        return -UMQ_ERR_EINVAL;
    }

    util_external_mutex_lock *imported_tseg_list_mutex_lock =
        queue->dev_ctx->remote_imported_info->imported_tseg_list_mutex[queue->bind_ctx->remote_eid_id];
    (void)util_mutex_lock(imported_tseg_list_mutex_lock);
    ub_import_mempool_info_t *import_mempool_info = (ub_import_mempool_info_t *)(rx_buf->buf_data + temp_size);
    for (uint32_t i = 0; i < umq_imm_head->mempool_num; i++) {
        if (import_mempool_info[i].mempool_id >= UMQ_MAX_TSEG_NUM) {
            (void)util_mutex_unlock(imported_tseg_list_mutex_lock);
            UMQ_LIMIT_VLOG_INFO(VLOG_UMQ, "eid: " EID_FMT ", jetty_id: %u, mempool id %u invalid\n", EID_ARGS(*eid),
                id, import_mempool_info[i].mempool_id);
            return -UMQ_ERR_EINVAL;
        }

        if (queue->imported_tseg_list[import_mempool_info[i].mempool_id] != NULL) {
            UMQ_LIMIT_VLOG_INFO(VLOG_UMQ, "eid: " EID_FMT ", jetty_id: %u, mempool %u has been imported\n",
                EID_ARGS(*eid), id, import_mempool_info[i].mempool_id);
            umq_ub_return_import_result(queue, import_mempool_info[i].mempool_id, send_ack);
            continue;
        }

        xchg_mem_info_t mem_info = {
            .seg_len = import_mempool_info[i].mempool_length,
            .seg_token_id = import_mempool_info[i].mempool_token_id,
            .seg_flag.value = import_mempool_info[i].mempool_seg_flag,
            .token.token = import_mempool_info[i].mempool_token_value
        };

        (void)memcpy(&mem_info.ubva, &import_mempool_info[i].mempool_ubva, sizeof(urma_ubva_t));
        urma_target_seg_t *imported_tseg = import_mem(queue->dev_ctx->urma_ctx, &mem_info);
        if (imported_tseg == NULL) {
            (void)util_mutex_unlock(imported_tseg_list_mutex_lock);
            UMQ_LIMIT_VLOG_ERR(VLOG_UMQ, "eid: " EID_FMT ", jetty_id: %u, import memory failed\n", EID_ARGS(*eid), id);
            return UMQ_FAIL;
        }

        umq_ub_return_import_result(queue, import_mempool_info[i].mempool_id, send_ack);
        queue->dev_ctx->remote_imported_info->
            imported_tseg_list[queue->bind_ctx->remote_eid_id][import_mempool_info[i].mempool_id] = imported_tseg;
    }
    (void)util_mutex_unlock(imported_tseg_list_mutex_lock);
    return UMQ_SUCCESS;
}

static ALWAYS_INLINE urma_status_t umq_ub_read_post_send(
    ub_queue_t *queue, urma_sge_t *src_sge, urma_sge_t *dst_sge, umq_buf_t *ctx_buf)
{
    urma_jfs_wr_t urma_wr = {.rw = {.src = {.sge = src_sge, .num_sge = 1},
        .dst = {.sge = dst_sge, .num_sge = 1}},
        .user_ctx = (uint64_t)(uintptr_t)ctx_buf,
        .opcode = URMA_OPC_READ,
        .flag = {.bs = {.complete_enable = 1, .inline_flag = 0}},
        .tjetty = queue->bind_ctx->tjetty[UB_QUEUE_JETTY_IO]};

    urma_jfs_wr_t *bad_wr = NULL;
    uint64_t start_timestamp = umq_perf_get_start_timestamp();
    urma_status_t status = umq_symbol_urma()->urma_post_jetty_send_wr(queue->jetty[UB_QUEUE_JETTY_IO],
        &urma_wr, &bad_wr);
    umq_perf_record_write(UMQ_PERF_RECORD_TRANSPORT_POST_SEND, start_timestamp);
    if (status == URMA_SUCCESS) {
        umq_ub_io_packet_stats(queue, UB_PACKET_STATS_TYPE_SEND, 1, queue->dev_ctx->io_lock_free);
    }
    return status;
}

static inline void umq_ub_read_ctx_destroy(umq_buf_t *ctx_buf)
{
    user_ctx_t *user_ctx = (user_ctx_t *)ctx_buf->buf_data;
    if (user_ctx->dst_buf != NULL) {
        umq_buf_free(user_ctx->dst_buf);
    }
    umq_buf_free(ctx_buf);
}

int umq_ub_read(uint64_t umqh_tp, umq_buf_t *rx_buf, umq_ub_imm_t imm)
{
    ub_queue_t *queue = (ub_queue_t *)(uintptr_t)umqh_tp;
    urma_eid_t *eid = &queue->jetty[UB_QUEUE_JETTY_IO]->jetty_id.eid;
    uint32_t id = queue->jetty[UB_QUEUE_JETTY_IO]->jetty_id.id;
    if (queue->bind_ctx == NULL) {
        UMQ_LIMIT_VLOG_ERR(VLOG_UMQ, "eid: " EID_FMT ", jetty_id: %u, umq has not been binded\n", EID_ARGS(*eid), id);
        return -UMQ_ERR_ENODEV;
    }

    uint16_t buf_num = imm.ub_plus.msg_num;
    uint16_t msg_id = imm.ub_plus.msg_id;
    umq_imm_head_t *umq_imm_head = (umq_imm_head_t *)(uintptr_t)rx_buf->buf_data;
    ub_ref_sge_t *ref_sge = (ub_ref_sge_t *)(uintptr_t)(umq_imm_head + 1);
    umq_buf_t *ctx_buf = umq_ub_read_ctx_create(queue, umq_imm_head, buf_num, msg_id);
    if (ctx_buf == NULL) {
        UMQ_LIMIT_VLOG_ERR(VLOG_UMQ, "eid: " EID_FMT ", jetty_id: %u, create ctx buf failed\n", EID_ARGS(*eid), id);
        return -UMQ_ERR_ENOMEM;
    }

    urma_target_seg_t **tseg_list = queue->dev_ctx->tseg_list;
    user_ctx_t *user_ctx = (user_ctx_t *)ctx_buf->buf_data;
    umq_buf_t *dst_buf = user_ctx->dst_buf;
    umq_buf_t *tmp_buf = dst_buf;
    urma_sge_t src_sge[buf_num];
    urma_sge_t dst_sge[buf_num];
    uint32_t total_data_size = 0;
    uint32_t buf_offset = 0;
    uint32_t src_buf_length = 0;
    for (uint32_t i = 0; i < buf_num; i++) {
        src_buf_length = ref_sge[i].length;
        if (ref_sge[i].mempool_id >= UMQ_MAX_TSEG_NUM) {
            UMQ_LIMIT_VLOG_ERR(VLOG_UMQ, "eid: " EID_FMT ", jetty_id: %u, mempool id: %u invalid\n",
                EID_ARGS(*eid), id, ref_sge[i].mempool_id);
            goto FREE_CTX_BUF;
        }
        // To read a whole qbuf at once, jump to the next tmp-buf instead of filling tm_buf.
        if (buf_offset + src_buf_length > tmp_buf->data_size) {
            tmp_buf->data_size = buf_offset;
            tmp_buf = QBUF_LIST_NEXT(tmp_buf);
            buf_offset = 0;
            if (tmp_buf == NULL || src_buf_length > tmp_buf->data_size) {
                UMQ_LIMIT_VLOG_ERR(VLOG_UMQ, "eid: " EID_FMT ", jetty_id: %u, tmp_buf or src_buf_length: %u invalid\n",
                    EID_ARGS(*eid), id, src_buf_length);
                goto FREE_CTX_BUF;
            }
        }
        dst_sge[i].addr = (uint64_t)(uintptr_t)(tmp_buf->buf_data + buf_offset);
        dst_sge[i].len = src_buf_length;
        dst_sge[i].user_tseg = NULL;
        dst_sge[i].tseg = tseg_list[tmp_buf->mempool_id];

        src_sge[i].addr = ref_sge[i].addr;
        src_sge[i].len = src_buf_length;
        src_sge[i].tseg = queue->imported_tseg_list[ref_sge[i].mempool_id];
        if (src_sge[i].tseg == NULL) {
            UMQ_LIMIT_VLOG_ERR(VLOG_UMQ, "eid: " EID_FMT ", jetty_id: %u, imported memory handle not exist\n",
                EID_ARGS(*eid), id);
            goto FREE_CTX_BUF;
        }
        buf_offset += src_buf_length;
        total_data_size += src_buf_length;

        urma_status_t status = umq_ub_read_post_send(queue, src_sge + i, dst_sge + i, ctx_buf);
        if (status != URMA_SUCCESS) {
            UMQ_LIMIT_VLOG_ERR(VLOG_UMQ_URMA_API, "local eid: " EID_FMT ", local jetty_id: %u, remote eid: " EID_FMT ""
                ", remote jetty_id: %u, urma_post_jetty_send_wr failed, status: %d\n", EID_ARGS(*eid), id,
                EID_ARGS(queue->bind_ctx->tjetty[UB_QUEUE_JETTY_IO]->id.eid),
                queue->bind_ctx->tjetty[UB_QUEUE_JETTY_IO]->id.id, (int)status);
            if (i == 0) {
                goto FREE_CTX_BUF;
            } else {
                return umq_status_convert(status);
            }
        }
    }
    tmp_buf->data_size = buf_offset;
    dst_buf->total_data_size = total_data_size;
    umq_inc_ref(queue->dev_ctx->io_lock_free, &queue->tx_outstanding, buf_num);
    return UMQ_SUCCESS;

FREE_CTX_BUF:
    umq_ub_read_ctx_destroy(ctx_buf);
    return UMQ_FAIL;
}

static int process_send_imm(umq_buf_t *rx_buf, umq_ub_imm_t imm, uint64_t umqh)
{
    int ret = UMQ_SUCCESS;
    if (imm.bs.type == IMM_TYPE_USER) {
        umq_buf_pro_t *buf_pro = (umq_buf_pro_t *)rx_buf->qbuf_ext;
        buf_pro->imm_data = imm.value;
        return UMQ_SUCCESS;
    }

    if (imm.bs.type == IMM_TYPE_REVERSE_PULL_MEM) {
        if (umq_ub_data_plan_import_mem(umqh, rx_buf, imm.ub_plus.msg_num, true) != UMQ_SUCCESS) {
            UMQ_LIMIT_VLOG_ERR(VLOG_UMQ, "import mem failed\n");
            umq_buf_free(rx_buf); // release rx
            return UMQ_CONTINUE_FLAG;
        }

        ret = umq_ub_read(umqh, rx_buf, imm);
        if (ret != UMQ_SUCCESS) {
            UMQ_LIMIT_VLOG_ERR(VLOG_UMQ, "umq ub send read failed, status: %d\n", ret);
        }
        umq_buf_free(rx_buf); // release rx
        ret = UMQ_CONTINUE_FLAG;
    } else if (imm.bs.type == IMM_TYPE_REVERSE_PULL_MEM_FREE) {
        uint16_t msg_id = (uint16_t)(imm.ub_plus.msg_id);
        ub_queue_t *queue = (ub_queue_t *)(uintptr_t)umqh;
        if (msg_id != 0 && queue->addr_list != NULL) {
            umq_buf_t *buffer = umq_ub_queue_addr_list_remove(queue->addr_list, msg_id);
            /*
             * break qbuf list for many batches connected, only release the first batch,
             * can't break qbuf list when send, because all qbufs of 128 wr are connected,
             * and the address of the first qbuf is placed in the user_ctx of the 128th wr, then released
             */
            (void)umq_buf_break_and_free(buffer);
            util_id_allocator_release(&g_umq_ub_id_allocator, msg_id);
        }
        umq_buf_free(rx_buf); // release rx
        ret = UMQ_CONTINUE_FLAG;
    }
    return ret;
}

static int process_write_imm(umq_buf_t *rx_buf, umq_ub_imm_t imm, uint64_t umqh)
{
    int ret = UMQ_SUCCESS;
    if (imm.bs.type == IMM_TYPE_USER) {
        umq_buf_pro_t *buf_pro = (umq_buf_pro_t *)(uintptr_t)rx_buf->qbuf_ext;
        buf_pro->imm_data = imm.value;
    } else if (imm.bs.type == IMM_TYPE_MEM_IMPORT_DONE) {
        ub_queue_t *queue = (ub_queue_t *)(uintptr_t)umqh;
        if (imm.mem_import.mempool_id >= UMQ_MAX_TSEG_NUM) {
            UMQ_LIMIT_VLOG_ERR(VLOG_UMQ, "umq ub mempool_id: %u invalid\n", imm.mem_import.mempool_id);
        } else {
            queue->dev_ctx->remote_imported_info->
                tesg_imported[queue->bind_ctx->remote_eid_id][imm.mem_import.mempool_id] = true;
        }
        ret = UMQ_CONTINUE_FLAG;
        umq_buf_free(rx_buf);
    } else if (imm.bs.type == IMM_TYPE_NOTIFY) {
        ret = UMQ_CONTINUE_FLAG;
        umq_buf_free(rx_buf);
    }
    return ret;
}

static inline int process_imm_msg(uint64_t umqh_tp, umq_buf_t *buf, urma_cr_t *cr)
{
    umq_ub_imm_t imm = {.value = cr->imm_data};
    if (cr->opcode == URMA_CR_OPC_SEND_WITH_IMM) {
        return process_send_imm(buf, imm, umqh_tp);
    } else if (cr->opcode == URMA_CR_OPC_WRITE_WITH_IMM) {
        return process_write_imm(buf, imm, umqh_tp);
    }
    return UMQ_SUCCESS;
}

static int umq_ub_read_done(ub_queue_t *queue, uint16_t msg_id)
{
    umq_ub_imm_t imm = {.ub_plus = {.type = IMM_TYPE_REVERSE_PULL_MEM_FREE, .msg_id = msg_id}};

    urma_sge_t sge = {
        .tseg = queue->dev_ctx->tseg_list[UMQ_QBUF_DEFAULT_MEMPOOL_ID],
    };
    return umq_ub_send_imm(queue, imm.value, &sge, 0);
}

static void umq_ub_rev_pull_tx_cqe(
    ub_queue_t *queue, umq_buf_t *cur_tx_buf, umq_buf_t **buf, int *qbuf_cnt, int *return_rx_cnt)
{
    user_ctx_t *user_ctx = (user_ctx_t *)cur_tx_buf->buf_data;
    user_ctx->wr_cnt++;
    if (user_ctx->wr_cnt == user_ctx->wr_total) {
        int ret = umq_ub_read_done(queue, user_ctx->msg_id);
        if (ret != UMQ_SUCCESS) {
            UMQ_LIMIT_VLOG_ERR(VLOG_UMQ, "eid: " EID_FMT ", jetty_id: %u, umq ub send imm failed, status: %d\n",
                EID_ARGS(queue->jetty[UB_QUEUE_JETTY_IO]->jetty_id.eid), queue->jetty[UB_QUEUE_JETTY_IO]->jetty_id.id,
                ret);
        }
        umq_buf_t *tmp = cur_tx_buf;
        if (user_ctx->dst_buf) {
            cur_tx_buf = user_ctx->dst_buf;
            cur_tx_buf->io_direction = UMQ_IO_RX;
            if (*return_rx_cnt == 0) {
                buf[*return_rx_cnt] = cur_tx_buf;
            } else {
                buf[*return_rx_cnt] = cur_tx_buf;
                buf[*return_rx_cnt - 1]->qbuf_next = cur_tx_buf;
            }
            (*return_rx_cnt)++;
            ++(*qbuf_cnt);
        }
        umq_buf_free(tmp);
    }
}

static void umq_ub_non_rev_pull_tx_cqe(ub_queue_t *queue, umq_buf_t *cur_tx_buf, int *qbuf_cnt)
{
    (void)umq_buf_break_and_free(cur_tx_buf);
    ++(*qbuf_cnt);
}

int umq_ub_dequeue_plus_with_poll_tx(ub_queue_t *queue, urma_cr_t *cr, umq_buf_t **buf, int return_rx_cnt)
{
    umq_buf_t *tx_buf[UMQ_POST_POLL_BATCH];
    urma_eid_t *eid = &queue->jetty[UB_QUEUE_JETTY_IO]->jetty_id.eid;
    uint32_t id = queue->jetty[UB_QUEUE_JETTY_IO]->jetty_id.id;
    int tx_cr_cnt = umq_symbol_urma()->urma_poll_jfc(queue->jfs_jfc[UB_QUEUE_JETTY_IO], UMQ_POST_POLL_BATCH, cr);
    if (tx_cr_cnt < 0) {
        UMQ_LIMIT_VLOG_ERR(VLOG_UMQ_URMA_API, "eid: " EID_FMT ", jetty_id: %u, urma_poll_jfc reports tx_cr_cnt[%d]\n",
            EID_ARGS(*eid), id, tx_cr_cnt);
        return return_rx_cnt;
    }
    int qbuf_cnt = 0;
    uint32_t success_cnt = 0;
    uint32_t failed_cnt = 0;
    for (int i = 0; i < tx_cr_cnt; i++) {
        if (cr[i].status != URMA_CR_SUCCESS) {
            UMQ_LIMIT_VLOG_ERR(VLOG_UMQ_URMA_CQE, "eid: " EID_FMT ", jetty_id: %u, urma_poll_jfc reports tx cr[%d] "
                "status: %d\n", EID_ARGS(*eid), id, i, cr[i].status);
            if (cr[i].status == URMA_CR_WR_FLUSH_ERR_DONE) {
                if (queue->state == QUEUE_STATE_ERR) {
                    queue->tx_flush_done = true;
                }
                continue;
            }
            if (cr[i].status == URMA_CR_WR_SUSPEND_DONE) {
                continue;
            }
            failed_cnt++;
        } else {
            success_cnt++;
        }
        /* After the read operation is complete, send_imm request with user_ctx equal to 0 will be sent.
         * This tx_cqe request does't need to be reported. */
        if (cr[i].user_ctx == 0) {
            umq_dec_ref(queue->dev_ctx->io_lock_free, &queue->tx_outstanding, 1);
            continue;
        }
        umq_dec_ref(queue->dev_ctx->io_lock_free, &queue->tx_outstanding, 1);
        tx_buf[qbuf_cnt] = (umq_buf_t *)(uintptr_t)cr[i].user_ctx;
        umq_buf_pro_t *buf_pro = (umq_buf_pro_t *)(tx_buf[qbuf_cnt])->qbuf_ext;
        umq_ub_imm_t imm = {.value = buf_pro->imm_data};
        if (imm.bs.type == IMM_TYPE_REVERSE_PULL_MEM_DONE) {
            umq_ub_rev_pull_tx_cqe(queue, tx_buf[qbuf_cnt], buf, &qbuf_cnt, &return_rx_cnt);
            continue;
        }
        umq_ub_non_rev_pull_tx_cqe(queue, tx_buf[qbuf_cnt], &qbuf_cnt);
    }

    if (success_cnt > 0) {
        umq_ub_io_packet_stats(queue, UB_PACKET_STATS_TYPE_SEND_SUCCESS, success_cnt, queue->dev_ctx->io_lock_free);
    }

    if (failed_cnt > 0) {
        umq_ub_io_packet_stats(queue, UB_PACKET_STATS_TYPE_SEND_ERROR, failed_cnt, queue->dev_ctx->io_lock_free);
    }

    return return_rx_cnt;
}

static uint32_t get_mem_interval(uint32_t used_mem_size)
{
    uint32_t i = 0;
    uint32_t buf_size;

    if (used_mem_size <= umq_buf_size_small()) {
        return i;
    }

    for (i = UMQ_SIZE_SMALL_MID_INTERVAL; i < UMQ_SIZE_INTERVAL_MAX; i++) {
        buf_size = umq_huge_qbuf_get_size_by_type(i - 1);
        if (used_mem_size <= buf_size) {
            break;
        }
    }
    if (i == UMQ_SIZE_INTERVAL_MAX) {
        return i - 1;
    }
    return i;
}

void ub_fill_umq_imm_head(umq_imm_head_t *umq_imm_head, umq_buf_t *buffer)
{
    umq_imm_head->version = UMQ_IMM_VERSION;
    umq_imm_head->type = IMM_PROTOCAL_TYPE_NONE;
    umq_imm_head->mempool_num = 0;
    umq_imm_head->mem_interval = get_mem_interval(buffer->data_size);
}

int fill_big_data_ref_sge(ub_queue_t *queue, ub_ref_sge_t *ref_sge, umq_buf_t *buffer, mempool_info_ctx_t *ctx)
{
    if (buffer->mempool_id >= UMQ_MAX_TSEG_NUM) {
        UMQ_LIMIT_VLOG_ERR(VLOG_UMQ, "the buf mempool id [%u] invalid\n", buffer->mempool_id);
        return UMQ_FAIL;
    }
    urma_target_seg_t *tseg = queue->dev_ctx->tseg_list[buffer->mempool_id];
    urma_seg_t *seg = &tseg->seg;
    if (!queue->dev_ctx->remote_imported_info->tesg_imported[queue->bind_ctx->remote_eid_id][buffer->mempool_id] &&
        !ctx->mempool_info_record[buffer->mempool_id]) {
        ub_import_mempool_info_t *import_mempool_info = ctx->import_mempool_info;
        ctx->umq_imm_head->type = IMM_PROTOCAL_TYPE_IMPORT_MEM;
        ctx->umq_imm_head->mempool_num++;
        import_mempool_info->mempool_seg_flag = seg->attr.value;
        import_mempool_info->mempool_length = seg->len;
        import_mempool_info->mempool_token_id = seg->token_id;
        import_mempool_info->mempool_id = buffer->mempool_id;
        import_mempool_info->mempool_token_value = tseg->user_ctx;
        (void)memcpy(import_mempool_info->mempool_ubva, &seg->ubva, sizeof(urma_ubva_t));
        ctx->mempool_info_record[buffer->mempool_id] = true;
    }

    ref_sge->addr = (uint64_t)(uintptr_t)buffer->buf_data;
    ref_sge->length = buffer->data_size;
    ref_sge->token_id = seg->token_id;
    ref_sge->mempool_id = buffer->mempool_id;
    ref_sge->token_value = tseg->user_ctx;
    return UMQ_SUCCESS;
}

uint32_t umq_ub_ref_sge_cnt(umq_buf_t *buffer)
{
    uint32_t ref_sge_cnt = 0;
    umq_buf_t *tmp_buf = buffer;
    uint32_t rest_size = tmp_buf->total_data_size;
    while (tmp_buf != NULL && rest_size != 0) {
        if (rest_size < tmp_buf->data_size) {
            UMQ_LIMIT_VLOG_ERR(VLOG_UMQ, "remaining size[%u] is smaller than data_size[%u]\n",
                rest_size, tmp_buf->data_size);
            return 0;
        }
        rest_size -= tmp_buf->data_size;
        tmp_buf = tmp_buf->qbuf_next;
        ref_sge_cnt++;
    }
    return ref_sge_cnt;
}

static int umq_ub_send_big_data(ub_queue_t *queue, umq_buf_t **buffer)
{
    if (umq_ub_queue_addr_list_alloc(queue) != UMQ_SUCCESS) {
        return -UMQ_ERR_ENOMEM;
    }
    // apply for one to avoid memory leak
    urma_eid_t *eid = &queue->jetty[UB_QUEUE_JETTY_IO]->jetty_id.eid;
    uint32_t id = queue->jetty[UB_QUEUE_JETTY_IO]->jetty_id.id;
    umq_buf_t *send_buf = umq_buf_alloc(umq_buf_size_small(), UMQ_MAX_QBUF_NUM, UMQ_INVALID_HANDLE, NULL);
    if (send_buf == NULL) {
        UMQ_LIMIT_VLOG_ERR(VLOG_UMQ, "eid: " EID_FMT ", jetty_id: %u, umq malloc failed\n", EID_ARGS(*eid), id);
        return -UMQ_ERR_ENOMEM;
    }
    // In the tx direction, user_ctx needs to initialize imm data ub_plus type
    umq_buf_pro_t *buf_pro = (umq_buf_pro_t *)send_buf->qbuf_ext;
    umq_ub_imm_t imm_temp = {
        .ub_plus = {.type = IMM_TYPE_UB_PLUS_DEFAULT}
    };
    buf_pro->imm_data = imm_temp.value;
    uint16_t msg_id = util_id_allocator_get(&g_umq_ub_id_allocator);
    umq_ub_queue_addr_list_record(queue->addr_list, msg_id, *buffer);

    umq_imm_head_t *umq_imm_head = (umq_imm_head_t *)(uintptr_t)send_buf->buf_data;
    ub_fill_umq_imm_head(umq_imm_head, *buffer);

    ub_ref_sge_t *ref_sge = (ub_ref_sge_t *)(uintptr_t)(umq_imm_head + 1);
    uint32_t ref_sge_cnt = umq_ub_ref_sge_cnt(*buffer);
    if (ref_sge_cnt == 0) {
        UMQ_LIMIT_VLOG_ERR(VLOG_UMQ, "eid: " EID_FMT ", jetty_id: %u, get ref sge cnt failed\n", EID_ARGS(*eid), id);
        goto FREE_BUF;
    }

    uint32_t ref_sge_size = ref_sge_cnt * sizeof(ub_ref_sge_t);
    if (ref_sge_size + (uint32_t)sizeof(umq_imm_head_t) > umq_buf_size_small()) {
        UMQ_LIMIT_VLOG_ERR(VLOG_UMQ, "eid: " EID_FMT ", jetty_id: %u, the buf num [%d] exceeds the maximum limit\n",
            EID_ARGS(*eid), id, ref_sge_cnt);
        goto FREE_BUF;
    }

    uint32_t mempool_info_size = umq_buf_size_small() - ref_sge_size - (uint32_t)sizeof(umq_imm_head_t);
    ub_import_mempool_info_t *import_mempool_info = (ub_import_mempool_info_t *)(uintptr_t)(send_buf->buf_data +
        (uint32_t)sizeof(umq_imm_head_t) + ref_sge_cnt * (uint32_t)sizeof(ub_ref_sge_t));

    uint32_t rest_size = (*buffer)->total_data_size;
    uint32_t buf_index = 0;
    urma_sge_t sge;
    uint32_t max_data_size = 0;
    mempool_info_ctx_t mempool_info_ctx = {
        .umq_imm_head = umq_imm_head,
    };
    while ((*buffer) && rest_size != 0) {
        if (mempool_info_size < (umq_imm_head->mempool_num * sizeof(ub_import_mempool_info_t))) {
            UMQ_LIMIT_VLOG_ERR(VLOG_UMQ, "eid: " EID_FMT ", jetty_id: %u, the buf num [%d] mempool info num [%u] "
                "exceeds the maximum limit [%u]\n", EID_ARGS(*eid), id, ref_sge_cnt, umq_imm_head->mempool_num);
            goto FREE_BUF;
        }

        mempool_info_ctx.import_mempool_info = &import_mempool_info[umq_imm_head->mempool_num];
        if (fill_big_data_ref_sge(queue, &ref_sge[buf_index], *buffer, &mempool_info_ctx) != UMQ_SUCCESS) {
            goto FREE_BUF;
        }

        max_data_size =  (*buffer)->data_size > max_data_size ? (*buffer)->data_size : max_data_size;
        rest_size -= (*buffer)->data_size;
        (*buffer) = QBUF_LIST_NEXT((*buffer));
        ++buf_index;
    }
    if (buf_index >= UMQ_MAX_MSG_ID_NUM) {
        UMQ_LIMIT_VLOG_ERR(VLOG_UMQ, "eid: " EID_FMT ", jetty_id: %u, the buf index [%d] "
            "exceeds the maximum limit\n", EID_ARGS(*eid), id, buf_index);
    }
    umq_imm_head->mem_interval = get_mem_interval(max_data_size);

    uint64_t user_ctx = (uint64_t)(uintptr_t)send_buf;
    sge.addr = (uint64_t)(uintptr_t)send_buf->buf_data;
    sge.len = sizeof(umq_imm_head_t) +
        buf_index * sizeof(ub_ref_sge_t) + umq_imm_head->mempool_num * sizeof(ub_import_mempool_info_t);
    sge.tseg = queue->dev_ctx->tseg_list[send_buf->mempool_id];
    umq_ub_imm_t imm = {.ub_plus = {.type = IMM_TYPE_REVERSE_PULL_MEM,
                                    .msg_id = msg_id,
                                    .msg_num = (uint16_t)buf_index}};
    int ret = umq_ub_send_imm(queue, imm.value, &sge, user_ctx);
    if (ret != UMQ_SUCCESS) {
        umq_buf_free(send_buf);
        UMQ_LIMIT_VLOG_ERR(VLOG_UMQ, "eid: " EID_FMT ", jetty_id: %u, umq_ub_send_imm failed, status: %d\n",
            EID_ARGS(*eid), id, ret);
        return ret;
    }
    return UMQ_SUCCESS;

FREE_BUF:
    umq_buf_free(send_buf);
    return UMQ_FAIL;
}

int umq_ub_plus_fill_wr_impl(umq_buf_t *qbuf, ub_queue_t *queue, urma_jfs_wr_t *urma_wr_ptr,
                             urma_sge_t *sges, uint32_t remain_tx)
{
    uint32_t max_sge_num = queue->max_tx_sge;
    urma_target_jetty_t *tjetty = queue->bind_ctx->tjetty[UB_QUEUE_JETTY_IO];
    urma_sge_t *sges_ptr;
    umq_buf_t *buffer = qbuf;
    uint32_t wr_index = 0;
    uint32_t sge_index = 0;
    urma_target_seg_t **tseg_list = queue->dev_ctx->tseg_list;
    uint32_t remote_rx_buf_size = queue->remote_rx_buf_size;
    uint32_t sge_num = 0;
    urma_eid_t *eid = &queue->jetty[UB_QUEUE_JETTY_IO]->jetty_id.eid;
    uint32_t id = queue->jetty[UB_QUEUE_JETTY_IO]->jetty_id.id;

    while (buffer != NULL) {
        umq_buf_pro_t *buf_pro = (umq_buf_pro_t *)buffer->qbuf_ext;
        buf_pro->flag.value = 0;
        buf_pro->flag.bs.complete_enable = 1;
        buf_pro->flag.bs.solicited_enable = 1;
        if (buffer->data_size < UMQ_ENABLE_INLINE_LIMIT_SIZE) {
            buf_pro->flag.bs.inline_flag = UMQ_INLINE_ENABLE;
        }
        buf_pro->opcode = UMQ_OPC_SEND_IMM;
        uint32_t rest_size = buffer->total_data_size;
        if (rest_size > remote_rx_buf_size) {
            int ret = umq_ub_send_big_data(queue, &buffer);
            if (ret != UMQ_SUCCESS) {
                UMQ_LIMIT_VLOG_ERR(VLOG_UMQ, "eid: " EID_FMT ", jetty_id: %u, send big data failed, status: %d\n",
                    EID_ARGS(*eid), id, ret);
                return ret;
            }
            if (buffer) {
                continue;
            } else if (buffer == NULL && wr_index != 0) {
                break;
            }
            return 0;
        }
        if (rest_size > queue->tx_buf_size) {
            UMQ_LIMIT_VLOG_ERR(VLOG_UMQ, "eid: " EID_FMT ", jetty_id: %u, total data size[%u] exceed "
                "max tx size[%u]\n", EID_ARGS(*eid), id, rest_size, queue->tx_buf_size);
            return -UMQ_ERR_EINVAL;
        }
        /* sges is defined as two-dimensional array, cast to a one-dimensional array for passing, and within the
         * `umq_ub_plus_fill_wr_impl`, it is assigned by jumping in groups of max_sge_num. */
        sge_index = wr_index * max_sge_num;
        sges_ptr = &sges[sge_index];
        sge_num = 0;
        uint64_t user_ctx = (uint64_t)(uintptr_t)buffer;
        while (buffer && rest_size > 0) { // try to add up to total_size
            if (sge_num++ >= max_sge_num) {
                UMQ_LIMIT_VLOG_ERR(VLOG_UMQ, "eid: " EID_FMT ", jetty_id: %u, sge num exceed max sge num[%u]\n",
                    EID_ARGS(*eid), id, max_sge_num);
                return -UMQ_ERR_EINVAL;
            }
            sges_ptr->addr = (uint64_t)(uintptr_t)buffer->buf_data;
            sges_ptr->len = buffer->data_size;
            sges_ptr->user_tseg = NULL;
            sges_ptr->tseg = tseg_list[buffer->mempool_id];
            sges_ptr++;

            if (rest_size < buffer->data_size) { // if cannot add up to total_size, return fail
                UMQ_LIMIT_VLOG_ERR(VLOG_UMQ, "eid: " EID_FMT ", jetty_id: %u, cannot put together tx buffer, rest size"
                    " is negative\n", EID_ARGS(*eid), id);
                return -UMQ_ERR_EINVAL;
            }

            rest_size -= buffer->data_size;
            buffer = QBUF_LIST_NEXT(buffer);
        }
        if (rest_size != 0) { // if cannot add up to total_size, return fail
            UMQ_LIMIT_VLOG_ERR(VLOG_UMQ, "eid: " EID_FMT ", jetty_id: %u, cannot put together enough tx buffer\n",
                EID_ARGS(*eid), id);
            return -UMQ_ERR_ENOMEM;
        }

        urma_wr_ptr->user_ctx = user_ctx;
        urma_wr_ptr->send.src.sge = &sges[sge_index];
        urma_wr_ptr->send.src.num_sge = sge_num;
        urma_wr_ptr->send.imm_data = buf_pro->imm_data;
        urma_wr_ptr->opcode = URMA_OPC_SEND_IMM;
        urma_wr_ptr->flag.value = buf_pro->flag.value;
        urma_wr_ptr->tjetty = tjetty;
        urma_wr_ptr++;
        (urma_wr_ptr - 1)->next = urma_wr_ptr;
        wr_index++;
        if ((wr_index == remain_tx || wr_index == UMQ_POST_POLL_BATCH) && buffer != NULL) {
            // wr count exceed remain_tx or UMQ_POST_POLL_BATCH
            UMQ_LIMIT_VLOG_ERR(VLOG_UMQ, "eid: " EID_FMT ", jetty_id: %u, wr count %u exceeds remain_tx %u or "
                "max_post_size %d, not supported\n", EID_ARGS(*eid), id, wr_index, remain_tx, UMQ_POST_POLL_BATCH);
            return -UMQ_ERR_EINVAL;
        }
    }
    (urma_wr_ptr - 1)->next = NULL;
    return wr_index;
}

static void umq_ub_merge_rx_buffer(umq_buf_t *cur_buf, umq_buf_t **previous_last)
{
    umq_buf_t *tmp_buf = cur_buf;
    if (*previous_last != NULL) {
        (*previous_last)->qbuf_next = tmp_buf;
    }
    uint32_t rest_data_size = tmp_buf->total_data_size;
    while (tmp_buf && rest_data_size > 0) {
        if (rest_data_size <= tmp_buf->data_size) {
            tmp_buf->qbuf_next = NULL;
            *previous_last = tmp_buf;
            break;
        }
        rest_data_size -= tmp_buf->data_size;
        tmp_buf = tmp_buf->qbuf_next;
    }
}

static int umq_report_incomplete_and_merge_rx(
    ub_queue_t *queue, int max_rx_ctx, umq_buf_t **buf, umq_buf_t **previous_last)
{
    int buf_cnt = 0;
    if (!queue->tx_flush_done || queue->rx_flush_done || queue->state != QUEUE_STATE_ERR) {
        return buf_cnt;
    }
    rx_buf_ctx_t *rx_buf_ctx;
    for (; buf_cnt < max_rx_ctx; buf_cnt++) {
        rx_buf_ctx = queue_rx_buf_ctx_flush(&queue->jfr_ctx[UB_QUEUE_JETTY_IO]->rx_buf_ctx_list);
        if (rx_buf_ctx == NULL) {
            break;
        }
        buf[buf_cnt] = rx_buf_ctx->buffer;
        buf[buf_cnt]->buf_data = 0;
        buf[buf_cnt]->io_direction = UMQ_IO_RX;
        buf[buf_cnt]->status = UMQ_BUF_WR_FLUSH_ERR;
        umq_ub_merge_rx_buffer(buf[buf_cnt], previous_last);
    }

    if (buf_cnt == 0) {
        queue->rx_flush_done = true;
    }
    return buf_cnt;
}

void umq_ub_fill_rx_buffer(ub_queue_t *queue, int rx_cnt)
{
    __atomic_fetch_add(&queue->require_rx_count, rx_cnt, __ATOMIC_RELAXED);
    uint32_t require_rx_count = umq_get_post_rx_num(queue->rx_depth, &queue->require_rx_count);
    if (require_rx_count > 0) {
        uint32_t cur_batch_count = 0;
        int ret = UMQ_SUCCESS;
        urma_eid_t *eid = &queue->jetty[UB_QUEUE_JETTY_IO]->jetty_id.eid;
        uint32_t id = queue->jetty[UB_QUEUE_JETTY_IO]->jetty_id.id;
        do {
            cur_batch_count = require_rx_count > UMQ_POST_POLL_BATCH ? UMQ_POST_POLL_BATCH : require_rx_count;
            umq_buf_t *qbuf = umq_buf_alloc(queue->rx_buf_size, cur_batch_count, UMQ_INVALID_HANDLE, NULL);
            if (qbuf == NULL) {
                __atomic_fetch_add(&queue->require_rx_count, cur_batch_count, __ATOMIC_RELAXED);
                UMQ_LIMIT_VLOG_ERR(VLOG_UMQ, "eid: " EID_FMT ", jetty_id: %u, alloc rx failed\n", EID_ARGS(*eid), id);
                break;
            }
            umq_buf_t *bad_buf = NULL;
            ret = umq_ub_post_rx_inner_impl(queue, qbuf, &bad_buf);
            if (ret != UMQ_SUCCESS) {
                UMQ_LIMIT_VLOG_ERR(VLOG_UMQ, "eid: " EID_FMT ", jetty_id: %u, post rx failed, status: %d\n",
                    EID_ARGS(*eid), id, ret);
                uint32_t fail_count = 0;
                umq_buf_t *tmp_buf = bad_buf;
                while (tmp_buf) {
                    fail_count++;
                    tmp_buf = tmp_buf->qbuf_next;
                }
                umq_buf_free(bad_buf);
                __atomic_fetch_add(&queue->require_rx_count, fail_count, __ATOMIC_RELAXED);
                break;
            }
            require_rx_count -= cur_batch_count;
        } while (require_rx_count > 0);
    }
}

int umq_ub_dequeue_with_poll_rx(ub_queue_t *queue, urma_cr_t *cr, umq_buf_t **buf)
{
    int qbuf_cnt = 0;
    // merge rx buffer
    umq_buf_t *previous_last = NULL;
    if (queue->state == QUEUE_STATE_ERR) {
        return umq_report_incomplete_and_merge_rx(queue, UMQ_POST_POLL_BATCH, buf, &previous_last);
    }

    int rx_cr_cnt = umq_symbol_urma()->urma_poll_jfc(queue->jfr_ctx[UB_QUEUE_JETTY_IO]->jfr_jfc, UMQ_POST_POLL_BATCH, cr);
    if (rx_cr_cnt < 0) {
        UMQ_LIMIT_VLOG_ERR(VLOG_UMQ_URMA_API, "eid: " EID_FMT ", jetty_id: %u, urma_poll_jfc reports rx_cr_cnt[%d]\n",
            EID_ARGS(queue->jetty[UB_QUEUE_JETTY_IO]->jetty_id.eid), queue->jetty[UB_QUEUE_JETTY_IO]->jetty_id.id,
            rx_cr_cnt);
        return rx_cr_cnt;
    }

    uint32_t success_cnt = 0;
    for (int i = 0; i < rx_cr_cnt; i++) {
        buf[i] = umq_get_buf_by_user_ctx(queue, cr[i].user_ctx, UB_QUEUE_JETTY_IO);
        buf[i]->io_direction = UMQ_IO_RX;
        buf[i]->status = (umq_buf_status_t)cr[i].status;
        if (cr[i].status != URMA_CR_SUCCESS) {
            umq_ub_io_packet_stats(queue, UB_PACKET_STATS_TYPE_RECV_ERROR, 1, queue->dev_ctx->io_lock_free);
            UMQ_LIMIT_VLOG_ERR(VLOG_UMQ_URMA_CQE, "eid: " EID_FMT ", jetty_id: %u, urma_poll_jfc reports rx cr[%d] "
                "status: %d\n", EID_ARGS(queue->jetty[UB_QUEUE_JETTY_IO]->jetty_id.eid),
                queue->jetty[UB_QUEUE_JETTY_IO]->jetty_id.id, i, cr[i].status);
        } else {
            umq_buf_t *tmp_buf = buf[i];
            uint32_t total_data_size = cr[i].completion_len;
            tmp_buf->total_data_size = total_data_size;
            while (tmp_buf != NULL && total_data_size > 0) {
                tmp_buf->data_size = total_data_size > tmp_buf->data_size ? tmp_buf->data_size : total_data_size;
                total_data_size -= tmp_buf->data_size;
                tmp_buf = tmp_buf->qbuf_next;
            }
            success_cnt++;
        }
        umq_ub_merge_rx_buffer(buf[i], &previous_last);
        qbuf_cnt++;
    }

    if (qbuf_cnt > 0) {
        umq_ub_io_packet_stats(queue, UB_PACKET_STATS_TYPE_RECV, success_cnt, queue->dev_ctx->io_lock_free);
    }

    return qbuf_cnt;
}

int umq_ub_dequeue_plus_with_poll_rx(uint64_t umqh_tp, urma_cr_t *cr, umq_buf_t **buf)
{
    ub_queue_t *queue = (ub_queue_t *)(uintptr_t)umqh_tp;
    // merge rx buffer
    umq_buf_t *previous_last = NULL;
    if (queue->state == QUEUE_STATE_ERR) {
        return umq_report_incomplete_and_merge_rx(queue, UMQ_POST_POLL_BATCH, buf, &previous_last);
    }

    int qbuf_cnt = 0;
    urma_eid_t *eid = &queue->jetty[UB_QUEUE_JETTY_IO]->jetty_id.eid;
    uint32_t id = queue->jetty[UB_QUEUE_JETTY_IO]->jetty_id.id;
    int rx_cr_cnt = umq_symbol_urma()->urma_poll_jfc(queue->jfr_ctx[UB_QUEUE_JETTY_IO]->jfr_jfc, UMQ_POST_POLL_BATCH, cr);
    if (rx_cr_cnt < 0) {
        UMQ_LIMIT_VLOG_ERR(VLOG_UMQ_URMA_API, "eid: " EID_FMT ", jetty_id: %u, urma_poll_jfc reports rx_cr_cnt[%d]\n",
            EID_ARGS(*eid), id, rx_cr_cnt);
        return rx_cr_cnt;
    }

    uint32_t success_cnt = 0;
    for (int i = 0; i < rx_cr_cnt; i++) {
        buf[qbuf_cnt] = umq_get_buf_by_user_ctx(queue, cr[i].user_ctx, UB_QUEUE_JETTY_IO);
        if (process_imm_msg(umqh_tp, buf[qbuf_cnt], cr + i) == UMQ_CONTINUE_FLAG) {
            continue;
        }
        buf[qbuf_cnt]->io_direction = UMQ_IO_RX;
        buf[qbuf_cnt]->status = (umq_buf_status_t)cr[i].status;
        if (cr[i].status != URMA_CR_SUCCESS) {
            UMQ_LIMIT_VLOG_ERR(VLOG_UMQ_URMA_CQE, "eid: " EID_FMT ", jetty_id: %u, urma_poll_jfc reports rx cr[%d] "
                "status: %d\n", EID_ARGS(*eid), id, i, cr[i].status);
        } else {
            umq_buf_t *tmp_buf = buf[qbuf_cnt];
            uint32_t total_data_size = cr[i].completion_len;
            tmp_buf->total_data_size = total_data_size;
            while (tmp_buf != NULL && total_data_size > 0) {
                tmp_buf->data_size = total_data_size > tmp_buf->data_size ? tmp_buf->data_size : total_data_size;
                total_data_size -= tmp_buf->data_size;
                tmp_buf = tmp_buf->qbuf_next;
            }
            success_cnt++;
        }
        umq_ub_merge_rx_buffer(buf[qbuf_cnt], &previous_last);
        ++qbuf_cnt;
    }

    if (success_cnt > 0) {
        umq_ub_io_packet_stats(queue, UB_PACKET_STATS_TYPE_RECV, success_cnt, queue->dev_ctx->io_lock_free);
    }

    if (rx_cr_cnt != 0) {
        umq_ub_fill_rx_buffer(queue, rx_cr_cnt);
    }
    return qbuf_cnt;
}

void process_bad_qbuf(umq_buf_t *bad_qbuf, umq_buf_t *qbuf, ub_queue_t *queue)
{
    umq_buf_t *tmp_qbuf = qbuf;
    uint32_t count = 0;
    umq_buf_t *previous = NULL;
    while (tmp_qbuf != NULL && tmp_qbuf != bad_qbuf) {
        count++;
        uint32_t rest_data_size = tmp_qbuf->total_data_size;
        if (rest_data_size == 0) {
            previous = tmp_qbuf;
            tmp_qbuf = tmp_qbuf->qbuf_next;
            continue;
        }
        while (tmp_qbuf && rest_data_size > 0) {
            if (rest_data_size < tmp_qbuf->data_size) {
                UMQ_LIMIT_VLOG_ERR(VLOG_UMQ, "eid: " EID_FMT ", jetty_id: %u, cannot put together tx buffer, rest size"
                    " is negative\n", EID_ARGS(queue->jetty[UB_QUEUE_JETTY_IO]->jetty_id.eid),
                    queue->jetty[UB_QUEUE_JETTY_IO]->jetty_id.id);
                return;
            }
            if (rest_data_size == tmp_qbuf->data_size) {
                previous = tmp_qbuf;
            }
            rest_data_size -= tmp_qbuf->data_size;
            tmp_qbuf = tmp_qbuf->qbuf_next;
        }
    }
    if (previous && tmp_qbuf == bad_qbuf) {
        // break chain of succeed qbuf and failed qbuf on tx
        previous->qbuf_next = NULL;
    }
    umq_ub_io_packet_stats(queue, UB_PACKET_STATS_TYPE_SEND, count, queue->dev_ctx->io_lock_free);
    umq_inc_ref(queue->dev_ctx->io_lock_free, &queue->tx_outstanding, count);
}

void umq_ub_enqueue_with_poll_tx(ub_queue_t *queue, umq_buf_t **buf)
{
    urma_cr_t cr[UMQ_POST_POLL_BATCH];
    urma_eid_t *eid = &queue->jetty[UB_QUEUE_JETTY_IO]->jetty_id.eid;
    uint32_t id = queue->jetty[UB_QUEUE_JETTY_IO]->jetty_id.id;
    int tx_cr_cnt = umq_symbol_urma()->urma_poll_jfc(queue->jfs_jfc[UB_QUEUE_JETTY_IO], UMQ_POST_POLL_BATCH, cr);
    if (tx_cr_cnt < 0) {
        UMQ_LIMIT_VLOG_ERR(VLOG_UMQ_URMA_API, "eid: " EID_FMT ", jetty_id: %u, urma_poll_jfc reports tx_cr_cnt[%d]\n",
            EID_ARGS(*eid), id, tx_cr_cnt);
        return;
    }

    int32_t qbuf_cnt = 0;
    uint32_t success_cnt = 0;
    uint32_t failed_cnt = 0;
    for (int i = 0; i < tx_cr_cnt; i++) {
        if (cr[i].status != URMA_CR_SUCCESS) {
            UMQ_LIMIT_VLOG_ERR(VLOG_UMQ_URMA_CQE, "eid: " EID_FMT ", jetty_id: %u, urma_poll_jfc reports tx cr[%d] "
                "status: %d\n", EID_ARGS(*eid), id, i, cr[i].status);
            if (cr[i].status == URMA_CR_WR_FLUSH_ERR_DONE) {
                if (queue->state == QUEUE_STATE_ERR) {
                    queue->tx_flush_done = true;
                }
                continue;
            }
            if (cr[i].status == URMA_CR_WR_SUSPEND_DONE) {
                continue;
            }
            failed_cnt++;
        } else {
            success_cnt++;
        }

        buf[qbuf_cnt] = (umq_buf_t *)(uintptr_t)cr[i].user_ctx;
        (void)umq_buf_break_and_free(buf[qbuf_cnt]);
        ++qbuf_cnt;
    }
    if (success_cnt > 0) {
        umq_ub_io_packet_stats(queue, UB_PACKET_STATS_TYPE_SEND_SUCCESS, success_cnt, queue->dev_ctx->io_lock_free);
    }

    if (failed_cnt > 0) {
        umq_ub_io_packet_stats(queue, UB_PACKET_STATS_TYPE_SEND_ERROR, success_cnt, queue->dev_ctx->io_lock_free);
    }
    umq_dec_ref(queue->dev_ctx->io_lock_free, &queue->tx_outstanding, qbuf_cnt);
}

void umq_ub_enqueue_plus_with_poll_tx(ub_queue_t *queue, umq_buf_t **buf)
{
    urma_cr_t cr[UMQ_POST_POLL_BATCH];
    urma_eid_t *eid = &queue->jetty[UB_QUEUE_JETTY_IO]->jetty_id.eid;
    uint32_t id = queue->jetty[UB_QUEUE_JETTY_IO]->jetty_id.id;
    int tx_cr_cnt = umq_symbol_urma()->urma_poll_jfc(queue->jfs_jfc[UB_QUEUE_JETTY_IO], UMQ_POST_POLL_BATCH, cr);
    if (tx_cr_cnt < 0) {
        UMQ_LIMIT_VLOG_ERR(VLOG_UMQ_URMA_API, "eid: " EID_FMT ", jetty_id: %u, urma_poll_jfc reports tx_cr_cnt[%d]\n",
            EID_ARGS(*eid), id, tx_cr_cnt);
        return;
    }

    int32_t qbuf_cnt = 0;
    uint32_t success_cnt = 0;
    uint32_t failed_cnt = 0;
    int ret = UMQ_SUCCESS;
    for (int i = 0; i < tx_cr_cnt; i++) {
        if (cr[i].status != URMA_CR_SUCCESS) {
            UMQ_LIMIT_VLOG_ERR(VLOG_UMQ_URMA_CQE, "eid: " EID_FMT ", jetty_id: %u, urma_poll_jfc reports tx cr[%d] "
                "status: %d\n", EID_ARGS(*eid), id, i, cr[i].status);
            if (cr[i].status == URMA_CR_WR_FLUSH_ERR_DONE) {
                if (queue->state == QUEUE_STATE_ERR) {
                    queue->tx_flush_done = true;
                }
                continue;
            }
            if (cr[i].status == URMA_CR_WR_SUSPEND_DONE) {
                continue;
            }
            failed_cnt++;
        } else {
            success_cnt++;
        }

        if (cr[i].user_ctx == 0) {
            umq_dec_ref(queue->dev_ctx->io_lock_free, &queue->tx_outstanding, 1);
            continue;
        }
        umq_dec_ref(queue->dev_ctx->io_lock_free, &queue->tx_outstanding, 1);
        buf[qbuf_cnt] = (umq_buf_t *)(uintptr_t)cr[i].user_ctx;
        buf[qbuf_cnt]->io_direction = UMQ_IO_TX;
        buf[qbuf_cnt]->status = (umq_buf_status_t)cr[i].status;
        umq_buf_pro_t *buf_pro = (umq_buf_pro_t *)buf[qbuf_cnt]->qbuf_ext;
        umq_ub_imm_t imm = {.value = buf_pro->imm_data};
        if (imm.bs.type == IMM_TYPE_REVERSE_PULL_MEM_DONE) {
            user_ctx_t *user_ctx = (user_ctx_t *)buf[qbuf_cnt]->buf_data;
            user_ctx->wr_cnt++;
            if (user_ctx->wr_cnt == user_ctx->wr_total) {
                ret = umq_ub_read_done(queue, user_ctx->msg_id);
                if (ret != UMQ_SUCCESS) {
                    UMQ_LIMIT_VLOG_ERR(VLOG_UMQ, "eid: " EID_FMT ", jetty_id: %u, umq ub send imm failed, "
                        "status: %d\n", EID_ARGS(*eid), id, ret);
                }
                umq_buf_t *tmp = buf[qbuf_cnt];
                if (user_ctx->dst_buf) {
                    buf[qbuf_cnt] = user_ctx->dst_buf;
                    buf[qbuf_cnt]->io_direction = UMQ_IO_RX;
                    ++qbuf_cnt;
                }
                umq_buf_free(tmp);
            }
            continue;
        }
        (void)umq_buf_break_and_free(buf[qbuf_cnt]);
        ++qbuf_cnt;
    }

    if (success_cnt > 0) {
        umq_ub_io_packet_stats(queue, UB_PACKET_STATS_TYPE_SEND_SUCCESS, success_cnt, queue->dev_ctx->io_lock_free);
    }

    if (failed_cnt > 0) {
        umq_ub_io_packet_stats(queue, UB_PACKET_STATS_TYPE_SEND_ERROR, failed_cnt, queue->dev_ctx->io_lock_free);
    }
}

int umq_ub_send_imm(ub_queue_t *queue, uint64_t imm_value, urma_sge_t *sge, uint64_t user_ctx)
{
    urma_eid_t *eid = &queue->jetty[UB_QUEUE_JETTY_IO]->jetty_id.eid;
    uint32_t id = queue->jetty[UB_QUEUE_JETTY_IO]->jetty_id.id;
    if (queue->bind_ctx == NULL) {
        UMQ_LIMIT_VLOG_ERR(VLOG_UMQ, "eid: " EID_FMT ", jetty_id: %u, umq has not been binded\n", EID_ARGS(*eid), id);
        return -UMQ_ERR_ENODEV;
    }

    urma_jfs_wr_t urma_wr = {
        .send = {.src = {.sge = sge, .num_sge = 1}, .imm_data = imm_value },
        .user_ctx = user_ctx,
        .flag = { .bs = { .complete_enable = 1, .inline_flag = 0, } },
        .tjetty = queue->bind_ctx->tjetty[UB_QUEUE_JETTY_IO],
        .opcode = URMA_OPC_SEND_IMM};
    urma_jfs_wr_t *bad_wr = NULL;
    uint64_t start_timestamp = umq_perf_get_start_timestamp();
    urma_status_t status = umq_symbol_urma()->urma_post_jetty_send_wr(queue->jetty[UB_QUEUE_JETTY_IO],
        &urma_wr, &bad_wr);
    umq_perf_record_write(UMQ_PERF_RECORD_TRANSPORT_POST_SEND, start_timestamp);
    if (status != URMA_SUCCESS) {
        UMQ_LIMIT_VLOG_ERR(VLOG_UMQ_URMA_API, "local eid: " EID_FMT ", local jetty_id: %u, remote eid: " EID_FMT ", "
            "remote jetty_id: %u, urma_post_jetty_send_wr failed, status: %d\n", EID_ARGS(*eid), id,
            EID_ARGS(queue->bind_ctx->tjetty[UB_QUEUE_JETTY_IO]->id.eid),
            queue->bind_ctx->tjetty[UB_QUEUE_JETTY_IO]->id.id, (int)status);
        return umq_status_convert(status);
    }
    umq_ub_io_packet_stats(queue, UB_PACKET_STATS_TYPE_SEND, 1, queue->dev_ctx->io_lock_free);
    umq_inc_ref(queue->dev_ctx->io_lock_free, &queue->tx_outstanding, 1);
    return UMQ_SUCCESS;
}

int umq_ub_write_imm(uint64_t umqh_tp, uint64_t target_addr, uint32_t len, uint64_t imm_value)
{
    ub_queue_t *queue = (ub_queue_t *)(uintptr_t)umqh_tp;
    urma_eid_t *eid = &queue->jetty[UB_QUEUE_JETTY_IO]->jetty_id.eid;
    uint32_t id = queue->jetty[UB_QUEUE_JETTY_IO]->jetty_id.id;
    if (queue->bind_ctx == NULL) {
        UMQ_LIMIT_VLOG_ERR(VLOG_UMQ, "eid: " EID_FMT ", jetty_id: %u, umq has not been binded\n", EID_ARGS(*eid), id);
        return -UMQ_ERR_ENODEV;
    }

    /* Prepare src_sge. */
    uint8_t src = 1;
    urma_sge_t src_sge = {
        .addr = (uint64_t)(uintptr_t)&src,
        .len = 1,
        .tseg = queue->dev_ctx->tseg_list[UMQ_QBUF_DEFAULT_MEMPOOL_ID],
    };

    /* Prepare dst_sge. */
    urma_sge_t dst_sge = {
        .addr = target_addr,
        .len = len,
        .tseg = queue->imported_tseg_list[UMQ_QBUF_DEFAULT_MEMPOOL_ID],
    };

    /* WRITE to dst_sge. */
    urma_jfs_wr_t urma_wr = {
        .opcode = URMA_OPC_WRITE_IMM,
        .flag.bs.solicited_enable = URMA_SOLICITED_ENABLE,
        .flag.bs.inline_flag = URMA_INLINE_ENABLE,
        .tjetty = queue->bind_ctx->tjetty[UB_QUEUE_JETTY_IO],
        .user_ctx = UINT16_MAX,     // do not report TX events
        .rw = {
            .src = {.sge = &src_sge, .num_sge = 1},
            .dst = {.sge = &dst_sge, .num_sge = 1},
            .notify_data = imm_value, },
        .next = NULL
    };

    urma_jfs_wr_t *bad_wr = NULL;
    uint64_t start_timestamp = umq_perf_get_start_timestamp();
    urma_status_t status = umq_symbol_urma()->urma_post_jetty_send_wr(queue->jetty[UB_QUEUE_JETTY_IO],
        &urma_wr, &bad_wr);
    umq_perf_record_write(UMQ_PERF_RECORD_TRANSPORT_POST_SEND, start_timestamp);
    if (status != URMA_SUCCESS) {
        UMQ_LIMIT_VLOG_ERR(VLOG_UMQ_URMA_API, "local eid: " EID_FMT ", local jetty_id: %u, remote eid: " EID_FMT ", "
            "remote jetty_id: %u, urma_post_jetty_send_wr failed, status: %d\n", EID_ARGS(*eid), id,
            EID_ARGS(queue->bind_ctx->tjetty[UB_QUEUE_JETTY_IO]->id.eid),
            queue->bind_ctx->tjetty[UB_QUEUE_JETTY_IO]->id.id, (int)status);
        return umq_status_convert(status);
    }
    umq_ub_io_packet_stats(queue, UB_PACKET_STATS_TYPE_SEND, 1, queue->dev_ctx->io_lock_free);
    return UMQ_SUCCESS;
}

int umq_ub_fill_wr_impl(umq_buf_t *qbuf, ub_queue_t *queue, urma_jfs_wr_t *urma_wr_ptr,
                        urma_sge_t *sges, uint32_t remain_tx)
{
    uint32_t max_sge_num = queue->max_tx_sge;
    urma_target_jetty_t *tjetty = queue->bind_ctx->tjetty[UB_QUEUE_JETTY_IO];
    urma_sge_t *sges_ptr;
    umq_buf_t *buffer = qbuf;
    uint32_t wr_index = 0;
    uint32_t sge_index = 0;
    urma_target_seg_t **tseg_list = queue->dev_ctx->tseg_list;
    uint32_t max_send_size =
        (queue->remote_rx_buf_size > queue->tx_buf_size) ? queue->tx_buf_size : queue->remote_rx_buf_size;
    uint32_t sge_num = 0;
    urma_eid_t *eid = &queue->jetty[UB_QUEUE_JETTY_IO]->jetty_id.eid;
    uint32_t id = queue->jetty[UB_QUEUE_JETTY_IO]->jetty_id.id;

    while (buffer != NULL) {
        umq_buf_pro_t *buf_pro = (umq_buf_pro_t *)buffer->qbuf_ext;
        buf_pro->flag.value = 0;
        buf_pro->flag.bs.complete_enable = 1;
        buf_pro->flag.bs.solicited_enable = 1;
        if (buffer->data_size < UMQ_ENABLE_INLINE_LIMIT_SIZE) {
            buf_pro->flag.bs.inline_flag = UMQ_INLINE_ENABLE;
        }
        buf_pro->opcode = UMQ_OPC_SEND;

        uint32_t rest_size = buffer->total_data_size;
        if (rest_size > max_send_size) {
            UMQ_LIMIT_VLOG_ERR(VLOG_UMQ, "eid: " EID_FMT ", jetty_id: %u, total data size[%u] exceed max_send_size[%u]"
                "\n", EID_ARGS(*eid), id, rest_size, max_send_size);
            return -UMQ_ERR_EINVAL;
        }
        /* sges is defined as two-dimensional array, cast to a one-dimensional array for passing, and within the
         * `umq_ub_fill_wr_impl`, it is assigned by jumping in groups of max_sge_num. */
        sge_index = wr_index * max_sge_num;
        sges_ptr = &sges[sge_index];
        uint64_t user_ctx = (uint64_t)(uintptr_t)buffer;
        sge_num = 0;
        while (buffer && rest_size > 0) { // try to add up to total_size
            if (sge_num++ >= max_sge_num) {
                UMQ_LIMIT_VLOG_ERR(VLOG_UMQ, "eid: " EID_FMT ", jetty_id: %u, sge num exceed max sge num[%u]\n",
                    EID_ARGS(*eid), id, max_sge_num);
                return -UMQ_ERR_EINVAL;
            }
            sges_ptr->addr = (uint64_t)(uintptr_t)buffer->buf_data;
            sges_ptr->len = buffer->data_size;
            sges_ptr->user_tseg = NULL;
            sges_ptr->tseg = tseg_list[buffer->mempool_id];
            sges_ptr++;

            if (rest_size < buffer->data_size) { // if cannot add up to total_size, return fail
                UMQ_LIMIT_VLOG_ERR(VLOG_UMQ, "eid: " EID_FMT ", jetty_id: %u, cannot put together tx buffer, rest size"
                    " is negative\n", EID_ARGS(*eid), id);
                return -UMQ_ERR_EINVAL;
            }

            rest_size -= buffer->data_size;
            buffer = QBUF_LIST_NEXT(buffer);
        }
        if (rest_size != 0) { // if cannot add up to total_size, return fail
            UMQ_LIMIT_VLOG_ERR(VLOG_UMQ, "eid: " EID_FMT ", jetty_id: %u, cannot put together enough tx buffer\n",
                EID_ARGS(*eid), id);
            return -UMQ_ERR_ENOMEM;
        }

        urma_wr_ptr->user_ctx = user_ctx;
        urma_wr_ptr->send.src.sge = &sges[sge_index];
        urma_wr_ptr->send.src.num_sge = sge_num;
        urma_wr_ptr->opcode = URMA_OPC_SEND;
        urma_wr_ptr->flag.value = buf_pro->flag.value;
        urma_wr_ptr->tjetty = tjetty;
        urma_wr_ptr++;
        (urma_wr_ptr - 1)->next = urma_wr_ptr;
        wr_index++;
        if ((wr_index == remain_tx || wr_index == UMQ_POST_POLL_BATCH) && buffer != NULL) {
            // wr count exceed remain_tx or UMQ_POST_POLL_BATCH
            UMQ_LIMIT_VLOG_ERR(VLOG_UMQ, "eid: " EID_FMT ", jetty_id: %u, wr count %u exceeds remain_tx %u or "
                "max_post_size %d, not supported\n", EID_ARGS(*eid), id, wr_index, remain_tx, UMQ_POST_POLL_BATCH);
            return -UMQ_ERR_EINVAL;
        }
    }
    (urma_wr_ptr - 1)->next = NULL;
    return wr_index;
}

void umq_flush_rx(ub_queue_t *queue, uint32_t max_retry_times)
{
    int rx_cnt = 0;
    uint32_t retry_times = 0;
    umq_buf_t *buf[UMQ_POST_POLL_BATCH];
    uint32_t remain = queue->rx_depth - __atomic_load_n(&queue->require_rx_count, __ATOMIC_ACQUIRE);
    while (remain > 0 && retry_times < max_retry_times) {
        rx_cnt = umq_ub_poll_rx((uint64_t)(uintptr_t)queue, buf, UMQ_POST_POLL_BATCH);
        if (rx_cnt < 0) {
            return;
        }
        for (int i = 0; i < rx_cnt; i++) {
            umq_buf_free(buf[i]);
        }
        remain -= (uint32_t)rx_cnt;
        retry_times++;
    }
}

void umq_flush_tx(ub_queue_t *queue, uint32_t max_retry_times)
{
    int tx_cnt = 0;
    uint32_t retry_times = 0;
    umq_buf_t *buf[UMQ_POST_POLL_BATCH];
    while (!queue->tx_flush_done && retry_times < max_retry_times) {
        tx_cnt = umq_ub_poll_tx((uint64_t)(uintptr_t)queue, buf, UMQ_POST_POLL_BATCH);
        if (tx_cnt < 0) {
            return;
        }
        for (int i = 0; i < tx_cnt; i++) {
            (void)umq_buf_break_and_free(buf[i]);
        }
        retry_times++;
    }
}

/**
 * fc enable && is main umq: jfc cnt = 2, use io jfr jfce
 * fc disable && is main umq: jfc cnt = 1, use io jfr jfce
 * fc enable && is sub umq: jfc cnt = 1, use fc jfr jfce
 * fc disable && is sub umq: jfc cnt = 0, return 0
 */
int umq_ub_wait_rx_interrupt(ub_queue_t *queue, int time_out, urma_jfc_t *jfc[])
{
    uint32_t jfc_cnt = 0;
    urma_jfce_t *jfr_jfce = NULL;

    if (queue->flow_control.enabled) {
        jfc_cnt++;
        jfr_jfce = queue->jfr_ctx[UB_QUEUE_JETTY_FLOW_CONTROL]->jfr_jfce;
    }

    if ((queue->create_flag & UMQ_CREATE_FLAG_SUB_UMQ) == 0) {
        jfc_cnt++;
        jfr_jfce = queue->jfr_ctx[UB_QUEUE_JETTY_IO]->jfr_jfce;
    }

    if (jfr_jfce == NULL) {
        return 0;
    }

    urma_jfc_t *temp_jfc[jfc_cnt];
    uint64_t start_timestamp = umq_perf_get_start_timestamp();
    int p_num = umq_symbol_urma()->urma_wait_jfc(jfr_jfce, jfc_cnt, time_out, temp_jfc);
    umq_perf_record_write(UMQ_PERF_RECORD_TRANSPORT_WAIT_RX, start_timestamp);
    if (p_num <= 0) {
        return p_num;
    }
    uint32_t nevents[p_num];
    for (int i = 0; i < p_num; i++) {
        nevents[i] = 1;
        jfc[i] = temp_jfc[i];
        if ((queue->create_flag & UMQ_CREATE_FLAG_SUB_UMQ) == 0 &&
            temp_jfc[i] == queue->jfr_ctx[UB_QUEUE_JETTY_IO]->jfr_jfc) {
            queue->interrupt_ctx.rx_io_interrupt = true;
        } else if (queue->flow_control.enabled && temp_jfc[i] == queue->jfr_ctx[UB_QUEUE_JETTY_FLOW_CONTROL]->jfr_jfc) {
            queue->interrupt_ctx.rx_fc_interrupt = true;
        }
    }
    start_timestamp = umq_perf_get_start_timestamp();
    umq_symbol_urma()->urma_ack_jfc(temp_jfc, nevents, p_num);
    umq_perf_record_write(UMQ_PERF_RECORD_TRANSPORT_ACK_RX, start_timestamp);
    return p_num;
}

int umq_ub_wait_tx_interrupt(ub_queue_t *queue, int time_out, urma_jfc_t *jfc[])
{
    uint32_t jfc_cnt = 1;
    if (queue->flow_control.enabled) {
        jfc_cnt++;
    }

    urma_jfc_t *temp_jfc[jfc_cnt];
    uint64_t start_timestamp = umq_perf_get_start_timestamp();
    int p_num = umq_symbol_urma()->urma_wait_jfc(queue->jfs_jfce, jfc_cnt, time_out, temp_jfc);
    umq_perf_record_write(UMQ_PERF_RECORD_TRANSPORT_WAIT_TX, start_timestamp);
    if (p_num <= 0) {
        return p_num;
    }
    uint32_t nevents[p_num];
    for (int i = 0; i < p_num; i++) {
        nevents[i] = 1;
        jfc[i] = temp_jfc[i];
        if (temp_jfc[i] == queue->jfs_jfc[UB_QUEUE_JETTY_IO]) {
            queue->interrupt_ctx.tx_io_interrupt = true;
        } else if (queue->flow_control.enabled && temp_jfc[i] == queue->jfs_jfc[UB_QUEUE_JETTY_FLOW_CONTROL]) {
            queue->interrupt_ctx.tx_fc_interrupt = true;
        }
    }
    start_timestamp = umq_perf_get_start_timestamp();
    umq_symbol_urma()->urma_ack_jfc(temp_jfc, nevents, p_num);
    umq_perf_record_write(UMQ_PERF_RECORD_TRANSPORT_ACK_TX, start_timestamp);
    return p_num;
}

int umq_flow_control_stats_get(uint64_t umqh_tp, umq_flow_control_stats_t *flow_control_stats)
{
    ub_queue_t *queue = (ub_queue_t *)(uintptr_t)umqh_tp;
    if (!queue->flow_control.enabled) {
        UMQ_VLOG_ERR(VLOG_UMQ, "flow control disabled\n");
        return -UMQ_ERR_EINVAL;
    }

    ub_credit_pool_t *pool = &queue->jfr_ctx[UB_QUEUE_JETTY_IO]->credit;
    pool->ops.stats_query(pool, &flow_control_stats->pool_credit);
    queue->flow_control.ops.stats_query(&queue->flow_control, queue, flow_control_stats);
    return UMQ_SUCCESS;
}

void umq_ub_ack_import_tseg(ub_queue_t *queue)
{
    if (queue->wait_ack_import.wait_ack_pool_id == NULL) {
        return;
    }

    if (queue->bind_ctx == NULL) {
        UMQ_LIMIT_VLOG_ERR(VLOG_UMQ, "umq has not been binded\n");
        return;
    }

    uint16_t mempool_id = 0;
    while (queue->wait_ack_import.wait_ack_idx > 0) {
        mempool_id = queue->wait_ack_import.wait_ack_pool_id[--queue->wait_ack_import.wait_ack_idx];
        if (umq_ub_import_mem_done(queue, mempool_id) != UMQ_SUCCESS) {
            UMQ_LIMIT_VLOG_WARN(VLOG_UMQ, "send import mem done imm failed, pool id %u\n", mempool_id);
        }
    }
}

int umq_status_convert(urma_status_t urma_status)
{
    switch (urma_status) {
        case URMA_SUCCESS:
            return UMQ_SUCCESS;
        case URMA_FAIL:
            return UMQ_FAIL;
        case URMA_EAGAIN:
            return -UMQ_ERR_EAGAIN;
        case URMA_ENOMEM:
            return -UMQ_ERR_ENOMEM;
        case URMA_ENOPERM:
            return -UMQ_ERR_EPERM;
        case URMA_ETIMEOUT:
            return -UMQ_ERR_ETIMEOUT;
        case URMA_EINVAL:
            return -UMQ_ERR_EINVAL;
        case URMA_EEXIST:
            return -UMQ_ERR_EEXIST;
        case EINPROGRESS:
            return -UMQ_ERR_EINPROGRESS;
        default:
            UMQ_LIMIT_VLOG_WARN(VLOG_UMQ, "unrecognized urma status: %d\n", (int)urma_status);
            return UMQ_FAIL;
    };
}
