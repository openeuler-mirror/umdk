/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2025-2025. All rights reserved.
 * Description: UMQ UB
 * Create: 2025-12-22
 * Note:
 * History: 2025-12-22
 */

#include "perf.h"
#include "umq_qbuf_pool.h"
#include "umq_ub_flow_control.h"
#include "qbuf_list.h"
#include "umq_ub_api.h"

#define DEFAULT_PRIORITY 5
#define DEFAULT_RNR_RETRY 6      // Retry 6 times
#define DEFAULT_ERR_TIMEOUT 2
#define DEFAULT_MIN_RNR_TIMER 19 // RNR single retransmission time: 2us*2^19 = 1.049s
#define UMQ_MAX_SGE_NUM 6
#define UMQ_MAX_QBUF_NUM 1
#define UMQ_ENABLE_INLINE_LIMIT_SIZE 32
#define UMQ_INLINE_ENABLE 1

static util_id_allocator_t g_umq_ub_id_allocator = {0};
static ub_queue_ctx_list_t g_umq_ub_queue_ctx_list;

static inline uint32_t umq_ub_bind_fature_allowlist_get(void)
{
    return UMQ_FEATURE_ENABLE_STATS | UMQ_FEATURE_ENABLE_PERF;
}

static inline bool umq_ub_bind_feature_check(uint32_t local_feature, uint32_t remote_feature)
{
    return ((local_feature ^ remote_feature) & (~umq_ub_bind_fature_allowlist_get())) == 0;
}

int umq_ub_bind_info_check(ub_queue_t *queue, umq_ub_bind_info_t *info)
{
    if (info->umq_trans_mode != UMQ_TRANS_MODE_UB && info->umq_trans_mode != UMQ_TRANS_MODE_UB_PLUS &&
        info->umq_trans_mode != UMQ_TRANS_MODE_UBMM && info->umq_trans_mode != UMQ_TRANS_MODE_UBMM_PLUS) {
        UMQ_VLOG_ERR("trans mode %d is not UB\n", info->umq_trans_mode);
        return -UMQ_ERR_EINVAL;
    }

    if (queue->state > QUEUE_STATE_READY || info->state > QUEUE_STATE_READY) {
        UMQ_VLOG_ERR("queue state is not ready, local is %u, remote is %u\n", queue->state, info->state);
        return -UMQ_ERR_EINVAL;
    }

    if (queue->dev_ctx->trans_info.trans_mode != info->umq_trans_mode) {
        UMQ_VLOG_ERR("trans mode misatch, local is %u but remote %u\n",
            queue->dev_ctx->trans_info.trans_mode, info->umq_trans_mode)
        return -UMQ_ERR_EINVAL;
    }

    if (!umq_ub_bind_feature_check(queue->dev_ctx->feature, info->feature)) {
        UMQ_VLOG_ERR("feature misatch, local is %u but remote %u\n", queue->dev_ctx->feature, info->feature);
        return -UMQ_ERR_EINVAL;
    }

    if (info->buf_pool_mode != umq_qbuf_mode_get()) {
        UMQ_VLOG_ERR("buf pool mode negotiation inconsistency, recv mode: %d\n", info->buf_pool_mode);
        return -UMQ_ERR_EINVAL;
    }

    if (queue->bind_ctx != NULL || info->is_binded) {
        UMQ_VLOG_ERR("umq has already been binded\n");
        return -UMQ_ERR_EEXIST;
    }

    if (memcmp(&queue->jetty->jetty_id.eid, &info->jetty_id.eid, sizeof(urma_eid_t)) == 0 &&
        queue->jetty->jetty_id.id == info->jetty_id.id) {
        UMQ_VLOG_ERR("the queue cannot bind itself, eid: " EID_FMT ", jetty_id: %u\n",
                     EID_ARGS(queue->jetty->jetty_id.eid), queue->jetty->jetty_id.id);
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
            UMQ_VLOG_ERR("alloc rx failed\n");
            ret = UMQ_ERR_ENOMEM;
            goto DEC_REF;
        }

        umq_buf_t *bad_buf = NULL;
        if (umq_ub_post_rx_inner_impl(queue, qbuf, &bad_buf) != UMQ_SUCCESS) {
            umq_buf_free(bad_buf);
            ret = UMQ_FAIL;
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
        UMQ_VLOG_ERR("xchg_mem invalid\n");
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

    urma_target_seg_t *import_tseg = urma_import_seg(urma_ctx, &remote_seg, &token, 0, flag);
    if (import_tseg == NULL) {
        UMQ_VLOG_ERR("urma import segment failed\n");
        return NULL;
    }
    return import_tseg;
}

static int umq_ub_eid_id_get(ub_queue_t *queue, umq_ub_bind_info_t *info, uint32_t *remote_eid_id)
{
    remote_imported_tseg_info_t *remote_imported_info = queue->dev_ctx->remote_imported_info;
    urma_eid_t *remote_eid = &info->jetty_id.eid;
    uint32_t hash_eid = urpc_hash_bytes(remote_eid, sizeof(urma_eid_t), 0);
    uint32_t hash = urpc_hash_add(hash_eid, info->pid);
    bool find = false;
    remote_eid_hmap_node_t *eid_node;
    pthread_mutex_lock(&remote_imported_info->remote_eid_id_table_lock);
    URPC_HMAP_FOR_EACH_WITH_HASH(eid_node, node, hash, &remote_imported_info->remote_eid_id_table) {
        if ((memcmp(&eid_node->eid, remote_eid, sizeof(urma_eid_t)) == 0) && (info->pid == eid_node->pid)) {
            find = true;
            break;
        }
    }

    if (find) {
        *remote_eid_id = eid_node->remote_eid_id;
        eid_node->ref_cnt++;
        pthread_mutex_unlock(&remote_imported_info->remote_eid_id_table_lock);
        return UMQ_SUCCESS;
    }

    // The jetty for a bind operation originates from a new EID
    eid_node = (remote_eid_hmap_node_t *)malloc(sizeof(remote_eid_hmap_node_t));
    if (eid_node == NULL) {
        pthread_mutex_unlock(&remote_imported_info->remote_eid_id_table_lock);
        UMQ_VLOG_ERR("malloc eid node failed\n");
        return -UMQ_ERR_ENOMEM;
    }

    // allocating EID ID
    uint32_t eid_id = util_id_allocator_get(&remote_imported_info->eid_id_allocator);
    if (eid_id >= UMQ_UB_MAX_REMOTE_EID_NUM) {
        free(eid_node);
        pthread_mutex_unlock(&remote_imported_info->remote_eid_id_table_lock);
        UMQ_VLOG_ERR("remote eid cnt exceed maxinum limit\n");
        return -UMQ_ERR_ENODEV;
    }

    // importing the remote memory
    urma_target_seg_t *tseg = &info->tseg;
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
        util_id_allocator_release(&remote_imported_info->eid_id_allocator, eid_id);
        free(eid_node);
        pthread_mutex_unlock(&remote_imported_info->remote_eid_id_table_lock);
        UMQ_VLOG_ERR("import mem failed, remote eid "EID_FMT", local eid "EID_FMT"\n",
            EID_ARGS(info->jetty_id.eid), EID_ARGS(queue->dev_ctx->urma_ctx->eid));
        return -UMQ_ERR_ENODEV;
    }

    (void)pthread_mutex_init(&remote_imported_info->imported_tseg_list_mutex[eid_id], NULL);
    eid_node->pid = info->pid;
    eid_node->remote_eid_id = eid_id;
    eid_node->ref_cnt = 1;
    *remote_eid_id = eid_id;
    (void)memset(remote_imported_info->tesg_imported[eid_id], 0, sizeof(bool) * UMQ_MAX_TSEG_NUM);
    remote_imported_info->tesg_imported[eid_id][UMQ_QBUF_DEFAULT_MEMPOOL_ID] = true;
    (void)memcpy(&eid_node->eid, remote_eid, sizeof(urma_eid_t));
    urpc_hmap_insert(&remote_imported_info->remote_eid_id_table, &eid_node->node, hash);
    pthread_mutex_unlock(&remote_imported_info->remote_eid_id_table_lock);
    return UMQ_SUCCESS;
}

int umq_ub_eid_id_release(remote_imported_tseg_info_t *remote_imported_info, ub_bind_ctx_t *ctx)
{
    if (remote_imported_info == NULL || ctx == NULL || ctx->tjetty == NULL) {
        UMQ_VLOG_ERR("invalid parameter\n");
        return -UMQ_ERR_EINVAL;
    }
    urma_eid_t *remote_eid = &ctx->tjetty->id.eid;
    uint32_t hash_eid = urpc_hash_bytes(remote_eid, sizeof(urma_eid_t), 0);
    uint32_t hash = urpc_hash_add(hash_eid, ctx->remote_pid);
    bool find = false;
    remote_eid_hmap_node_t *eid_node;
    pthread_mutex_lock(&remote_imported_info->remote_eid_id_table_lock);
    URPC_HMAP_FOR_EACH_WITH_HASH(eid_node, node, hash, &remote_imported_info->remote_eid_id_table) {
        if (memcmp(&eid_node->eid, remote_eid, sizeof(urma_eid_t)) == 0 && (ctx->remote_pid == eid_node->pid) &&
            eid_node->remote_eid_id == ctx->remote_eid_id) {
            find = true;
            break;
        }
    }

    if (!find) {
        pthread_mutex_unlock(&remote_imported_info->remote_eid_id_table_lock);
        UMQ_VLOG_ERR("not find eid node %u\n", ctx->remote_eid_id);
        return -UMQ_ERR_ENODEV;
    }

    eid_node->ref_cnt--;
    if (eid_node->ref_cnt == 0) {
        pthread_mutex_destroy(&remote_imported_info->imported_tseg_list_mutex[eid_node->remote_eid_id]);
        for (uint32_t i = 0; i < UMQ_MAX_TSEG_NUM; i++) {
            if (remote_imported_info->imported_tseg_list[eid_node->remote_eid_id][i] == NULL) {
                continue;
            }
            urma_unimport_seg(remote_imported_info->imported_tseg_list[eid_node->remote_eid_id][i]);
            remote_imported_info->imported_tseg_list[eid_node->remote_eid_id][i] = NULL;
        }
        util_id_allocator_release(&remote_imported_info->eid_id_allocator, eid_node->remote_eid_id);
        urpc_hmap_remove(&remote_imported_info->remote_eid_id_table, &eid_node->node);
        free(eid_node);
    }
    pthread_mutex_unlock(&remote_imported_info->remote_eid_id_table_lock);
    return UMQ_SUCCESS;
}

int umq_ub_bind_inner_impl(ub_queue_t *queue, umq_ub_bind_info_t *info)
{
    ub_bind_ctx_t *ctx = (ub_bind_ctx_t *)calloc(1, sizeof(ub_bind_ctx_t));
    if (ctx == NULL) {
        UMQ_VLOG_ERR("bind ctx calloc failed\n");
        return -UMQ_ERR_ENOMEM;
    }

    ctx->remote_notify_addr = info->notify_buf;

    urma_rjetty_t rjetty = {
        .jetty_id = info->jetty_id,
        .trans_mode = info->trans_mode,
        .type = info->type,
        .flag.bs.token_policy = token_policy_get((queue->dev_ctx->feature & UMQ_FEATURE_ENABLE_TOKEN_POLICY) != 0),
        .flag.bs.order_type = info->order_type,
        .flag.bs.share_tp = 1
    };
    urma_target_jetty_t *tjetty = urma_import_jetty(queue->dev_ctx->urma_ctx, &rjetty, &info->token);
    if (tjetty == NULL) {
        UMQ_VLOG_ERR("import jetty failed, local eid: " EID_FMT ", local jetty_id: %u, remote eid: " EID_FMT ", "
                     "remote jetty_id: %u\n", EID_ARGS(queue->jetty->jetty_id.eid), queue->jetty->jetty_id.id,
                     EID_ARGS(info->jetty_id.eid), info->jetty_id.id);
        goto FREE_CTX;
    }

    urma_status_t status = urma_bind_jetty(queue->jetty, tjetty);
    if (status != URMA_SUCCESS && status != URMA_EEXIST) {
        UMQ_VLOG_ERR("bind jetty failed, status: %d, local eid: " EID_FMT ", local jetty_id: %u, remote eid: "
                     " " EID_FMT ", remote jetty_id: %u\n", (int)status, EID_ARGS(queue->jetty->jetty_id.eid),
                     queue->jetty->jetty_id.id, EID_ARGS(tjetty->id.eid), tjetty->id.id);
        goto UNIMPORT_JETTY;
    }
    // if mode is UB, post rx here. if mode is UB PRO, no need to post rx
    if ((queue->dev_ctx->feature & UMQ_FEATURE_API_PRO) == 0) {
        int ret = umq_ub_prefill_rx_buf(queue);
        if (ret != UMQ_SUCCESS) {
            goto UNIMPORT_JETTY;
        }
    }

    ctx->remote_pid = info->pid;
    ctx->tjetty = tjetty;
    queue->bind_ctx = ctx;

    if (umq_ub_eid_id_get(queue, info, &ctx->remote_eid_id) != UMQ_SUCCESS) {
        UMQ_VLOG_ERR("get eid id failed\n");
        goto UNBIND_JETTY;
    }

    queue->imported_tseg_list = queue->dev_ctx->remote_imported_info->imported_tseg_list[ctx->remote_eid_id];
    uint32_t max_msg_size = queue->dev_ctx->dev_attr.dev_cap.max_msg_size;
    queue->remote_rx_buf_size = (max_msg_size > info->rx_buf_size) ? info->rx_buf_size : max_msg_size;
    UMQ_VLOG_INFO("bind jetty success, local eid: " EID_FMT ", local jetty_id: %u, remote eid: " EID_FMT ", "
                  "remote jetty_id: %u\n", EID_ARGS(queue->jetty->jetty_id.eid), queue->jetty->jetty_id.id,
                  EID_ARGS(tjetty->id.eid), tjetty->id.id);
    return UMQ_SUCCESS;

UNBIND_JETTY:
    queue->bind_ctx = NULL;
    urma_unbind_jetty(queue->jetty);

UNIMPORT_JETTY:
    urma_unimport_jetty(tjetty);

FREE_CTX:
    free(ctx);
    return UMQ_FAIL;
}

int umq_modify_ubq_to_err(ub_queue_t *queue, umq_io_direction_t direction)
{
    urma_status_t urma_status = URMA_EINVAL;
    if (direction == UMQ_IO_ALL || direction == UMQ_IO_TX) {
        urma_jetty_attr_t jetty_attr = {
            .mask = JETTY_STATE,
            .state = URMA_JETTY_STATE_ERROR,
        };
        urma_status = urma_modify_jetty(queue->jetty, &jetty_attr);
        if (urma_status != URMA_SUCCESS) {
            UMQ_VLOG_ERR("modify jetty to URMA_JETTY_STATE_ERROR fail, status %u, eid: " EID_FMT ", jetty_id: %u\n",
                        urma_status, EID_ARGS(queue->jetty->jetty_id.eid), queue->jetty->jetty_id.id);
        }
    }

    if (direction == UMQ_IO_ALL || direction == UMQ_IO_RX) {
        urma_jfr_attr_t jfr_attr = {
            .mask = JETTY_STATE,
            .state = URMA_JFR_STATE_ERROR,
        };
        urma_status = urma_modify_jfr(queue->jfr_ctx->jfr, &jfr_attr);
        if (urma_status != URMA_SUCCESS) {
            UMQ_VLOG_ERR("modify jfr to URMA_JFR_STATE_ERROR fail, status %u\n", urma_status);
        }
    }

    queue->state = QUEUE_STATE_ERR;
    return urma_status;
}

static uint32_t get_dev_by_eid_str(urma_transport_type_t type, urma_eid_t *eid, urma_device_t **urma_dev,
                                   uint32_t *eid_index)
{
    if (eid == NULL) {
        UMQ_VLOG_ERR("eid is null\n");
        return 0;
    }

    int device_num = 0;
    urma_device_t **device_list = urma_get_device_list(&device_num);
    if (device_list == NULL || device_num == 0) {
        UMQ_VLOG_ERR("urma get device list failed, eid " EID_FMT "\n", EID_ARGS(*eid));
        return 0;
    }

    uint32_t j, cnt = 0;
    int i;
    for (i = 0; i < device_num; i++) {
        if (device_list[i]->type != type) {
            continue;
        }
        urma_eid_info_t *eid_list = urma_get_eid_list(device_list[i], &cnt);
        if (eid_list == NULL || cnt == 0) {
            continue;
        }
        for (j = 0; j < cnt; j++) {
            if ((memcmp(eid, &eid_list[j].eid, sizeof(urma_eid_t)) == 0)) {
                *urma_dev = device_list[i];
                *eid_index = eid_list[j].eid_index;
                break;
            }
        }
        urma_free_eid_list(eid_list);
        if (j != cnt) {
            break;
        }
    }

    urma_free_device_list(device_list);

    if (i == device_num) {
        UMQ_VLOG_ERR("get device failed, eid " EID_FMT "\n", EID_ARGS(*eid));
        return 0;
    }
    return 1;
}

static uint32_t umq_find_ub_dev_by_eid(urma_transport_type_t type, umq_dev_assign_t *dev_info, urma_device_t **urma_dev,
                                       uint32_t *eid_index)
{
    urma_eid_t *eid = (urma_eid_t *)&dev_info->eid.eid;
    return get_dev_by_eid_str(type, eid, urma_dev, eid_index);
}

static uint32_t umq_find_ub_dev_by_ip_addr(urma_transport_type_t type, umq_dev_assign_t *dev_info,
                                           urma_device_t **urma_dev, uint32_t *eid_index)
{
    const char *ip_addr = dev_info->assign_mode == UMQ_DEV_ASSIGN_MODE_IPV4 ? dev_info->ipv4.ip_addr
                                                                                 : dev_info->ipv6.ip_addr;
    urma_eid_t eid;
    int ret = urma_str_to_eid(ip_addr, &eid);
    if (ret != 0) {
        UMQ_VLOG_ERR("format ip addr to eid failed, ip_addr %s\n", ip_addr);
        return 0;
    }
    return get_dev_by_eid_str(type, &eid, urma_dev, eid_index);
}

static uint32_t umq_find_ub_dev_by_name(char *dev_name, urma_device_t **urma_dev)
{
    *urma_dev = urma_get_device_by_name(dev_name);
    if (*urma_dev == NULL) {
        UMQ_VLOG_ERR("urma get device by name failed, dev_name %s\n", dev_name);
        return 0;
    }
    return 1;
}

uint32_t umq_ub_get_urma_dev(umq_dev_assign_t *dev_info, urma_device_t **urma_dev, uint32_t *eid_index)
{
    uint32_t eid_cnt = 0;
    if (dev_info->assign_mode == UMQ_DEV_ASSIGN_MODE_DEV) {
        eid_cnt = umq_find_ub_dev_by_name(dev_info->dev.dev_name, urma_dev);
        *eid_index = dev_info->dev.eid_idx;
    } else if (dev_info->assign_mode == UMQ_DEV_ASSIGN_MODE_EID) {
        eid_cnt = umq_find_ub_dev_by_eid(URMA_TRANSPORT_UB, dev_info, urma_dev, eid_index);
    } else if (dev_info->assign_mode == UMQ_DEV_ASSIGN_MODE_IPV4 ||
               dev_info->assign_mode == UMQ_DEV_ASSIGN_MODE_IPV6) {
        eid_cnt = umq_find_ub_dev_by_ip_addr(URMA_TRANSPORT_UB, dev_info, urma_dev, eid_index);
    } else {
        UMQ_VLOG_ERR("assign mode: %d not supported\n", dev_info->assign_mode);
    }
    return eid_cnt;
}

int umq_ub_create_urma_ctx(urma_device_t *urma_dev, uint32_t eid_index, umq_ub_ctx_t *ub_ctx)
{
    urma_device_attr_t dev_attr;
    if (urma_query_device(urma_dev, &dev_attr) != URMA_SUCCESS) {
        UMQ_VLOG_ERR("query device failed, device name: %s\n", *urma_dev->name);
        return -UMQ_ERR_ENODEV;
    }
    ub_ctx->dev_attr = dev_attr;

    ub_ctx->urma_ctx = urma_create_context(urma_dev, eid_index);
    if (ub_ctx->urma_ctx == NULL) {
        UMQ_VLOG_ERR("failed to create urma context\n");
        return -UMQ_ERR_ENODEV;
    }
    return UMQ_SUCCESS;
}

int umq_ub_delete_urma_ctx(umq_ub_ctx_t *ub_ctx)
{
    if (ub_ctx == NULL || ub_ctx->urma_ctx) {
        UMQ_VLOG_ERR("invalid parameter\n");
        return -UMQ_ERR_EINVAL;
    }

    urma_status_t urma_status = urma_delete_context(ub_ctx->urma_ctx);
    if (urma_status != URMA_SUCCESS) {
        UMQ_VLOG_ERR("delete context failed\n");
        return -UMQ_ERR_ENODEV;
    }

    ub_ctx->urma_ctx = NULL;
    return UMQ_SUCCESS;
}

int umq_ub_get_eid_dev_info(urma_device_t *urma_dev, uint32_t eid_idx, umq_dev_assign_t *out_info)
{
    uint32_t eid_cnt = 0;
    urma_eid_info_t *eid_info_list = urma_get_eid_list(urma_dev, &eid_cnt);
    if (eid_info_list == NULL || eid_cnt == 0) {
        UMQ_VLOG_ERR("get eid list fialed\n");
        return -UMQ_ERR_ENODEV;
    }

    for (uint32_t i = 0; i < eid_cnt; i++) {
        if (eid_info_list[i].eid_index != eid_idx) {
            continue;
        }

        out_info->assign_mode = UMQ_DEV_ASSIGN_MODE_EID;
        (void)memcpy(&out_info->eid.eid, &eid_info_list[i].eid, sizeof(urma_eid_t));
        break;
    }

    urma_free_eid_list(eid_info_list);
    return UMQ_SUCCESS;
}

umq_ub_ctx_t *umq_ub_get_ub_ctx_by_dev_info(umq_ub_ctx_t *ub_ctx_list, uint32_t ub_ctx_cnt, umq_dev_assign_t *dev_info)
{
    urma_device_t *urma_dev;
    uint32_t eid_index = 0;
    uint32_t eid_cnt = umq_ub_get_urma_dev(dev_info, &urma_dev, &eid_index);
    if (eid_cnt == 0) {
        UMQ_VLOG_ERR("failed to get urma dev\n");
        return NULL;
    }

    umq_dev_assign_t eid_dev_info;
    int ret = umq_ub_get_eid_dev_info(urma_dev, eid_index, &eid_dev_info);
    if (ret != UMQ_SUCCESS) {
        UMQ_VLOG_ERR("umq get eid trans info\n");
        return NULL;
    }

    umq_ub_ctx_t *ub_ctx = NULL;
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
        UMQ_VLOG_ERR("calloc imported info failed\n");
        return NULL;
    }

    int ret = urpc_hmap_init(&remote_imported_tseg_info->remote_eid_id_table, UMQ_UB_MAX_REMOTE_EID_NUM);
    if (ret != UMQ_SUCCESS) {
        UMQ_VLOG_ERR("remote eid map init failed\n");
        goto FREE_INFO;
    }

    ret = util_id_allocator_init(&remote_imported_tseg_info->eid_id_allocator,
        UMQ_UB_MAX_REMOTE_EID_NUM, UMQ_UB_MIN_EID_ID);
    if (ret != UMQ_SUCCESS) {
        UMQ_VLOG_ERR("bind id allocator init failed\n");
        goto REMOTE_EID_MAP_UNINIT;
    }

    (void)pthread_mutex_init(&remote_imported_tseg_info->remote_eid_id_table_lock, NULL);
    return remote_imported_tseg_info;

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
    (void)pthread_mutex_destroy(&remote_imported_tseg_info->remote_eid_id_table_lock);
    urpc_hmap_uninit(&remote_imported_tseg_info->remote_eid_id_table);
    util_id_allocator_uninit(&ub_ctx->remote_imported_info->eid_id_allocator);
    free(ub_ctx->remote_imported_info);
    ub_ctx->remote_imported_info = NULL;
}

urma_jetty_t *umq_create_jetty(ub_queue_t *queue, umq_ub_ctx_t *dev_ctx)
{
    urma_jetty_cfg_t jetty_cfg = {
        .jfs_cfg = {
            .flag.bs.order_type = dev_ctx->order_type,
            .trans_mode = URMA_TM_RC,
            .depth = queue->tx_depth,
            .priority = queue->priority,
            .max_sge = queue->max_tx_sge,
            .max_inline_data = dev_ctx->dev_attr.dev_cap.max_jfs_inline_len,
            .jfc = queue->jfs_jfc,
            .rnr_retry = queue->rnr_retry,
            .err_timeout = queue->err_timeout,
        },
        .id = 0,
    };
    jetty_cfg.flag.bs.share_jfr = true;
    jetty_cfg.shared.jfr = queue->jfr_ctx->jfr;

    urma_jetty_t *jetty = urma_create_jetty(dev_ctx->urma_ctx, &jetty_cfg);
    if (jetty == NULL) {
        UMQ_VLOG_ERR("urma create jetty failed\n");
        return NULL;
    }
    UMQ_VLOG_INFO("create jetty success, eid: " EID_FMT ", jetty_id: %u\n",
                  EID_ARGS(jetty->jetty_id.eid), jetty->jetty_id.id);
    return jetty;
}

int check_and_set_param(umq_ub_ctx_t *dev_ctx, umq_create_option_t *option, ub_queue_t *queue)
{
    if (option->create_flag & UMQ_CREATE_FLAG_RX_BUF_SIZE) {
        if (option->rx_buf_size > dev_ctx->dev_attr.dev_cap.max_msg_size) {
            UMQ_VLOG_ERR("rx buf size [%u] exceed max buf size [%d]\n", option->rx_buf_size,
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
            UMQ_VLOG_ERR("tx buf size [%u] exceed max buf size [%d]\n", option->tx_buf_size,
                         dev_ctx->dev_attr.dev_cap.max_msg_size);
            return -UMQ_ERR_EINVAL;
        }
        queue->tx_buf_size = option->tx_buf_size;
    } else {
        queue->tx_buf_size = dev_ctx->dev_attr.dev_cap.max_msg_size < UMQ_DEFAULT_BUF_SIZE ?
                             dev_ctx->dev_attr.dev_cap.max_msg_size : UMQ_DEFAULT_BUF_SIZE;
    }
    if (option->create_flag & UMQ_CREATE_FLAG_RX_DEPTH) {
        if (option->rx_depth > dev_ctx->dev_attr.dev_cap.max_jfc_depth) {
            UMQ_VLOG_ERR("rx depth [%u] exceed max depth [%d]\n", option->rx_depth,
                         dev_ctx->dev_attr.dev_cap.max_jfc_depth);
            return -UMQ_ERR_EINVAL;
        }
        queue->rx_depth = option->rx_depth;
    } else {
        queue->rx_depth = dev_ctx->dev_attr.dev_cap.max_jfc_depth < UMQ_DEFAULT_DEPTH ?
                          dev_ctx->dev_attr.dev_cap.max_jfc_depth : UMQ_DEFAULT_DEPTH;
    }

    if ((dev_ctx->feature & UMQ_FEATURE_ENABLE_FLOW_CONTROL) != 0 &&
        (queue->tx_depth > UINT16_MAX || (queue->rx_depth > UINT16_MAX))) {
        UMQ_VLOG_ERR("queue tx depth %u, rx depth %u exceed %u\n", queue->tx_depth, queue->rx_depth, UINT16_MAX);
        return -UMQ_ERR_EINVAL;
    }

    if (option->create_flag & UMQ_CREATE_FLAG_TX_DEPTH) {
        if (option->tx_depth + 1 > dev_ctx->dev_attr.dev_cap.max_jfc_depth) {
            UMQ_VLOG_ERR("tx depth [%u] exceed max depth [%d]\n", option->tx_depth + 1,
                         dev_ctx->dev_attr.dev_cap.max_jfc_depth);
            return -UMQ_ERR_EINVAL;
        }
        queue->tx_depth = option->tx_depth;
    } else {
        queue->tx_depth = dev_ctx->dev_attr.dev_cap.max_jfc_depth < UMQ_DEFAULT_DEPTH ?
                          dev_ctx->dev_attr.dev_cap.max_jfc_depth : UMQ_DEFAULT_DEPTH;
    }
    if (option->create_flag & UMQ_CREATE_FLAG_QUEUE_MODE) {
        if (option->mode < 0 || option->mode >= UMQ_MODE_MAX) {
            UMQ_VLOG_ERR("queue mode[%d] is invalid\n", option->mode);
            return -UMQ_ERR_EINVAL;
        }
        queue->mode = option->mode;
    }
    if (((option->create_flag & UMQ_CREATE_FLAG_SHARE_RQ) != 0 && (option->create_flag &
        UMQ_CREATE_FLAG_SUB_UMQ) == 0) || ((option->create_flag & UMQ_CREATE_FLAG_SHARE_RQ) == 0 &&
        (option->create_flag & UMQ_CREATE_FLAG_SUB_UMQ) != 0)) {
        UMQ_VLOG_ERR("queue create_flag[%u] is invalid\n", option->create_flag);
        return -UMQ_ERR_EINVAL;
    }
    queue->max_rx_sge = dev_ctx->dev_attr.dev_cap.max_jfr_sge < UMQ_MAX_SGE_NUM ?
                        dev_ctx->dev_attr.dev_cap.max_jfr_sge : UMQ_MAX_SGE_NUM;
    queue->max_tx_sge = dev_ctx->dev_attr.dev_cap.max_jfs_sge < UMQ_MAX_SGE_NUM ?
                        dev_ctx->dev_attr.dev_cap.max_jfs_sge : UMQ_MAX_SGE_NUM;
    queue->priority = DEFAULT_PRIORITY;
    queue->err_timeout = DEFAULT_ERR_TIMEOUT;
    queue->rnr_retry = DEFAULT_RNR_RETRY;
    queue->min_rnr_timer = DEFAULT_MIN_RNR_TIMER;
    (void)memcpy(queue->name, option->name, UMQ_NAME_MAX_LEN);
    queue->dev_ctx = dev_ctx;
    queue->umq_trans_mode = option->trans_mode;
    queue->remote_rx_buf_size = dev_ctx->dev_attr.dev_cap.max_msg_size;
    queue->create_flag = option->create_flag;
    return UMQ_SUCCESS;
}

int share_rq_param_check(ub_queue_t *queue, ub_queue_t *share_rq)
{
    if (share_rq->state == QUEUE_STATE_ERR) {
        UMQ_VLOG_ERR("the share_rq is invalid\n");
        goto ERR;
    }
    if (share_rq->create_flag & UMQ_CREATE_FLAG_SUB_UMQ) {
        UMQ_VLOG_ERR("sub umq cannot be used as share_rq\n");
        goto ERR;
    }
    if (share_rq->dev_ctx != queue->dev_ctx) {
        UMQ_VLOG_ERR("the dev_ctx of share_rq and creating queue is different\n");
        goto ERR;
    }
    if ((queue->create_flag & UMQ_CREATE_FLAG_RX_BUF_SIZE) && (share_rq->rx_buf_size != queue->rx_buf_size)) {
        UMQ_VLOG_ERR("the rx_buf_size of share_rq and creating queue is different\n");
        goto ERR;
    }
    if ((queue->create_flag & UMQ_CREATE_FLAG_RX_DEPTH) && (share_rq->rx_depth != queue->rx_depth)) {
        UMQ_VLOG_ERR("the rx_depth of share_rq and creating queue is different\n");
        goto ERR;
    }
    if ((queue->create_flag & UMQ_CREATE_FLAG_QUEUE_MODE) && (share_rq->mode != queue->mode)) {
        UMQ_VLOG_ERR("the queue_mode of share_rq and creating queue is different\n");
        goto ERR;
    }
    return UMQ_SUCCESS;
ERR:
    errno = UMQ_ERR_EINVAL;
    return -UMQ_ERR_EINVAL;
}

void umq_ub_jfr_ctx_destroy(ub_queue_t *queue)
{
    uint32_t new_value = __atomic_sub_fetch(&queue->jfr_ctx->ref_cnt, 1, __ATOMIC_RELAXED);
    UMQ_VLOG_DEBUG("jfr_ctx ref_cnt %u\n", new_value);
    if (new_value > 0) {
        return;
    }
    UMQ_VLOG_INFO("destroy jfr_ctx, eid: " EID_FMT ", jfr_id: %u\n",
                  EID_ARGS(queue->jfr_ctx->jfr->jfr_id.eid), queue->jfr_ctx->jfr->jfr_id.id);
    if (urma_delete_jfr(queue->jfr_ctx->jfr) != URMA_SUCCESS) {
        UMQ_VLOG_ERR("delete jfr failed\n");
    }
    if (urma_delete_jfc(queue->jfr_ctx->jfr_jfc) != URMA_SUCCESS) {
        UMQ_VLOG_ERR("delete jfr_jfc failed\n");
    }
    if (queue->mode == UMQ_MODE_INTERRUPT) {
        if (urma_delete_jfce(queue->jfr_ctx->jfr_jfce) != URMA_SUCCESS) {
            UMQ_VLOG_ERR("delete jfr_jfce failed\n");
        }
    }
    rx_buf_ctx_list_uninit(&queue->jfr_ctx->rx_buf_ctx_list);
    free(queue->jfr_ctx);
    queue->jfr_ctx = NULL;
}

int umq_ub_jfr_ctx_create(ub_queue_t *queue, umq_ub_ctx_t *dev_ctx, umq_create_option_t *option,
                          ub_queue_t *share_queue)
{
    if ((option->create_flag & UMQ_CREATE_FLAG_SHARE_RQ) != 0) {
        queue->jfr_ctx = share_queue->jfr_ctx;
        (void)__atomic_add_fetch(&queue->jfr_ctx->ref_cnt, 1, __ATOMIC_RELAXED);
        return UMQ_SUCCESS;
    }
    bool enable_token = (dev_ctx->feature & UMQ_FEATURE_ENABLE_TOKEN_POLICY) != 0;
    uint32_t jetty_token;
    if (umq_ub_token_generate(enable_token, &jetty_token) != 0) {
        UMQ_VLOG_ERR("generate jetty token failed\n");
        return UMQ_FAIL;
    }
    queue->jfr_ctx = calloc(1, sizeof(jfr_ctx_t));
    if (queue->jfr_ctx == NULL) {
        UMQ_VLOG_ERR("get_jfr_ctx failed, calloc jfr_ctx failed\n");
        return -UMQ_ERR_ENOMEM;
    }
    // create jfce
    if (queue->mode == UMQ_MODE_INTERRUPT) {
        queue->jfr_ctx->jfr_jfce = urma_create_jfce(dev_ctx->urma_ctx);
        if (queue->jfr_ctx->jfr_jfce == NULL) {
            UMQ_VLOG_ERR("create jfr_jfce failed\n");
            goto FREE_JFR_CTX;
        }
    }
    // create jfr_jfc
    urma_jfc_cfg_t jfr_jfc_cfg = {
        .depth = queue->rx_depth,
        .jfce = queue->jfr_ctx->jfr_jfce
    };
    queue->jfr_ctx->jfr_jfc = urma_create_jfc(dev_ctx->urma_ctx, &jfr_jfc_cfg);
    if (queue->jfr_ctx->jfr_jfc == NULL) {
        UMQ_VLOG_ERR("urma create jfr_jfc failed\n");
        goto DELETE_JFR_JFCE;
    }
    // create jfr
    urma_jfr_cfg_t jfr_cfg = {
        .flag.bs.token_policy = token_policy_get(enable_token),
        .trans_mode = URMA_TM_RC,
        .depth = queue->rx_depth,
        .max_sge = queue->max_rx_sge,
        .min_rnr_timer = queue->min_rnr_timer,
        .jfc = queue->jfr_ctx->jfr_jfc,
        .token_value = { .token = jetty_token }
    };
    jfr_cfg.flag.bs.order_type = dev_ctx->order_type;
    queue->jfr_ctx->jfr = urma_create_jfr(dev_ctx->urma_ctx, &jfr_cfg);
    if (queue->jfr_ctx->jfr == NULL) {
        UMQ_VLOG_ERR("urma create jfr failed\n");
        goto DELETE_JFR_JFC;
    }
    if (rx_buf_ctx_list_init(queue) != UMQ_SUCCESS) {
        UMQ_VLOG_ERR("rx buf ctx list init failed\n");
        goto DELETE_JFR;
    }
    queue->jfr_ctx->ref_cnt = 1;
    UMQ_VLOG_INFO("create jfr_ctx success, eid: " EID_FMT ", jfr_id: %u\n",
                  EID_ARGS(queue->jfr_ctx->jfr->jfr_id.eid), queue->jfr_ctx->jfr->jfr_id.id);
    return UMQ_SUCCESS;

DELETE_JFR:
    (void)urma_delete_jfr(queue->jfr_ctx->jfr);

DELETE_JFR_JFC:
    (void)urma_delete_jfc(queue->jfr_ctx->jfr_jfc);

DELETE_JFR_JFCE:
    if (queue->mode == UMQ_MODE_INTERRUPT) {
        (void)urma_delete_jfce(queue->jfr_ctx->jfr_jfce);
    }

FREE_JFR_CTX:
    free(queue->jfr_ctx);
    queue->jfr_ctx = NULL;
    return UMQ_FAIL;
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

int umq_ub_register_seg(umq_ub_ctx_t *ctx, uint8_t mempool_id, void *addr, uint64_t size)
{
    bool enable_token = (ctx->feature & UMQ_FEATURE_ENABLE_TOKEN_POLICY) != 0;
    uint32_t mem_token;
    int ret = umq_ub_token_generate(enable_token, &mem_token);
    if (ret != UMQ_SUCCESS) {
        UMQ_VLOG_ERR("generate memory token failed\n");
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

    ctx->tseg_list[mempool_id] = urma_register_seg(ctx->urma_ctx, &seg_cfg);
    if (ctx->tseg_list[mempool_id] == NULL) {
        UMQ_VLOG_ERR("fail to register segment\n");
        return -UMQ_ERR_ENODEV;
    }

    return UMQ_SUCCESS;
}

void umq_ub_unregister_seg(umq_ub_ctx_t *ctx_list, uint32_t ctx_cnt, uint8_t mempool_id)
{
    for (uint32_t i = 0; i < ctx_cnt; i++) {
        if (ctx_list[i].tseg_list[mempool_id] != NULL &&
            urma_unregister_seg(ctx_list[i].tseg_list[mempool_id]) != URMA_SUCCESS) {
            UMQ_VLOG_ERR("ub ctx[%u] unregister segment failed\n", i);
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

    (void)pthread_rwlock_rdlock(&g_umq_ub_queue_ctx_list.lock);
    URPC_LIST_FOR_EACH(local, qctx_node, &g_umq_ub_queue_ctx_list.queue_list) {
        if (local->jfs_jfc == urma_event->element.jfc) {
            find = true;
            umq_event->event_type = UMQ_EVENT_QH_SQ_CQ_ERR;
            umq_event->element.umqh = local->umqh;
            break;
        }

        if (local->jfr_ctx->jfr_jfc == urma_event->element.jfc) {
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
    (void)pthread_rwlock_unlock(&g_umq_ub_queue_ctx_list.lock);

    if (!find) {
        UMQ_VLOG_WARN("can not find jfc id %u in all umq\n", urma_event->element.jfc->jfc_id.id);
    }
}

void handle_async_event_jfr_err(urma_async_event_t *urma_event, umq_async_event_t *umq_event)
{
    bool find = false;
    ub_queue_t *local = NULL;
    umq_event->event_type = UMQ_EVENT_QH_RQ_ERR;
    umq_event->element.umqh = UMQ_INVALID_HANDLE;

    (void)pthread_rwlock_rdlock(&g_umq_ub_queue_ctx_list.lock);
    URPC_LIST_FOR_EACH(local, qctx_node, &g_umq_ub_queue_ctx_list.queue_list) {
        if (local->jfr_ctx->jfr == urma_event->element.jfr) {
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
    (void)pthread_rwlock_unlock(&g_umq_ub_queue_ctx_list.lock);

    if (!find) {
        UMQ_VLOG_WARN("can not find jfr id %u in all umq\n", urma_event->element.jfr->jfr_id.id);
    }
}

void handle_async_event_jfr_limit(urma_async_event_t *urma_event, umq_async_event_t *umq_event)
{
    bool find = false;
    ub_queue_t *local = NULL;
    umq_event->event_type = UMQ_EVENT_QH_RQ_LIMIT;
    umq_event->element.umqh = UMQ_INVALID_HANDLE;

    (void)pthread_rwlock_rdlock(&g_umq_ub_queue_ctx_list.lock);
    URPC_LIST_FOR_EACH(local, qctx_node, &g_umq_ub_queue_ctx_list.queue_list) {
        if (local->jfr_ctx->jfr == urma_event->element.jfr) {
            find = true;
            if (local->create_flag & UMQ_CREATE_FLAG_SUB_UMQ) {
                umq_event->element.umqh = local->share_rq_umqh;
                break;
            }
            umq_event->element.umqh = local->umqh;
            break;
        }
    }
    (void)pthread_rwlock_unlock(&g_umq_ub_queue_ctx_list.lock);

    if (!find) {
        UMQ_VLOG_WARN("can not find jfr id %u in all umq\n", urma_event->element.jfr->jfr_id.id);
    }
}

void handle_async_event_jetty_err(urma_async_event_t *urma_event, umq_async_event_t *umq_event)
{
    bool find = false;
    ub_queue_t *local = NULL;
    umq_event->event_type = UMQ_EVENT_QH_ERR;
    umq_event->element.umqh = UMQ_INVALID_HANDLE;

    (void)pthread_rwlock_rdlock(&g_umq_ub_queue_ctx_list.lock);
    URPC_LIST_FOR_EACH(local, qctx_node, &g_umq_ub_queue_ctx_list.queue_list) {
        if (local->jetty == urma_event->element.jetty) {
            find = true;
            umq_event->element.umqh = local->umqh;
            break;
        }
    }
    (void)pthread_rwlock_unlock(&g_umq_ub_queue_ctx_list.lock);

    if (!find) {
        UMQ_VLOG_WARN("can not find jetty id %u in all umq\n", urma_event->element.jetty->jetty_id.id);
    }
}

void handle_async_event_jetty_limit(urma_async_event_t *urma_event, umq_async_event_t *umq_event)
{
    bool find = false;
    ub_queue_t *local = NULL;
    umq_event->event_type = UMQ_EVENT_QH_LIMIT;
    umq_event->element.umqh = UMQ_INVALID_HANDLE;

    (void)pthread_rwlock_rdlock(&g_umq_ub_queue_ctx_list.lock);
    URPC_LIST_FOR_EACH(local, qctx_node, &g_umq_ub_queue_ctx_list.queue_list) {
        if (local->jetty == urma_event->element.jetty) {
            find = true;
            umq_event->element.umqh = local->umqh;
            break;
        }
    }
    (void)pthread_rwlock_unlock(&g_umq_ub_queue_ctx_list.lock);

    if (!find) {
        UMQ_VLOG_WARN("can not find jetty id %u in all umq\n", urma_event->element.jetty->jetty_id.id);
    }
}

void umq_ub_queue_ctx_list_init(void)
{
    urpc_list_init(&g_umq_ub_queue_ctx_list.queue_list);
    (void)pthread_rwlock_init(&g_umq_ub_queue_ctx_list.lock, NULL);
}

void umq_ub_queue_ctx_list_uninit(void)
{
    ub_queue_t *cur_node, *next_node;
    URPC_LIST_FOR_EACH_SAFE(cur_node, next_node, qctx_node, &g_umq_ub_queue_ctx_list.queue_list) {
        urpc_list_remove(&cur_node->qctx_node);
    }
    (void)pthread_rwlock_destroy(&g_umq_ub_queue_ctx_list.lock);
}

void umq_ub_queue_ctx_list_push(urpc_list_t *qctx_node)
{
    (void)pthread_rwlock_wrlock(&g_umq_ub_queue_ctx_list.lock);
    urpc_list_push_back(&g_umq_ub_queue_ctx_list.queue_list, qctx_node);
    (void)pthread_rwlock_unlock(&g_umq_ub_queue_ctx_list.lock);
}

void umq_ub_queue_ctx_list_remove(urpc_list_t *qctx_node)
{
    (void)pthread_rwlock_wrlock(&g_umq_ub_queue_ctx_list.lock);
    urpc_list_remove(qctx_node);
    (void)pthread_rwlock_unlock(&g_umq_ub_queue_ctx_list.lock);
}

int umq_ub_id_allocator_init(void)
{
    return util_id_allocator_init(&g_umq_ub_id_allocator, UMQ_MAX_ID_NUM, 1);
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
    if (size_interval == UMQ_SIZE_0K_SMALL_INTERVAL) {
        return umq_buf_size_small();
    } else if (size_interval == UMQ_SIZE_SMALL_MID_INTERVAL) {
        return umq_buf_size_middle();
    } else if (size_interval == UMQ_SIZE_MID_BIG_INTERVAL) {
        return umq_buf_size_big();
    } else if (size_interval == UMQ_SIZE_BIG_HUGE_INTERVAL) {
        return umq_buf_size_huge();
    }

    UMQ_LIMIT_VLOG_ERR("size_interval: %d is invalid\n", size_interval);
    return UINT32_MAX;
}

static ALWAYS_INLINE uint32_t umq_ub_get_read_pre_allocate_max_total_size(
    umq_size_interval_t size_interval, uint16_t buf_num)
{
    uint32_t read_alloc_mem_size = umq_read_alloc_mem_size(size_interval);
    if (read_alloc_mem_size == UINT32_MAX) {
        return UINT32_MAX;
    }

    umq_buf_mode_t buf_mode = umq_qbuf_mode_get();
    if (buf_mode == UMQ_BUF_SPLIT) {
        return read_alloc_mem_size * buf_num - umq_qbuf_headroom_get();
    } else if (buf_mode == UMQ_BUF_COMBINE) {
        return read_alloc_mem_size * buf_num - sizeof(umq_buf_t) * buf_num - umq_qbuf_headroom_get();
    }

    UMQ_LIMIT_VLOG_ERR("buf mode: %d is invalid\n", buf_mode);
    return UINT32_MAX;
}

umq_buf_t *umq_ub_read_ctx_create(ub_queue_t *queue, umq_imm_head_t *umq_imm_head, uint16_t buf_num, uint16_t msg_id)
{
    umq_buf_t *ctx_buf = umq_buf_alloc(sizeof(user_ctx_t), 1, UMQ_INVALID_HANDLE, NULL);
    if (ctx_buf == NULL) {
        UMQ_LIMIT_VLOG_ERR("ctx_buf malloc failed\n");
        return NULL;
    }
    umq_buf_pro_t *buf_pro = (umq_buf_pro_t *)ctx_buf->qbuf_ext;
    umq_ub_imm_t imm_temp = {.ub_plus = {.umq_private = UMQ_UB_IMM_PRIVATE,
                                         .type = IMM_TYPE_UB_PLUS,
                                         .sub_type = IMM_TYPE_REVERSE_PULL_MEM_DONE}};
    buf_pro->imm_data = imm_temp.value;
    user_ctx_t *user_ctx = (user_ctx_t *)ctx_buf->buf_data;

    uint32_t total_size = umq_ub_get_read_pre_allocate_max_total_size(umq_imm_head->mem_interval, buf_num);
    if (total_size == UINT32_MAX) {
        umq_buf_free(ctx_buf);
        UMQ_LIMIT_VLOG_ERR("get total data size failed\n");
        return NULL;
    }

    user_ctx->dst_buf = umq_buf_alloc(total_size, 1, UMQ_INVALID_HANDLE, NULL);
    if (user_ctx->dst_buf == NULL) {
        umq_buf_free(ctx_buf);
        UMQ_LIMIT_VLOG_ERR("dst_buf malloc failed\n");
        return NULL;
    }

    user_ctx->wr_total = buf_num;
    user_ctx->msg_id = msg_id;
    user_ctx->wr_cnt = 0;
    return ctx_buf;
}

static ALWAYS_INLINE int umq_ub_import_mem_done(ub_queue_t *queue, uint16_t mempool_id)
{
    umq_ub_imm_t imm = { .mem_import ={ .umq_private = UMQ_UB_IMM_PRIVATE,
        .type = IMM_TYPE_MEM, .sub_type = IMM_TYPE_MEM_IMPORT_DONE, .mempool_id = mempool_id} };
    uint16_t max_tx = umq_ub_window_dec(&queue->flow_control, queue, 1);
    if (max_tx == 0) {
        UMQ_LIMIT_VLOG_ERR("flow control window lack\n");
        return -UMQ_ERR_EAGAIN;
    }
    int ret = umq_ub_write_imm((uint64_t)(uintptr_t)queue, queue->bind_ctx->remote_notify_addr, 1, imm.value);
    if (ret != UMQ_SUCCESS) {
        umq_ub_window_inc(&queue->flow_control, max_tx);
    }
    return ret;
}

// The rx buf contains metadata including the IMM header, reference SGE and import memory details.
int umq_ub_data_plan_import_mem(uint64_t umqh_tp, umq_buf_t *rx_buf, uint32_t ref_seg_num)
{
    umq_imm_head_t *umq_imm_head = (umq_imm_head_t *)rx_buf->buf_data;
    if (umq_imm_head->type == IMM_PROTOCAL_TYPE_NONE) {
        return UMQ_SUCCESS;
    }

    if (umq_imm_head->mempool_num >= UMQ_MAX_TSEG_NUM) {
        UMQ_LIMIT_VLOG_INFO("mempool num invalid, mempool_num %u\n", umq_imm_head->mempool_num);
        return -UMQ_ERR_EINVAL;
    }

    ub_queue_t *queue = (ub_queue_t *)(uintptr_t)umqh_tp;
    if (queue->bind_ctx == NULL) {
        UMQ_LIMIT_VLOG_INFO("The queue has been unbound\n");
        return -UMQ_ERR_EINVAL;
    }

    pthread_mutex_t *imported_tseg_list_mutex_lock =
        &queue->dev_ctx->remote_imported_info->imported_tseg_list_mutex[queue->bind_ctx->remote_eid_id];
    pthread_mutex_lock(imported_tseg_list_mutex_lock);
    ub_import_mempool_info_t *import_mempool_info = (ub_import_mempool_info_t *)
            (rx_buf->buf_data + sizeof(umq_imm_head_t) + ref_seg_num * sizeof(ub_ref_sge_t));
    for (uint32_t i = 0; i < umq_imm_head->mempool_num; i++) {
        if (import_mempool_info[i].mempool_id >= UMQ_MAX_TSEG_NUM) {
            pthread_mutex_unlock(imported_tseg_list_mutex_lock);
            UMQ_LIMIT_VLOG_INFO("mempool id %u invalid\n", import_mempool_info[i].mempool_id);
            return -UMQ_ERR_EINVAL;
        }

        if (queue->imported_tseg_list[import_mempool_info[i].mempool_id] != NULL) {
            UMQ_LIMIT_VLOG_INFO("mempool %u has been imported\n", import_mempool_info[i].mempool_id);
            (void)umq_ub_import_mem_done(queue, import_mempool_info[i].mempool_id);
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
            pthread_mutex_unlock(imported_tseg_list_mutex_lock);
            UMQ_LIMIT_VLOG_ERR("import memory failed\n");
            return UMQ_FAIL;
        }

        if (umq_ub_import_mem_done(queue, import_mempool_info[i].mempool_id) != UMQ_SUCCESS) {
            // send import mem done failed not cause the data plane to be unavailable
            UMQ_LIMIT_VLOG_WARN("send import mem done imm failed\n");
        }
        queue->dev_ctx->remote_imported_info->
            imported_tseg_list[queue->bind_ctx->remote_eid_id][import_mempool_info[i].mempool_id] = imported_tseg;
    }
    pthread_mutex_unlock(imported_tseg_list_mutex_lock);
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
        .tjetty = queue->bind_ctx->tjetty};

    urma_jfs_wr_t *bad_wr = NULL;
    uint64_t start_timestamp = umq_perf_get_start_timestamp_with_feature(queue->dev_ctx->feature);
    urma_status_t status = urma_post_jetty_send_wr(queue->jetty, &urma_wr, &bad_wr);
    umq_perf_record_write_with_feature(UMQ_PERF_RECORD_TRANSPORT_READ, start_timestamp, queue->dev_ctx->feature);
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
    if (queue->bind_ctx == NULL) {
        UMQ_LIMIT_VLOG_ERR("umq has not been binded\n");
        return -UMQ_ERR_ENODEV;
    }

    uint16_t buf_num = imm.ub_plus.msg_num;
    uint16_t msg_id = imm.ub_plus.msg_id;
    umq_imm_head_t *umq_imm_head = (umq_imm_head_t *)(uintptr_t)rx_buf->buf_data;
    ub_ref_sge_t *ref_sge = (ub_ref_sge_t *)(uintptr_t)(umq_imm_head + 1);
    umq_buf_t *ctx_buf = umq_ub_read_ctx_create(queue, umq_imm_head, buf_num, msg_id);
    if (ctx_buf == NULL) {
        UMQ_LIMIT_VLOG_ERR("create ctx buf failed\n");
        return -UMQ_ERR_ENOMEM;
    }

    urma_target_seg_t **tseg_list = queue->dev_ctx->tseg_list;
    user_ctx_t *user_ctx = (user_ctx_t *)ctx_buf->buf_data;
    umq_buf_t *dst_buf = user_ctx->dst_buf;
    umq_buf_t *tmp_buf = dst_buf;
    urma_sge_t src_sge[buf_num];
    urma_sge_t dst_sge[buf_num];
    uint32_t total_data_size = 0;
    uint32_t src_buf_length = 0;
    for (uint32_t i = 0; i < buf_num; i++) {
        src_buf_length = ref_sge[i].length;

        dst_sge[i].addr = (uint64_t)(uintptr_t)tmp_buf->buf_data;
        dst_sge[i].len = src_buf_length;
        dst_sge[i].user_tseg = NULL;
        dst_sge[i].tseg = tseg_list[tmp_buf->mempool_id];

        src_sge[i].addr = ref_sge[i].addr;
        src_sge[i].len = src_buf_length;
        src_sge[i].tseg = queue->imported_tseg_list[ref_sge[i].mempool_id];
        if (src_sge[i].tseg == NULL) {
            UMQ_LIMIT_VLOG_ERR("imported memory handle not exist\n");
            goto FREE_CTX_BUF;
        }

        tmp_buf->data_size = src_buf_length;
        tmp_buf = QBUF_LIST_NEXT(tmp_buf);
        total_data_size += src_buf_length;

        urma_status_t status = umq_ub_read_post_send(queue, src_sge + i, dst_sge + i, ctx_buf);
        if (status != URMA_SUCCESS) {
            umq_dec_ref(queue->dev_ctx->io_lock_free, &queue->ref_cnt, 1);
            UMQ_LIMIT_VLOG_ERR("urma_post_jetty_send_wr failed, status %d, local eid: " EID_FMT ", "
                               "local jetty_id: %u, remote eid: " EID_FMT ", remote jetty_id: %u\n", (int)status,
                               EID_ARGS(queue->jetty->jetty_id.eid), queue->jetty->jetty_id.id,
                               EID_ARGS(queue->bind_ctx->tjetty->id.eid), queue->bind_ctx->tjetty->id.id);
            if (i == 0) {
                goto FREE_CTX_BUF;
            } else {
                return -status;
            }
        }
    }
    dst_buf->total_data_size = total_data_size;
    umq_inc_ref(queue->dev_ctx->io_lock_free, &queue->tx_outstanding, buf_num);
    return UMQ_SUCCESS;

FREE_CTX_BUF:
    umq_ub_read_ctx_destroy(ctx_buf);
    return UMQ_FAIL;
}

static int process_send_imm(umq_buf_t *rx_buf, umq_ub_imm_t imm, uint64_t umqh)
{
    int ret = 0;
    if (imm.bs.umq_private == 0) {
        umq_buf_pro_t *buf_pro = (umq_buf_pro_t *)rx_buf->qbuf_ext;
        buf_pro->imm_data = imm.value;
        return UMQ_SUCCESS;
    }
    if (imm.bs.type != IMM_TYPE_UB_PLUS) {
        return ret;
    }
    if (imm.ub_plus.sub_type == IMM_TYPE_REVERSE_PULL_MEM) {
        if (umq_ub_data_plan_import_mem(umqh, rx_buf, imm.ub_plus.msg_num) != UMQ_SUCCESS) {
            UMQ_LIMIT_VLOG_ERR("import mem failed\n");
            umq_buf_free(rx_buf); // release rx
            return UMQ_CONTINUE_FLAG;
        }

        if (umq_ub_read(umqh, rx_buf, imm) != UMQ_SUCCESS) {
            UMQ_LIMIT_VLOG_ERR("umq ub send read failed\n");
        }
        umq_buf_free(rx_buf); // release rx
        ret = UMQ_CONTINUE_FLAG;
    } else if (imm.ub_plus.sub_type == IMM_TYPE_REVERSE_PULL_MEM_FREE) {
        uint16_t msg_id = (uint16_t)(imm.ub_plus.msg_id);
        if (msg_id != 0) {
            ub_queue_t *queue = (ub_queue_t *)(uintptr_t)umqh;
            umq_buf_t *buffer = (umq_buf_t *)queue->addr_list[msg_id];
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
    int ret = 0;
    if (imm.bs.umq_private == 0) {
        umq_buf_pro_t *buf_pro = (umq_buf_pro_t *)(uintptr_t)rx_buf->qbuf_ext;
        buf_pro->imm_data = imm.value;
    } else if (imm.bs.type == IMM_TYPE_MEM && imm.mem_import.sub_type == IMM_TYPE_MEM_IMPORT_DONE) {
        ub_queue_t *queue = (ub_queue_t *)(uintptr_t)umqh;
        queue->dev_ctx->remote_imported_info->
            tesg_imported[queue->bind_ctx->remote_eid_id][imm.mem_import.mempool_id] = true;
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
    umq_ub_imm_t imm = {.ub_plus = {.umq_private = UMQ_UB_IMM_PRIVATE,
                                    .type = IMM_TYPE_UB_PLUS,
                                    .sub_type = IMM_TYPE_REVERSE_PULL_MEM_FREE,
                                    .msg_id = msg_id}};

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
        if (umq_ub_read_done(queue, user_ctx->msg_id) != UMQ_SUCCESS) {
            UMQ_LIMIT_VLOG_ERR("umq ub send imm failed\n");
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
    int tx_cr_cnt = urma_poll_jfc(queue->jfs_jfc, UMQ_POST_POLL_BATCH, cr);
    if (tx_cr_cnt < 0) {
        UMQ_LIMIT_VLOG_ERR("UB TX reports tx_cr_cnt[%d]\n", tx_cr_cnt);
        return return_rx_cnt;
    }
    int qbuf_cnt = 0;
    for (int i = 0; i < tx_cr_cnt; i++) {
        if (cr[i].status != URMA_CR_SUCCESS) {
            UMQ_LIMIT_VLOG_ERR("UB TX reports cr[%d] status[%d]\n", i, cr[i].status);
            if (cr[i].status == URMA_CR_WR_FLUSH_ERR_DONE) {
                if (queue->state == QUEUE_STATE_ERR) {
                    queue->tx_flush_done = true;
                }
                continue;
            }
            if (cr[i].status == URMA_CR_WR_SUSPEND_DONE) {
                continue;
            }
        }
        if (cr[i].user_ctx == 0) {
            if (cr[i].opcode == URMA_CR_OPC_SEND_WITH_IMM) {
                umq_dec_ref(queue->dev_ctx->io_lock_free, &queue->tx_outstanding, 1);
            }
            continue;
        }
        umq_dec_ref(queue->dev_ctx->io_lock_free, &queue->tx_outstanding, 1);
        tx_buf[qbuf_cnt] = (umq_buf_t *)(uintptr_t)cr[i].user_ctx;
        umq_buf_pro_t *buf_pro = (umq_buf_pro_t *)(tx_buf[qbuf_cnt])->qbuf_ext;
        umq_ub_imm_t imm = {.value = buf_pro->imm_data};
        if (imm.bs.type == IMM_TYPE_UB_PLUS && imm.bs.umq_private == UMQ_UB_IMM_PRIVATE &&
            imm.ub_plus.sub_type == IMM_TYPE_REVERSE_PULL_MEM_DONE) {
            umq_ub_rev_pull_tx_cqe(queue, tx_buf[qbuf_cnt], buf, &qbuf_cnt, &return_rx_cnt);
            continue;
        }
        umq_ub_non_rev_pull_tx_cqe(queue, tx_buf[qbuf_cnt], &qbuf_cnt);
    }
    return return_rx_cnt;
}

static inline uint32_t get_mem_interval(uint32_t used_mem_size)
{
    if (used_mem_size <= umq_buf_size_small()) {
        return UMQ_SIZE_0K_SMALL_INTERVAL;
    } else if (used_mem_size <= umq_buf_size_middle()) {
        return UMQ_SIZE_SMALL_MID_INTERVAL;
    } else if (used_mem_size <= umq_buf_size_big()) {
        return UMQ_SIZE_MID_BIG_INTERVAL;
    }
    return UMQ_SIZE_BIG_HUGE_INTERVAL;
}

void ub_fill_umq_imm_head(umq_imm_head_t *umq_imm_head, umq_buf_t *buffer)
{
    umq_imm_head->version = UMQ_IMM_VERSION;
    umq_imm_head->type = IMM_PROTOCAL_TYPE_NONE;
    umq_imm_head->mempool_num = 0;
    umq_imm_head->mem_interval = get_mem_interval(buffer->data_size);
}

void fill_big_data_ref_sge(ub_queue_t *queue, ub_ref_sge_t *ref_sge,
    umq_buf_t *buffer, ub_import_mempool_info_t *import_mempool_info, umq_imm_head_t *umq_imm_head)
{
    urma_target_seg_t *tseg = queue->dev_ctx->tseg_list[buffer->mempool_id];
    urma_seg_t *seg = &tseg->seg;
    if (!queue->dev_ctx->remote_imported_info->tesg_imported[queue->bind_ctx->remote_eid_id][buffer->mempool_id]) {
        umq_imm_head->type = IMM_PROTOCAL_TYPE_IMPORT_MEM;
        umq_imm_head->mempool_num++;
        import_mempool_info->mempool_seg_flag = seg->attr.value;
        import_mempool_info->mempool_length = seg->len;
        import_mempool_info->mempool_token_id = seg->token_id;
        import_mempool_info->mempool_id = buffer->mempool_id;
        import_mempool_info->mempool_token_value = tseg->user_ctx;
        (void)memcpy(import_mempool_info->mempool_ubva, &seg->ubva, sizeof(urma_ubva_t));
    }

    ref_sge->addr = (uint64_t)(uintptr_t)buffer->buf_data;
    ref_sge->length = buffer->data_size;
    ref_sge->token_id = seg->token_id;
    ref_sge->mempool_id = buffer->mempool_id;
    ref_sge->token_value = tseg->user_ctx;
}


static int umq_ub_send_big_data(ub_queue_t *queue, umq_buf_t **buffer)
{
    // apply for one to avoid memory leak
    umq_buf_t *send_buf = umq_buf_alloc(umq_buf_size_small(), UMQ_MAX_QBUF_NUM, UMQ_INVALID_HANDLE, NULL);
    if (send_buf == NULL) {
        UMQ_LIMIT_VLOG_ERR("umq malloc failed\n");
        return -UMQ_ERR_ENOMEM;
    }
    // In the tx direction, user_ctx needs to initialize imm data ub_plus type
    umq_buf_pro_t *buf_pro = (umq_buf_pro_t *)send_buf->qbuf_ext;
    umq_ub_imm_t imm_temp = {
        .ub_plus = {.umq_private = UMQ_UB_IMM_PRIVATE, .type = IMM_TYPE_UB_PLUS, .sub_type = IMM_TYPE_UB_PLUS_DEFAULT}
    };
    buf_pro->imm_data = imm_temp.value;
    uint16_t msg_id = util_id_allocator_get(&g_umq_ub_id_allocator);
    queue->addr_list[msg_id] = (uint64_t)(uintptr_t)(*buffer);

    umq_imm_head_t *umq_imm_head = (umq_imm_head_t *)(uintptr_t)send_buf->buf_data;
    ub_fill_umq_imm_head(umq_imm_head, *buffer);
    ub_ref_sge_t *ref_sge = (ub_ref_sge_t *)(uintptr_t)(umq_imm_head + 1);

    ub_import_mempool_info_t import_mempool_info[UMQ_MAX_TSEG_NUM];
    uint32_t rest_size = (*buffer)->total_data_size;
    int32_t buf_index = 0;
    uint16_t ref_sge_num = (umq_buf_size_small() - sizeof(umq_imm_head_t)) / sizeof(ub_ref_sge_t);
    urma_sge_t sge;
    uint32_t max_data_size = 0;
    while ((*buffer) && rest_size != 0) {
        if (rest_size < (*buffer)->data_size) {
            UMQ_LIMIT_VLOG_ERR("remaining size[%u] is smaller than data_size[%u]\n", rest_size, (*buffer)->data_size);
            goto FREE_BUF;
        }

        if (buf_index == ref_sge_num) {
            UMQ_LIMIT_VLOG_ERR("the buf num [%d] exceeds the maximum limit [%u]\n", buf_index, (uint32_t)ref_sge_num);
            goto FREE_BUF;
        }

        fill_big_data_ref_sge(
            queue, &ref_sge[buf_index], *buffer, &import_mempool_info[umq_imm_head->mempool_num], umq_imm_head);

        max_data_size =  (*buffer)->data_size > max_data_size ? (*buffer)->data_size : max_data_size;
        rest_size -= (*buffer)->data_size;
        (*buffer) = QBUF_LIST_NEXT((*buffer));
        ++buf_index;
    }

    if (umq_imm_head->type == IMM_PROTOCAL_TYPE_IMPORT_MEM) {
        if ((sizeof(umq_imm_head_t) + sizeof(ub_ref_sge_t) * buf_index +
                sizeof(ub_import_mempool_info_t) * umq_imm_head->mempool_num) >
            (umq_buf_size_small() * UMQ_MAX_QBUF_NUM)) {
            UMQ_LIMIT_VLOG_ERR("import mempool info is not enough\n");
            goto FREE_BUF;
        }
        (void)memcpy(ref_sge + buf_index,
            import_mempool_info, sizeof(ub_import_mempool_info_t) * umq_imm_head->mempool_num);
    }
    umq_imm_head->mem_interval = get_mem_interval(max_data_size);

    uint64_t user_ctx = (uint64_t)(uintptr_t)send_buf;
    sge.addr = (uint64_t)(uintptr_t)send_buf->buf_data;
    sge.len = sizeof(umq_imm_head_t) +
        buf_index * sizeof(ub_ref_sge_t) + umq_imm_head->mempool_num * sizeof(ub_import_mempool_info_t);
    sge.tseg = queue->dev_ctx->tseg_list[send_buf->mempool_id];
    umq_ub_imm_t imm = {.ub_plus = {.umq_private = UMQ_UB_IMM_PRIVATE,
                                    .type = IMM_TYPE_UB_PLUS,
                                    .sub_type = IMM_TYPE_REVERSE_PULL_MEM,
                                    .msg_id = msg_id,
                                    .msg_num = (uint16_t)buf_index}};
    int ret = umq_ub_send_imm(queue, imm.value, &sge, user_ctx);
    if (ret != UMQ_SUCCESS) {
        umq_buf_free(send_buf);
        UMQ_LIMIT_VLOG_ERR("umq_ub_send_imm failed\n");
        return ret;
    }
    return UMQ_SUCCESS;

FREE_BUF:
    umq_buf_free(send_buf);
    return UMQ_FAIL;
}

int umq_ub_plus_fill_wr_impl(umq_buf_t *qbuf, ub_queue_t *queue, urma_jfs_wr_t *urma_wr_ptr, uint32_t remain_tx)
{
    uint32_t max_sge_num = queue->max_tx_sge;
    urma_sge_t sges[UMQ_POST_POLL_BATCH][max_sge_num];
    urma_target_jetty_t *tjetty = queue->bind_ctx->tjetty;
    urma_sge_t *sges_ptr;
    umq_buf_t *buffer = qbuf;
    uint32_t wr_index = 0;
    urma_target_seg_t **tseg_list = queue->dev_ctx->tseg_list;
    uint32_t remote_rx_buf_size = queue->remote_rx_buf_size;
    uint32_t sge_num = 0;

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
                UMQ_LIMIT_VLOG_ERR("send big data failed\n");
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
            UMQ_LIMIT_VLOG_ERR("total data size[%u] exceed max tx size[%u]\n", rest_size, queue->tx_buf_size);
            return -UMQ_ERR_EINVAL;
        }
        sges_ptr = sges[wr_index];
        sge_num = 0;
        uint64_t user_ctx = (uint64_t)(uintptr_t)buffer;
        while (buffer && rest_size > 0) { // try to add up to total_size
            if (sge_num++ >= max_sge_num) {
                UMQ_LIMIT_VLOG_ERR("sge num exceed max sge num[%u]\n", max_sge_num);
                return -UMQ_ERR_EINVAL;
            }
            sges_ptr->addr = (uint64_t)(uintptr_t)buffer->buf_data;
            sges_ptr->len = buffer->data_size;
            sges_ptr->user_tseg = NULL;
            sges_ptr->tseg = tseg_list[buffer->mempool_id];
            sges_ptr++;

            if (rest_size < buffer->data_size) { // if cannot add up to total_size, return fail
                UMQ_LIMIT_VLOG_ERR("cannot put together tx buffer, rest size is negative\n");
                return -UMQ_ERR_EINVAL;
            }

            rest_size -= buffer->data_size;
            buffer = QBUF_LIST_NEXT(buffer);
        }
        if (rest_size != 0) { // if cannot add up to total_size, return fail
            UMQ_LIMIT_VLOG_ERR("cannot put together enough tx buffer\n");
            return -UMQ_ERR_ENOMEM;
        }

        urma_wr_ptr->user_ctx = user_ctx;
        urma_wr_ptr->send.src.sge = sges[wr_index];
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
            UMQ_LIMIT_VLOG_ERR("wr count %u exceeds remain_tx %u or max_post_size %d, not supported\n", wr_index,
                               remain_tx, UMQ_POST_POLL_BATCH);
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
    if (!queue->tx_flush_done || queue->rx_flush_done ||
        queue->state != QUEUE_STATE_ERR || queue->jfr_ctx->jfr->jfr_cfg.trans_mode != URMA_TM_RC) {
        return buf_cnt;
    }
    rx_buf_ctx_t *rx_buf_ctx;
    for (; buf_cnt < max_rx_ctx; buf_cnt++) {
        rx_buf_ctx = queue_rx_buf_ctx_flush(&queue->jfr_ctx->rx_buf_ctx_list);
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
    atomic_fetch_add_explicit(&queue->require_rx_count, rx_cnt, memory_order_relaxed);
    uint32_t require_rx_count = umq_get_post_rx_num(queue->rx_depth, &queue->require_rx_count);
    if (require_rx_count > 0) {
        umq_buf_list_t head;
        uint32_t cur_batch_count = 0;
        do {
            cur_batch_count = require_rx_count > UMQ_POST_POLL_BATCH ? UMQ_POST_POLL_BATCH : require_rx_count;
            QBUF_LIST_INIT(&head);
            if (umq_qbuf_alloc(queue->rx_buf_size, cur_batch_count, NULL, &head) != UMQ_SUCCESS) {
                atomic_fetch_add_explicit(&queue->require_rx_count, cur_batch_count, memory_order_relaxed);
                UMQ_LIMIT_VLOG_ERR("alloc rx failed\n");
                break;
            }
            umq_buf_t *bad_buf = NULL;
            if (umq_ub_post_rx_inner_impl(queue, QBUF_LIST_FIRST(&head), &bad_buf) != UMQ_SUCCESS) {
                UMQ_LIMIT_VLOG_ERR("post rx failed\n");
                QBUF_LIST_FIRST(&head) = bad_buf;
                uint32_t fail_count = 0;
                while (bad_buf) {
                    fail_count++;
                    bad_buf = bad_buf->qbuf_next;
                }
                umq_qbuf_free(&head);
                atomic_fetch_add_explicit(&queue->require_rx_count, fail_count, memory_order_relaxed);
                break;
            }
            require_rx_count -= cur_batch_count;
        } while (require_rx_count > 0);
    }
}

static inline umq_buf_t *umq_get_buf_by_user_ctx(ub_queue_t *queue, uint64_t user_ctx)
{
    rx_buf_ctx_t *rx_buf_ctx = (rx_buf_ctx_t *)(uintptr_t)user_ctx;
    umq_buf_t *buf = rx_buf_ctx->buffer;
    urpc_list_remove(&rx_buf_ctx->node);
    urpc_list_push_back(&queue->jfr_ctx->rx_buf_ctx_list.idle_rx_buf_ctx_list, &rx_buf_ctx->node);
    return buf;
}

int umq_ub_dequeue_with_poll_rx(ub_queue_t *queue, urma_cr_t *cr, umq_buf_t **buf)
{
    int qbuf_cnt = 0;
    // merge rx buffer
    umq_buf_t *previous_last = NULL;
    if (queue->state == QUEUE_STATE_ERR) {
        return umq_report_incomplete_and_merge_rx(queue, UMQ_POST_POLL_BATCH, buf, &previous_last);
    }

    int rx_cr_cnt = urma_poll_jfc(queue->jfr_ctx->jfr_jfc, UMQ_POST_POLL_BATCH, cr);
    if (rx_cr_cnt < 0) {
        UMQ_LIMIT_VLOG_ERR("UB RX reports rx_cr_cnt[%d]\n", rx_cr_cnt);
        return rx_cr_cnt;
    }

    for (int i = 0; i < rx_cr_cnt; i++) {
        buf[i] = umq_get_buf_by_user_ctx(queue, cr[i].user_ctx);
        buf[i]->io_direction = UMQ_IO_RX;
        buf[i]->status = (umq_buf_status_t)cr[i].status;
        if (cr[i].status != URMA_CR_SUCCESS) {
            UMQ_LIMIT_VLOG_ERR("UB RX reports cr[%d] status[%d]\n", i, cr[i].status);
        } else {
            umq_buf_t *tmp_buf = buf[i];
            uint32_t total_data_size = cr[i].completion_len;
            tmp_buf->total_data_size = total_data_size;
            while (tmp_buf != NULL && total_data_size > 0) {
                tmp_buf->data_size = total_data_size > tmp_buf->data_size ? tmp_buf->data_size : total_data_size;
                total_data_size -= tmp_buf->data_size;
                tmp_buf = tmp_buf->qbuf_next;
            }
        }
        umq_ub_merge_rx_buffer(buf[i], &previous_last);
        qbuf_cnt++;
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
    int rx_cr_cnt = urma_poll_jfc(queue->jfr_ctx->jfr_jfc, UMQ_POST_POLL_BATCH, cr);
    if (rx_cr_cnt < 0) {
        UMQ_LIMIT_VLOG_ERR("UB RX reports rx_cr_cnt[%d]\n", rx_cr_cnt);
        return rx_cr_cnt;
    }

    for (int i = 0; i < rx_cr_cnt; i++) {
        buf[qbuf_cnt] = umq_get_buf_by_user_ctx(queue, cr[i].user_ctx);
        if (process_imm_msg(umqh_tp, buf[qbuf_cnt], cr + i) == UMQ_CONTINUE_FLAG) {
            continue;
        }
        buf[qbuf_cnt]->io_direction = UMQ_IO_RX;
        buf[qbuf_cnt]->status = (umq_buf_status_t)cr[i].status;
        if (cr[i].status != URMA_CR_SUCCESS) {
            UMQ_LIMIT_VLOG_ERR("UB RX reports cr[%d] status[%d]\n", i, cr[i].status);
        } else {
            umq_buf_t *tmp_buf = buf[qbuf_cnt];
            uint32_t total_data_size = cr[i].completion_len;
            tmp_buf->total_data_size = total_data_size;
            while (tmp_buf != NULL && total_data_size > 0) {
                tmp_buf->data_size = total_data_size > tmp_buf->data_size ? tmp_buf->data_size : total_data_size;
                total_data_size -= tmp_buf->data_size;
                tmp_buf = tmp_buf->qbuf_next;
            }
        }
        umq_ub_merge_rx_buffer(buf[qbuf_cnt], &previous_last);
        ++qbuf_cnt;
    }
    if (rx_cr_cnt != 0) {
        umq_ub_fill_rx_buffer(queue, rx_cr_cnt);
    }
    return qbuf_cnt;
}

void process_bad_qbuf(urma_jfs_wr_t *bad_wr, umq_buf_t **bad_qbuf, umq_buf_t *qbuf, ub_queue_t *queue)
{
    *bad_qbuf = (umq_buf_t *)(uintptr_t)bad_wr->user_ctx;
    umq_buf_t *tmp_qbuf = qbuf;
    uint32_t count = 0;
    umq_buf_t *previous = NULL;
    while (tmp_qbuf != NULL && tmp_qbuf != *bad_qbuf) {
        count++;
        previous = tmp_qbuf;
        tmp_qbuf = tmp_qbuf->qbuf_next;
    }
    if (previous) {
        // break chain of succeed qbuf and failed qbuf on tx
        previous->qbuf_next = NULL;
    }
    umq_inc_ref(queue->dev_ctx->io_lock_free, &queue->tx_outstanding, count);
}

void umq_ub_enqueue_with_poll_tx(ub_queue_t *queue, umq_buf_t **buf)
{
    urma_cr_t cr[UMQ_POST_POLL_BATCH];
    int tx_cr_cnt = urma_poll_jfc(queue->jfs_jfc, UMQ_POST_POLL_BATCH, cr);
    if (tx_cr_cnt < 0) {
        UMQ_LIMIT_VLOG_ERR("UB TX reports tx_cr_cnt[%d]\n", tx_cr_cnt);
        return;
    }

    int32_t qbuf_cnt = 0;
    for (int i = 0; i < tx_cr_cnt; i++) {
        if (cr[i].status != URMA_CR_SUCCESS) {
            UMQ_LIMIT_VLOG_ERR("UB TX reports cr[%d] status[%d]\n", i, cr[i].status);
            if (cr[i].status == URMA_CR_WR_FLUSH_ERR_DONE) {
                if (queue->state == QUEUE_STATE_ERR) {
                    queue->tx_flush_done = true;
                }
                continue;
            }
            if (cr[i].status == URMA_CR_WR_SUSPEND_DONE) {
                continue;
            }
        }

        if (cr[i].user_ctx == 0) {
            continue;
        }
        buf[qbuf_cnt] = (umq_buf_t *)(uintptr_t)cr[i].user_ctx;
        (void)umq_buf_break_and_free(buf[qbuf_cnt]);
        ++qbuf_cnt;
    }
    umq_dec_ref(queue->dev_ctx->io_lock_free, &queue->tx_outstanding, qbuf_cnt);
}

void umq_ub_enqueue_plus_with_poll_tx(ub_queue_t *queue, umq_buf_t **buf)
{
    urma_cr_t cr[UMQ_POST_POLL_BATCH];
    int tx_cr_cnt = urma_poll_jfc(queue->jfs_jfc, UMQ_POST_POLL_BATCH, cr);
    if (tx_cr_cnt < 0) {
        UMQ_LIMIT_VLOG_ERR("UB TX reports tx_cr_cnt[%d]\n", tx_cr_cnt);
        return;
    }

    int32_t qbuf_cnt = 0;
    for (int i = 0; i < tx_cr_cnt; i++) {
        if (cr[i].status != URMA_CR_SUCCESS) {
            UMQ_LIMIT_VLOG_ERR("UB TX reports cr[%d] status[%d]\n", i, cr[i].status);
            if (cr[i].status == URMA_CR_WR_FLUSH_ERR_DONE) {
                if (queue->state == QUEUE_STATE_ERR) {
                    queue->tx_flush_done = true;
                }
                continue;
            }
            if (cr[i].status == URMA_CR_WR_SUSPEND_DONE) {
                continue;
            }
        }

        if (cr[i].user_ctx == 0) {
            if (cr[i].opcode == URMA_CR_OPC_SEND_WITH_IMM) {
                umq_dec_ref(queue->dev_ctx->io_lock_free, &queue->tx_outstanding, 1);
            }
            continue;
        }
        umq_dec_ref(queue->dev_ctx->io_lock_free, &queue->tx_outstanding, 1);
        buf[qbuf_cnt] = (umq_buf_t *)(uintptr_t)cr[i].user_ctx;
        buf[qbuf_cnt]->io_direction = UMQ_IO_TX;
        buf[qbuf_cnt]->status = (umq_buf_status_t)cr[i].status;
        umq_buf_pro_t *buf_pro = (umq_buf_pro_t *)buf[qbuf_cnt]->qbuf_ext;
        umq_ub_imm_t imm = {.value = buf_pro->imm_data};
        if (imm.bs.type == IMM_TYPE_UB_PLUS && imm.ub_plus.sub_type == IMM_TYPE_REVERSE_PULL_MEM_DONE) {
            user_ctx_t *user_ctx = (user_ctx_t *)buf[qbuf_cnt]->buf_data;
            user_ctx->wr_cnt++;
            if (user_ctx->wr_cnt == user_ctx->wr_total) {
                if (umq_ub_read_done(queue, user_ctx->msg_id) != UMQ_SUCCESS) {
                    UMQ_LIMIT_VLOG_ERR("umq ub send imm failed\n");
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
}

int umq_ub_send_imm(ub_queue_t *queue, uint64_t imm_value, urma_sge_t *sge, uint64_t user_ctx)
{
    if (queue->bind_ctx == NULL) {
        UMQ_LIMIT_VLOG_ERR("umq has not been binded\n");
        return -UMQ_ERR_ENODEV;
    }

    urma_jfs_wr_t urma_wr = {
        .send = {.src = {.sge = sge, .num_sge = 1}, .imm_data = imm_value },
        .user_ctx = user_ctx,
        .flag = { .bs = { .complete_enable = 1, .inline_flag = 0, } },
        .tjetty = queue->bind_ctx->tjetty,
        .opcode = URMA_OPC_SEND_IMM};
    urma_jfs_wr_t *bad_wr = NULL;
    uint64_t start_timestamp = umq_perf_get_start_timestamp_with_feature(queue->dev_ctx->feature);
    urma_status_t status = urma_post_jetty_send_wr(queue->jetty, &urma_wr, &bad_wr);
    umq_perf_record_write_with_feature(UMQ_PERF_RECORD_TRANSPORT_SEND_IMM, start_timestamp, queue->dev_ctx->feature);
    if (status != URMA_SUCCESS) {
        umq_dec_ref(queue->dev_ctx->io_lock_free, &queue->ref_cnt, 1);
        UMQ_LIMIT_VLOG_ERR("urma_post_jetty_send_wr failed, status %d, local eid: " EID_FMT ", "
                           "local jetty_id: %u, remote eid: " EID_FMT ", remote jetty_id: %u\n", (int)status,
                           EID_ARGS(queue->jetty->jetty_id.eid), queue->jetty->jetty_id.id,
                           EID_ARGS(queue->bind_ctx->tjetty->id.eid), queue->bind_ctx->tjetty->id.id);
        return -status;
    }
    umq_inc_ref(queue->dev_ctx->io_lock_free, &queue->tx_outstanding, 1);
    return UMQ_SUCCESS;
}

int umq_ub_write_imm(uint64_t umqh_tp, uint64_t target_addr, uint32_t len, uint64_t imm_value)
{
    ub_queue_t *queue = (ub_queue_t *)(uintptr_t)umqh_tp;
    if (queue->bind_ctx == NULL) {
        UMQ_LIMIT_VLOG_ERR("umq has not been binded\n");
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
        .tjetty = queue->bind_ctx->tjetty,
        .user_ctx = UINT16_MAX,     // do not report TX events
        .rw = {
            .src = {.sge = &src_sge, .num_sge = 1},
            .dst = {.sge = &dst_sge, .num_sge = 1},
            .notify_data = imm_value, },
        .next = NULL
    };

    urma_jfs_wr_t *bad_wr = NULL;
    uint64_t start_timestamp = umq_perf_get_start_timestamp_with_feature(queue->dev_ctx->feature);
    urma_status_t status = urma_post_jetty_send_wr(queue->jetty, &urma_wr, &bad_wr);
    umq_perf_record_write_with_feature(UMQ_PERF_RECORD_TRANSPORT_WRITE_IMM, start_timestamp, queue->dev_ctx->feature);
    if (status != URMA_SUCCESS) {
        UMQ_LIMIT_VLOG_ERR("urma_post_jetty_send_wr failed, status %d, local eid: " EID_FMT ", "
                           "local jetty_id: %u, remote eid: " EID_FMT ", remote jetty_id: %u\n", (int)status,
                           EID_ARGS(queue->jetty->jetty_id.eid), queue->jetty->jetty_id.id,
                           EID_ARGS(queue->bind_ctx->tjetty->id.eid), queue->bind_ctx->tjetty->id.id);
        return -status;
    }
    return UMQ_SUCCESS;
}

int umq_ub_fill_wr_impl(umq_buf_t *qbuf, ub_queue_t *queue, urma_jfs_wr_t *urma_wr_ptr, uint32_t remain_tx)
{
    uint32_t max_sge_num = queue->max_tx_sge;
    urma_sge_t sges[UMQ_POST_POLL_BATCH][max_sge_num];
    urma_target_jetty_t *tjetty = queue->bind_ctx->tjetty;
    urma_sge_t *sges_ptr;
    umq_buf_t *buffer = qbuf;
    uint32_t wr_index = 0;
    urma_target_seg_t **tseg_list = queue->dev_ctx->tseg_list;
    uint32_t max_send_size =
        (queue->remote_rx_buf_size > queue->tx_buf_size) ? queue->tx_buf_size : queue->remote_rx_buf_size;
    uint32_t sge_num = 0;

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
            UMQ_LIMIT_VLOG_ERR("total data size[%u] exceed max_send_size[%u]\n", rest_size, max_send_size);
            return -UMQ_ERR_EINVAL;
        }
        sges_ptr = sges[wr_index];
        uint64_t user_ctx = (uint64_t)(uintptr_t)buffer;
        sge_num = 0;
        while (buffer && rest_size > 0) { // try to add up to total_size
            if (sge_num++ >= max_sge_num) {
                UMQ_LIMIT_VLOG_ERR("sge num exceed max sge num[%u]\n", max_sge_num);
                return -UMQ_ERR_EINVAL;
            }
            sges_ptr->addr = (uint64_t)(uintptr_t)buffer->buf_data;
            sges_ptr->len = buffer->data_size;
            sges_ptr->user_tseg = NULL;
            sges_ptr->tseg = tseg_list[buffer->mempool_id];
            sges_ptr++;

            if (rest_size < buffer->data_size) { // if cannot add up to total_size, return fail
                UMQ_LIMIT_VLOG_ERR("cannot put together tx buffer, rest size is negative\n");
                return -UMQ_ERR_EINVAL;
            }

            rest_size -= buffer->data_size;
            buffer = QBUF_LIST_NEXT(buffer);
        }
        if (rest_size != 0) { // if cannot add up to total_size, return fail
            UMQ_LIMIT_VLOG_ERR("cannot put together enough tx buffer\n");
            return -UMQ_ERR_ENOMEM;
        }

        urma_wr_ptr->user_ctx = user_ctx;
        urma_wr_ptr->send.src.sge = sges[wr_index];
        urma_wr_ptr->send.src.num_sge = sge_num;
        urma_wr_ptr->opcode = URMA_OPC_SEND;
        urma_wr_ptr->flag.value = buf_pro->flag.value;
        urma_wr_ptr->tjetty = tjetty;
        urma_wr_ptr++;
        (urma_wr_ptr - 1)->next = urma_wr_ptr;
        wr_index++;
        if ((wr_index == remain_tx || wr_index == UMQ_POST_POLL_BATCH) && buffer != NULL) {
            // wr count exceed remain_tx or UMQ_POST_POLL_BATCH
            UMQ_LIMIT_VLOG_ERR("wr count %u exceeds remain_tx %u or max_post_size %d, not supported\n", wr_index,
                               remain_tx, UMQ_POST_POLL_BATCH);
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
    uint32_t remain = queue->rx_depth - atomic_load_explicit(&queue->require_rx_count, memory_order_acquire);
    while (remain > 0 && retry_times < max_retry_times) {
        rx_cnt = umq_ub_poll_rx((uint64_t)(uintptr_t)queue, buf, UMQ_POST_POLL_BATCH);
        if (rx_cnt < 0) {
            return;
        }
        umq_buf_list_t head;
        for (int i = 0; i < rx_cnt; i++) {
            head.first = buf[i];
            umq_qbuf_free(&head);
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