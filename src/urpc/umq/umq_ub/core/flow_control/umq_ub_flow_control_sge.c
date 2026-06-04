/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2026-2026. All rights reserved.
 * Description: UMQ UB flow control SGE memory management
 * Create: 2026-5-28
 * Note:
 * History: 2026-5-28
 */

#include "umq_vlog.h"
#include "umq_qbuf_pool.h"
#include "urpc_bitmap.h"
#include "util_lock.h"
#include "umq_ub_flow_control_sge.h"

int umq_ub_flow_control_sge_mgr_init(umq_ub_flow_control_sge_mgr_t *mgr)
{
    uint32_t qbuf_cnt = UMQ_UB_FLOW_CONTROL_SGE_BITMAP_SIZE *
                        UMQ_UB_FLOW_CONTROL_SGE_BYTES_PER_SLOT / umq_buf_size_small();
    if (qbuf_cnt > UMQ_UB_FLOW_CONTROL_SGE_QBUF_COUNT_MAX) {
        UMQ_VLOG_ERR(VLOG_UMQ, "flow control sge qbuf_cnt %u exceed max %u\n",
            qbuf_cnt, (uint32_t)UMQ_UB_FLOW_CONTROL_SGE_QBUF_COUNT_MAX);
        return -UMQ_ERR_EINVAL;
    }

    mgr->bitmap = urpc_bitmap_alloc(UMQ_UB_FLOW_CONTROL_SGE_BITMAP_SIZE);
    if (mgr->bitmap == NULL) {
        UMQ_VLOG_ERR(VLOG_UMQ, "flow control sge bitmap alloc failed\n");
        return -UMQ_ERR_ENOMEM;
    }

    mgr->lock = util_mutex_lock_create(UTIL_MUTEX_ATTR_EXCLUSIVE);
    if (mgr->lock == NULL) {
        UMQ_VLOG_ERR(VLOG_UMQ, "flow control sge lock create failed\n");
        goto ERR_UNINIT;
    }

    for (uint32_t i = 0; i < qbuf_cnt; i++) {
        mgr->qbuf_array[i] = NULL;
    }

    return UMQ_SUCCESS;

ERR_UNINIT:
    umq_ub_flow_control_sge_mgr_uninit(mgr);
    return -UMQ_ERR_ENOMEM;
}

void umq_ub_flow_control_sge_mgr_uninit(umq_ub_flow_control_sge_mgr_t *mgr)
{
    uint32_t qbuf_cnt = UMQ_UB_FLOW_CONTROL_SGE_BITMAP_SIZE *
                        UMQ_UB_FLOW_CONTROL_SGE_BYTES_PER_SLOT / umq_buf_size_small();
    for (uint32_t i = 0; i < qbuf_cnt; i++) {
        if (mgr->qbuf_array[i] != NULL) {
            umq_buf_free(mgr->qbuf_array[i]);
            mgr->qbuf_array[i] = NULL;
        }
    }

    if (mgr->bitmap != NULL) {
        urpc_bitmap_free(mgr->bitmap);
        mgr->bitmap = NULL;
    }

    if (mgr->lock != NULL) {
        (void)util_mutex_lock_destroy(mgr->lock);
        mgr->lock = NULL;
    }
}

static bool is_umq_ub_flow_control_sge_qbuf_free(umq_ub_flow_control_sge_mgr_t *mgr, uint32_t qbuf_idx)
{
    uint32_t slots_per_qbuf = umq_buf_size_small() / UMQ_UB_FLOW_CONTROL_SGE_BYTES_PER_SLOT;
    uint32_t base_bit = qbuf_idx * slots_per_qbuf;
    return urpc_bitmap_find_next_bit(mgr->bitmap, base_bit + slots_per_qbuf, base_bit) >=
        base_bit + slots_per_qbuf;
}

int umq_ub_flow_control_sge_alloc(umq_ub_flow_control_sge_mgr_t *mgr, umq_ub_flow_control_sge_slot_t *slot)
{
    (void)util_mutex_lock(mgr->lock);

    unsigned long bit = urpc_bitmap_find_next_zero_bit(mgr->bitmap, UMQ_UB_FLOW_CONTROL_SGE_BITMAP_SIZE, 0);
    if (bit >= UMQ_UB_FLOW_CONTROL_SGE_BITMAP_SIZE) {
        (void)util_mutex_unlock(mgr->lock);
        UMQ_VLOG_ERR(VLOG_UMQ, "flow control sge bitmap full, no free slot\n");
        return -UMQ_ERR_ENOMEM;
    }

    uint32_t qbuf_size = umq_buf_size_small();
    uint32_t slots_per_qbuf = qbuf_size / UMQ_UB_FLOW_CONTROL_SGE_BYTES_PER_SLOT;
    uint32_t qbuf_idx = (uint32_t)bit / slots_per_qbuf;
    uint32_t qbuf_offset = (uint32_t)bit % slots_per_qbuf;

    if (mgr->qbuf_array[qbuf_idx] == NULL) {
        mgr->qbuf_array[qbuf_idx] = umq_buf_alloc(qbuf_size, 1, UMQ_INVALID_HANDLE, NULL);
        if (mgr->qbuf_array[qbuf_idx] == NULL) {
            (void)util_mutex_unlock(mgr->lock);
            UMQ_VLOG_ERR(VLOG_UMQ, "flow control sge qbuf alloc failed\n");
            return -UMQ_ERR_ENOMEM;
        }
    }

    urpc_bitmap_set1(mgr->bitmap, bit);

    (void)util_mutex_unlock(mgr->lock);

    slot->addr = (char *)mgr->qbuf_array[qbuf_idx]->buf_data + qbuf_offset * UMQ_UB_FLOW_CONTROL_SGE_BYTES_PER_SLOT;
    slot->bitmap_idx = (uint32_t)bit;

    return UMQ_SUCCESS;
}

void umq_ub_flow_control_sge_free(umq_ub_flow_control_sge_mgr_t *mgr, umq_ub_flow_control_sge_slot_t *slot)
{
    if (slot->addr == NULL || slot->bitmap_idx >= UMQ_UB_FLOW_CONTROL_SGE_BITMAP_SIZE) {
        return;
    }

    (void)util_mutex_lock(mgr->lock);

    urpc_bitmap_set0(mgr->bitmap, slot->bitmap_idx);

    uint32_t slots_per_qbuf = umq_buf_size_small() / UMQ_UB_FLOW_CONTROL_SGE_BYTES_PER_SLOT;
    uint32_t qbuf_idx = slot->bitmap_idx / slots_per_qbuf;
    if (mgr->qbuf_array[qbuf_idx] != NULL && is_umq_ub_flow_control_sge_qbuf_free(mgr, qbuf_idx)) {
        umq_buf_free(mgr->qbuf_array[qbuf_idx]);
        mgr->qbuf_array[qbuf_idx] = NULL;
    }

    (void)util_mutex_unlock(mgr->lock);

    slot->addr = NULL;
    slot->bitmap_idx = UMQ_UB_FLOW_CONTROL_SGE_BITMAP_SIZE;
}

int umq_ub_flow_control_share_rq_sge_init(umq_ub_flow_control_share_recv_t *share_rq_sge, uint32_t qbuf_cnt)
{
    for (uint32_t i = 0; i < qbuf_cnt; i++) {
        share_rq_sge->qbuf_array[i] = umq_buf_alloc(umq_buf_size_small(), 1, UMQ_INVALID_HANDLE, NULL);
        if (share_rq_sge->qbuf_array[i] == NULL) {
            UMQ_VLOG_ERR(VLOG_UMQ, "flow control share recv qbuf[%u] alloc failed\n", i);
            for (uint32_t j = 0; j < i; j++) {
                umq_buf_free(share_rq_sge->qbuf_array[j]);
                share_rq_sge->qbuf_array[j] = NULL;
            }
            share_rq_sge->qbuf_cnt = 0;
            return -UMQ_ERR_ENOMEM;
        }
    }

    share_rq_sge->qbuf_cnt = qbuf_cnt;
    return UMQ_SUCCESS;
}

void umq_ub_flow_control_share_rq_sge_uninit(umq_ub_flow_control_share_recv_t *share_rq_sge)
{
    for (uint32_t i = 0; i < share_rq_sge->qbuf_cnt; i++) {
        if (share_rq_sge->qbuf_array[i] != NULL) {
            umq_buf_free(share_rq_sge->qbuf_array[i]);
            share_rq_sge->qbuf_array[i] = NULL;
        }
    }
    share_rq_sge->qbuf_cnt = 0;
}
