/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2026-2026. All rights reserved.
 * Description: realize func for umq dfx api
 * Create: 2026-2-4
 */

#include "umq_errno.h"
#include "umq_qbuf_pool.h"
#include "umq_huge_qbuf_pool.h"
#include "perf.h"
#include "umq_inner.h"

#define UMQ_DFX_EQUALS "=================================================================================="
#define UMQ_DFX_UNDERLINE "----------------------------------------------------------------------------------"
#define UMQ_DFX_EQUALS_120 "==========================================================================================\
=============================="
#define UMQ_DFX_UNDERLINE_120 "---------------------------------------------------------------------------------------\
---------------------------------"
#define TRANS_MODE_NAME_SIZE 20
#define UMQ_DFX_PERF_REC_NAME_MAX_LEN 20
#define UMQ_DFX_QBUF_POOL_TYPE_NAME_MAX_LEN 20

#define UMQ_DFX_SNPRINTF_BUF(__buf, __max_buf_len, __offset, __format, ...)            \
    do {                                                                                            \
        int __ret;                                                                                  \
        if ((__max_buf_len) <= (__offset)) {                                                        \
            __ret = snprintf(NULL, 0, __format, ##__VA_ARGS__);                                     \
        } else {                                                                                    \
            __ret = snprintf((__buf) + (__offset), (__max_buf_len) - (__offset),                    \
                            __format, ##__VA_ARGS__);                                               \
        }                                                                                           \
        (__offset) += __ret;                                                                        \
    } while (0)                                                                                     \

int umq_stats_flow_control_get(uint64_t umqh, umq_flow_control_stats_t *flow_control_stats)
{
    umq_t *umq = (umq_t *)(uintptr_t)umqh;
    if (umq == NULL || umq->umqh_tp == UMQ_INVALID_HANDLE || umq->dfx_tp_ops == NULL ||
        umq->dfx_tp_ops->umq_tp_stats_flow_control_get == NULL || flow_control_stats == NULL) {
        UMQ_VLOG_ERR(VLOG_UMQ, "umqh or flow control stats parameter invalid\n");
        return -UMQ_ERR_EINVAL;
    }
    return umq->dfx_tp_ops->umq_tp_stats_flow_control_get(umq->umqh_tp, flow_control_stats);
}

int umq_flow_control_stats_to_str(const umq_flow_control_stats_t *flow_control_stats, char *buf, int max_buf_len)
{
    if (flow_control_stats == NULL || buf == NULL || max_buf_len <= 0) {
        UMQ_VLOG_ERR(VLOG_UMQ, "invalid parameter\n");
        return -UMQ_ERR_EINVAL;
    }

    int str_size = 0;
    (void)memset(buf, 0, max_buf_len);

    // format flow control statistics header
    UMQ_DFX_SNPRINTF_BUF(buf, max_buf_len, str_size, "%s\n", UMQ_DFX_EQUALS);
    UMQ_DFX_SNPRINTF_BUF(buf, max_buf_len, str_size, "%s\n",
        "                               Flow Control Statistics");
    UMQ_DFX_SNPRINTF_BUF(buf, max_buf_len, str_size, "%s\n", UMQ_DFX_EQUALS);
    UMQ_DFX_SNPRINTF_BUF(buf, max_buf_len, str_size, "%-40s %-40s\n", "Type", "Value");

    // format pool credit statistics
    UMQ_DFX_SNPRINTF_BUF(buf, max_buf_len, str_size, "%s\n", UMQ_DFX_UNDERLINE);
    UMQ_DFX_SNPRINTF_BUF(buf, max_buf_len, str_size, "%s\n",
        "                               Pool Credit Statistics");
    UMQ_DFX_SNPRINTF_BUF(buf, max_buf_len, str_size, "%s\n", UMQ_DFX_UNDERLINE);
    UMQ_DFX_SNPRINTF_BUF(buf, max_buf_len, str_size,
        "%-40s %-40lu\n", "Pool Idle", flow_control_stats->pool_credit.pool_idle);
    UMQ_DFX_SNPRINTF_BUF(buf, max_buf_len, str_size,
        "%-40s %-40lu\n", "Pool Allocated", flow_control_stats->pool_credit.pool_be_allocated);
    UMQ_DFX_SNPRINTF_BUF(buf, max_buf_len, str_size,
        "%-40s %-40lu\n", "Total Pool Idle", flow_control_stats->pool_credit.total_pool_idle);
    UMQ_DFX_SNPRINTF_BUF(buf, max_buf_len, str_size,
        "%-40s %-40lu\n", "Total Pool Allocated", flow_control_stats->pool_credit.total_pool_be_allocated);
    UMQ_DFX_SNPRINTF_BUF(buf, max_buf_len, str_size,
        "%-40s %-40lu\n", "Total Pool Post RX Err", flow_control_stats->pool_credit.total_pool_post_rx_err);

    // format queue credit statistics
    UMQ_DFX_SNPRINTF_BUF(buf, max_buf_len, str_size, "%s\n", UMQ_DFX_UNDERLINE);
    UMQ_DFX_SNPRINTF_BUF(buf, max_buf_len, str_size,
        "                              Queue Credit Statistics\n");
    UMQ_DFX_SNPRINTF_BUF(buf, max_buf_len, str_size, "%s\n", UMQ_DFX_UNDERLINE);
    UMQ_DFX_SNPRINTF_BUF(buf, max_buf_len, str_size,
        "%-40s %-40lu\n", "Queue Idle", flow_control_stats->queue_credit.queue_idle);
    UMQ_DFX_SNPRINTF_BUF(buf, max_buf_len, str_size,
        "%-40s %-40lu\n", "Queue Allocated", flow_control_stats->queue_credit.queue_be_allocated);
    UMQ_DFX_SNPRINTF_BUF(buf, max_buf_len, str_size,
        "%-40s %-40lu\n", "Queue Acquired", flow_control_stats->queue_credit.queue_acquired);
    UMQ_DFX_SNPRINTF_BUF(buf, max_buf_len, str_size,
        "%-40s %-40lu\n", "Total Queue Idle", flow_control_stats->queue_credit.total_queue_idle);
    UMQ_DFX_SNPRINTF_BUF(buf, max_buf_len, str_size,
        "%-40s %-40lu\n", "Total Queue Acquired", flow_control_stats->queue_credit.total_queue_acquired);
    UMQ_DFX_SNPRINTF_BUF(buf, max_buf_len, str_size,
        "%-40s %-40lu\n", "Total Queue Allocated", flow_control_stats->queue_credit.total_queue_be_allocated);
    UMQ_DFX_SNPRINTF_BUF(buf, max_buf_len, str_size,
        "%-40s %-40lu\n", "Total Queue Post TX Success", flow_control_stats->queue_credit.total_queue_post_tx_success);
    UMQ_DFX_SNPRINTF_BUF(buf, max_buf_len, str_size,
        "%-40s %-40lu\n", "Total Queue Post TX Err", flow_control_stats->queue_credit.total_queue_post_tx_err);
    UMQ_DFX_SNPRINTF_BUF(buf, max_buf_len, str_size,
        "%-40s %-40lu\n", "Total Queue Acquired Err", flow_control_stats->queue_credit.total_queue_acquired_err);

    // format packet statistics
    UMQ_DFX_SNPRINTF_BUF(buf, max_buf_len, str_size, "%s\n", UMQ_DFX_UNDERLINE);
    UMQ_DFX_SNPRINTF_BUF(buf, max_buf_len, str_size, "                              Packet Statistics\n");
    UMQ_DFX_SNPRINTF_BUF(buf, max_buf_len, str_size, "%s\n", UMQ_DFX_UNDERLINE);
    UMQ_DFX_SNPRINTF_BUF(buf, max_buf_len, str_size,
        "%-40s %-40lu\n", "Send Cnt", flow_control_stats->packet_stats.send_cnt);
    UMQ_DFX_SNPRINTF_BUF(buf, max_buf_len, str_size,
        "%-40s %-40lu\n", "Send Success", flow_control_stats->packet_stats.send_success);
    UMQ_DFX_SNPRINTF_BUF(buf, max_buf_len, str_size,
        "%-40s %-40lu\n", "Recv Cnt", flow_control_stats->packet_stats.recv_cnt);
    UMQ_DFX_SNPRINTF_BUF(buf, max_buf_len, str_size,
        "%-40s %-40lu\n", "Send Error Cnt", flow_control_stats->packet_stats.send_error_cnt);
    UMQ_DFX_SNPRINTF_BUF(buf, max_buf_len, str_size,
        "%-40s %-40lu\n", "Recv Error Cnt", flow_control_stats->packet_stats.recv_error_cnt);
    UMQ_DFX_SNPRINTF_BUF(buf, max_buf_len, str_size, "%s\n", UMQ_DFX_UNDERLINE);
    UMQ_DFX_SNPRINTF_BUF(buf, max_buf_len, str_size, "%s\n", UMQ_DFX_EQUALS);

    return str_size;
}

int umq_stats_qbuf_pool_get(uint64_t umqh, umq_qbuf_pool_stats_t *qbuf_pool_stats)
{
    if (qbuf_pool_stats == NULL) {
        UMQ_VLOG_ERR(VLOG_UMQ, "qbuf pool stats stats parameter invalid\n");
        return -UMQ_ERR_EINVAL;
    }

    int ret;
    if (umqh == UMQ_INVALID_HANDLE) {
        qbuf_pool_stats->num = 0;
        ret = umq_qbuf_pool_info_get(qbuf_pool_stats);
        if (ret != UMQ_SUCCESS) {
            UMQ_VLOG_ERR(VLOG_UMQ, "umq qbuf pool info get failed\n");
            return ret;
        }

        ret = umq_huge_qbuf_pool_info_get(qbuf_pool_stats);
        if (ret != UMQ_SUCCESS) {
            UMQ_VLOG_ERR(VLOG_UMQ, "umq huge qbuf pool info get failed\n");
            return ret;
        }
        return UMQ_SUCCESS;
    }

    umq_t *umq = (umq_t *)(uintptr_t)umqh;
    if (umq == NULL || umq->umqh_tp == UMQ_INVALID_HANDLE || umq->dfx_tp_ops == NULL ||
        umq->dfx_tp_ops->umq_tp_stats_qbuf_pool_get == NULL) {
        UMQ_VLOG_ERR(VLOG_UMQ, "umqh or qbuf pool stats parameter invalid\n");
        return -UMQ_ERR_EINVAL;
    }

    return umq->dfx_tp_ops->umq_tp_stats_qbuf_pool_get(umq->umqh_tp, qbuf_pool_stats);
}

int umq_qbuf_pool_stats_to_str(const umq_qbuf_pool_stats_t *qbuf_pool_stats, char *buf, int max_buf_len)
{
    if (qbuf_pool_stats == NULL || buf == NULL || max_buf_len <= 0 ||
        qbuf_pool_stats->num > UMQ_STATS_QBUF_POOL_TYPE_MAX ||
        qbuf_pool_stats->local_qbuf_pool_num > UMQ_LOCAL_QBUF_POOL_MAX_NUM) {
        UMQ_VLOG_ERR(VLOG_UMQ, "invalid parameter\n");
        return -UMQ_ERR_EINVAL;
    }

    static const char qbuf_pool_type[UMQ_STATS_QBUF_POOL_TYPE_MAX][UMQ_DFX_QBUF_POOL_TYPE_NAME_MAX_LEN] = {
        "Small",
        "Medium",
        "Big",
        "Huge",
        "Gigantic",
    };

    int str_size = 0;
    (void)memset(buf, 0, max_buf_len);

    UMQ_DFX_SNPRINTF_BUF(buf, max_buf_len, str_size, "%s\n", UMQ_DFX_EQUALS_120);
    UMQ_DFX_SNPRINTF_BUF(buf, max_buf_len, str_size,
        "%s\n", "                                             Qbuf Pool Statistics");
    UMQ_DFX_SNPRINTF_BUF(buf, max_buf_len, str_size, "%s\n", UMQ_DFX_EQUALS_120);

    // === Global Pool Config ===
    UMQ_DFX_SNPRINTF_BUF(buf, max_buf_len, str_size,
        "%s\n", "                                             Global Pool Config");
    UMQ_DFX_SNPRINTF_BUF(buf, max_buf_len, str_size, "%s\n", UMQ_DFX_UNDERLINE_120);
    UMQ_DFX_SNPRINTF_BUF(buf, max_buf_len, str_size,
        "%-16s %-9s %-11s %-8s %-8s %-8s %-8s %-8s %-11s %-14s %-14s\n",
        "Type", "Mode", "TotalSize", "TotalBlk", "BlkSize", "Headroom",
        "DataSize", "BufSize", "UmqBufSize", "FreeBlk", "FreeSize");
    for (uint32_t i = 0; i < qbuf_pool_stats->num; i++) {
        const umq_qbuf_pool_info_t *info = &qbuf_pool_stats->qbuf_pool_info[i];
        UMQ_DFX_SNPRINTF_BUF(buf, max_buf_len, str_size,
            "%-16s %-9s %-11lu %-8lu %-8u %-8u %-8u %-8u %-11u %-14lu %-14lu\n",
            qbuf_pool_type[i],
            info->mode == UMQ_BUF_SPLIT ? "SPLIT" : "COMBINE",
            info->total_size,
            info->total_block_num,
            info->block_size,
            info->headroom_size,
            info->data_size,
            info->buf_size,
            info->umq_buf_t_size,
            info->available_mem.split.block_num_with_data,
            info->available_mem.split.size_with_data);
    }

    // === Expansion Pool ===
    UMQ_DFX_SNPRINTF_BUF(buf, max_buf_len, str_size, "%s\n", UMQ_DFX_EQUALS_120);
    UMQ_DFX_SNPRINTF_BUF(buf, max_buf_len, str_size,
        "%s\n", "                                             Expansion Pool");
    UMQ_DFX_SNPRINTF_BUF(buf, max_buf_len, str_size, "%s\n", UMQ_DFX_UNDERLINE_120);
    UMQ_DFX_SNPRINTF_BUF(buf, max_buf_len, str_size,
        "%-16s %-15s %-17s %-15s %-17s %-17s %-17s\n",
        "Type", "ExpandCnt", "TotalBlk", "FreeBlk", "MemSize", "AccExpCnt", "AccShrinkCnt");
    UMQ_DFX_SNPRINTF_BUF(buf, max_buf_len, str_size,
        "%-16s %-15u %-17lu %-15lu %-17lu %-17lu %-17lu\n",
        "WithData",
        qbuf_pool_stats->exp_pool_with_data.expansion_count,
        qbuf_pool_stats->exp_pool_with_data.exp_total_block_num,
        qbuf_pool_stats->exp_pool_with_data.exp_total_free_block_num,
        qbuf_pool_stats->exp_pool_with_data.exp_total_mem_size,
        qbuf_pool_stats->exp_pool_with_data.total_expansion_count,
        qbuf_pool_stats->exp_pool_with_data.total_shrink_count);
    UMQ_DFX_SNPRINTF_BUF(buf, max_buf_len, str_size,
        "%-16s %-15u %-17lu %-15lu %-17lu %-17lu %-17lu\n",
        "WithoutData",
        qbuf_pool_stats->exp_pool_without_data.expansion_count,
        qbuf_pool_stats->exp_pool_without_data.exp_total_block_num,
        qbuf_pool_stats->exp_pool_without_data.exp_total_free_block_num,
        qbuf_pool_stats->exp_pool_without_data.exp_total_mem_size,
        qbuf_pool_stats->exp_pool_without_data.total_expansion_count,
        qbuf_pool_stats->exp_pool_without_data.total_shrink_count);

    // === Per-Thread TLS Pool Stats (WithData) ===
    uint64_t total_tls_capacity_with_data = 0;
    uint64_t total_tls_buf_cnt_with_data = 0;
    uint64_t total_tls_capacity_without_data = 0;
    uint64_t total_tls_buf_cnt_without_data = 0;
    uint64_t total_tls_fetch_cnt_with_data = 0;
    uint64_t total_tls_fetch_buf_cnt_with_data = 0;
    uint64_t total_tls_fetch_cnt_without_data = 0;
    uint64_t total_tls_fetch_buf_cnt_without_data = 0;
    uint64_t total_tls_return_cnt_with_data = 0;
    uint64_t total_tls_return_buf_cnt_with_data = 0;
    uint64_t total_tls_return_cnt_without_data = 0;
    uint64_t total_tls_return_buf_cnt_without_data = 0;
    uint64_t total_alloc_cnt_with_data = 0;
    uint64_t total_alloc_cnt_without_data = 0;
    uint64_t total_free_cnt_with_data = 0;
    uint64_t total_free_cnt_without_data = 0;

    UMQ_DFX_SNPRINTF_BUF(buf, max_buf_len, str_size, "%s\n", UMQ_DFX_EQUALS_120);
    UMQ_DFX_SNPRINTF_BUF(buf, max_buf_len, str_size,
        "%s\n", "                                             Per-Thread TLS Pool Stats (WithData)");
    UMQ_DFX_SNPRINTF_BUF(buf, max_buf_len, str_size, "%s\n", UMQ_DFX_UNDERLINE_120);
    UMQ_DFX_SNPRINTF_BUF(buf, max_buf_len, str_size,
        "%-16s %-13s %-13s %-13s %-13s %-13s %-13s %-13s %-13s\n",
        "TID", "CurCap", "CurBuf", "AccFetchCnt", "AccFetchBuf", "AccReturnCnt", "AccReturnBuf", "AccAlloc", "AccFree");
   
    for (uint32_t i = 0; i < qbuf_pool_stats->local_qbuf_pool_num; i++) {
        const umq_local_qbuf_pool_stats_t *s = &qbuf_pool_stats->local_qbuf_pool_stats[i];
        total_tls_capacity_with_data += s->capacity_with_data;
        total_tls_buf_cnt_with_data += s->buf_cnt_with_data;
        total_tls_fetch_cnt_with_data += s->tls_fetch_cnt_with_data;
        total_tls_fetch_buf_cnt_with_data += s->tls_fetch_buf_cnt_with_data;
        total_tls_return_cnt_with_data += s->tls_return_cnt_with_data;
        total_tls_return_buf_cnt_with_data += s->tls_return_buf_cnt_with_data;
        total_alloc_cnt_with_data += s->alloc_cnt_with_data;
        total_free_cnt_with_data += s->free_cnt_with_data;
    }
    UMQ_DFX_SNPRINTF_BUF(buf, max_buf_len, str_size,
        "%-16s %-13lu %-13lu %-13lu %-13lu %-13lu %-13lu %-13lu %-13lu\n",
        "total",
        total_tls_capacity_with_data, total_tls_buf_cnt_with_data,
        total_tls_fetch_cnt_with_data, total_tls_fetch_buf_cnt_with_data,
        total_tls_return_cnt_with_data, total_tls_return_buf_cnt_with_data,
        total_alloc_cnt_with_data, total_free_cnt_with_data);

    for (uint32_t i = 0; i < qbuf_pool_stats->local_qbuf_pool_num; i++) {
        const umq_local_qbuf_pool_stats_t *s = &qbuf_pool_stats->local_qbuf_pool_stats[i];
        UMQ_DFX_SNPRINTF_BUF(buf, max_buf_len, str_size,
            "%-16lu %-13lu %-13lu %-13lu %-13lu %-13lu %-13lu %-13lu %-13lu\n",
            s->tid, s->capacity_with_data, s->buf_cnt_with_data,
            s->tls_fetch_cnt_with_data, s->tls_fetch_buf_cnt_with_data,
            s->tls_return_cnt_with_data, s->tls_return_buf_cnt_with_data,
            s->alloc_cnt_with_data, s->free_cnt_with_data);
    }

    // === Per-Thread TLS Pool Stats (WithoutData) ===
    UMQ_DFX_SNPRINTF_BUF(buf, max_buf_len, str_size, "%s\n", UMQ_DFX_EQUALS_120);
    UMQ_DFX_SNPRINTF_BUF(buf, max_buf_len, str_size,
        "%s\n", "                                             Per-Thread TLS Pool Stats (WithoutData)");
    UMQ_DFX_SNPRINTF_BUF(buf, max_buf_len, str_size, "%s\n", UMQ_DFX_UNDERLINE_120);
    UMQ_DFX_SNPRINTF_BUF(buf, max_buf_len, str_size,
        "%-16s %-13s %-13s %-13s %-13s %-13s %-13s %-13s %-13s\n",
        "TID", "CurCap", "CurBuf", "AccFetchCnt", "AccFetchBuf", "AccReturnCnt", "AccReturnBuf", "AccAlloc", "AccFree");

    for (uint32_t i = 0; i < qbuf_pool_stats->local_qbuf_pool_num; i++) {
        const umq_local_qbuf_pool_stats_t *s = &qbuf_pool_stats->local_qbuf_pool_stats[i];
        total_tls_capacity_without_data += s->capacity_without_data;
        total_tls_buf_cnt_without_data += s->buf_cnt_without_data;
        total_tls_fetch_cnt_without_data += s->tls_fetch_cnt_without_data;
        total_tls_fetch_buf_cnt_without_data += s->tls_fetch_buf_cnt_without_data;
        total_tls_return_cnt_without_data += s->tls_return_cnt_without_data;
        total_tls_return_buf_cnt_without_data += s->tls_return_buf_cnt_without_data;
        total_alloc_cnt_without_data += s->alloc_cnt_without_data;
        total_free_cnt_without_data += s->free_cnt_without_data;
    }
    UMQ_DFX_SNPRINTF_BUF(buf, max_buf_len, str_size,
        "%-16s %-13lu %-13lu %-13lu %-13lu %-13lu %-13lu %-13lu %-13lu\n",
        "total",
        total_tls_capacity_without_data, total_tls_buf_cnt_without_data,
        total_tls_fetch_cnt_without_data, total_tls_fetch_buf_cnt_without_data,
        total_tls_return_cnt_without_data, total_tls_return_buf_cnt_without_data,
        total_alloc_cnt_without_data, total_free_cnt_without_data);

    for (uint32_t i = 0; i < qbuf_pool_stats->local_qbuf_pool_num; i++) {
        const umq_local_qbuf_pool_stats_t *s = &qbuf_pool_stats->local_qbuf_pool_stats[i];
        UMQ_DFX_SNPRINTF_BUF(buf, max_buf_len, str_size,
            "%-16lu %-13lu %-13lu %-13lu %-13lu %-13lu %-13lu %-13lu %-13lu\n",
            s->tid, s->capacity_without_data, s->buf_cnt_without_data,
            s->tls_fetch_cnt_without_data, s->tls_fetch_buf_cnt_without_data,
            s->tls_return_cnt_without_data, s->tls_return_buf_cnt_without_data,
            s->alloc_cnt_without_data, s->free_cnt_without_data);
    }

    UMQ_DFX_SNPRINTF_BUF(buf, max_buf_len, str_size, "%s\n", UMQ_DFX_EQUALS_120);

    return str_size;
}

int umq_info_get(uint64_t umqh, umq_info_t *umq_info)
{
    umq_t *umq = (umq_t *)(uintptr_t)umqh;
    if (umq == NULL || umq->umqh_tp == UMQ_INVALID_HANDLE || umq->dfx_tp_ops == NULL ||
        umq->dfx_tp_ops->umq_tp_info_get == NULL || umq_info == NULL) {
        UMQ_VLOG_ERR(VLOG_UMQ, "umqh or umq info parameter invalid\n");
        return -UMQ_ERR_EINVAL;
    }

    return umq->dfx_tp_ops->umq_tp_info_get(umq->umqh_tp, umq_info);
}

int umq_info_to_str(const umq_info_t *umq_info, char *buf, int max_buf_len)
{
    if (umq_info == NULL || umq_info->trans_mode >= UMQ_TRANS_MODE_MAX || buf == NULL || max_buf_len <= 0) {
        UMQ_VLOG_ERR(VLOG_UMQ, "invalid parameter\n");
        return -UMQ_ERR_EINVAL;
    }

    int str_size = 0;
    (void)memset(buf, 0, max_buf_len);

    static const char trans_mode_map[UMQ_TRANS_MODE_MAX][TRANS_MODE_NAME_SIZE] = {
        [UMQ_TRANS_MODE_UB]        = "UB",
        [UMQ_TRANS_MODE_IB]        = "IB",
        [UMQ_TRANS_MODE_UCP]       = "UCP",
        [UMQ_TRANS_MODE_IPC]       = "IPC",
        [UMQ_TRANS_MODE_UBMM]      = "UBMM",
        [UMQ_TRANS_MODE_UB_PLUS]   = "UB_PLUS",
        [UMQ_TRANS_MODE_IB_PLUS]   = "IB_PLUS",
        [UMQ_TRANS_MODE_UBMM_PLUS] = "UB_PLUS",
    };

    // Format UMQ Info
    UMQ_DFX_SNPRINTF_BUF(buf, max_buf_len, str_size, "%s\n", UMQ_DFX_EQUALS);
    UMQ_DFX_SNPRINTF_BUF(buf, max_buf_len, str_size, "%s\n", "                               UMQ Info");
    UMQ_DFX_SNPRINTF_BUF(buf, max_buf_len, str_size, "%s\n", UMQ_DFX_EQUALS);
    UMQ_DFX_SNPRINTF_BUF(buf, max_buf_len, str_size, "%-40s %-40s\n", "Info", "Value");
    UMQ_DFX_SNPRINTF_BUF(buf, max_buf_len, str_size, "%s\n", UMQ_DFX_UNDERLINE);
    UMQ_DFX_SNPRINTF_BUF(buf, max_buf_len, str_size,
        "%-40s %-40s\n", "Trans Mode", trans_mode_map[umq_info->trans_mode]);

    if (umq_info->trans_mode == UMQ_TRANS_MODE_UB || umq_info->trans_mode == UMQ_TRANS_MODE_UB_PLUS) {
        UMQ_DFX_SNPRINTF_BUF(buf, max_buf_len, str_size, "%-40s %-40u\n", "UMQ ID", umq_info->ub.umq_id);
        UMQ_DFX_SNPRINTF_BUF(buf, max_buf_len, str_size,
            "%-40s " EID_FMT "\n", "EID", EID_ARGS(umq_info->ub.eid));
        UMQ_DFX_SNPRINTF_BUF(buf, max_buf_len, str_size,
            "%-40s %-40s\n", "Dev Name", umq_info->ub.dev_name);
        UMQ_DFX_SNPRINTF_BUF(buf, max_buf_len, str_size,
            "%-40s %-40u\n", "Local IO Jetty ID", umq_info->ub.local_io_jetty_id);
        UMQ_DFX_SNPRINTF_BUF(buf, max_buf_len, str_size,
            "%-40s %-40u\n", "Local FC Jetty ID", umq_info->ub.local_fc_jetty_id);
        UMQ_DFX_SNPRINTF_BUF(buf, max_buf_len, str_size,
            "%-40s %-40u\n", "Remote IO Jetty ID", umq_info->ub.remote_io_jetty_id);
        UMQ_DFX_SNPRINTF_BUF(buf, max_buf_len, str_size,
            "%-40s %-40u\n", "Remote FC Jetty ID", umq_info->ub.remote_fc_jetty_id);
    }
    UMQ_DFX_SNPRINTF_BUF(buf, max_buf_len, str_size, "%s\n", UMQ_DFX_UNDERLINE);
    UMQ_DFX_SNPRINTF_BUF(buf, max_buf_len, str_size, "%s\n", UMQ_DFX_EQUALS);

    return str_size;
}

int umq_stats_io_get(uint64_t umqh, umq_packet_stats_t *packet_stats)
{
    umq_t *umq = (umq_t *)(uintptr_t)umqh;
    if (umq == NULL || umq->umqh_tp == UMQ_INVALID_HANDLE || umq->dfx_tp_ops == NULL ||
        umq->dfx_tp_ops->umq_tp_stats_io_get == NULL || packet_stats == NULL) {
        UMQ_VLOG_ERR(VLOG_UMQ, "umqh or packet stats parameter invalid\n");
        return -UMQ_ERR_EINVAL;
    }
    return umq->dfx_tp_ops->umq_tp_stats_io_get(umq->umqh_tp, packet_stats);
}

int umq_stats_io_reset(uint64_t umqh)
{
    umq_t *umq = (umq_t *)(uintptr_t)umqh;
    if (umq == NULL || umq->umqh_tp == UMQ_INVALID_HANDLE || umq->dfx_tp_ops == NULL ||
        umq->dfx_tp_ops->umq_tp_stats_io_reset == NULL) {
        UMQ_VLOG_ERR(VLOG_UMQ, "umqh parameter invalid\n");
        return -UMQ_ERR_EINVAL;
    }
    return umq->dfx_tp_ops->umq_tp_stats_io_reset(umq->umqh_tp);
}

int umq_io_stats_to_str(const umq_packet_stats_t *packet_stats, char *buf, int max_buf_len)
{
    if (packet_stats == NULL || buf == NULL || max_buf_len <= 0) {
        UMQ_VLOG_ERR(VLOG_UMQ, "invalid parameter\n");
        return -UMQ_ERR_EINVAL;
    }

    int str_size = 0;
    (void)memset(buf, 0, max_buf_len);

    // Format IO Packet Statistics
    UMQ_DFX_SNPRINTF_BUF(buf, max_buf_len, str_size, "%s\n", UMQ_DFX_EQUALS);
    UMQ_DFX_SNPRINTF_BUF(buf, max_buf_len, str_size, "                              IO Packet Statistics\n");
    UMQ_DFX_SNPRINTF_BUF(buf, max_buf_len, str_size, "%s\n", UMQ_DFX_EQUALS);
    UMQ_DFX_SNPRINTF_BUF(buf, max_buf_len, str_size, "%-40s %-40s\n", "Type", "Value");
    UMQ_DFX_SNPRINTF_BUF(buf, max_buf_len, str_size, "%s\n", UMQ_DFX_UNDERLINE);
    UMQ_DFX_SNPRINTF_BUF(buf, max_buf_len, str_size, "%-40s %-40lu\n", "send_cnt", packet_stats->send_cnt);
    UMQ_DFX_SNPRINTF_BUF(buf, max_buf_len, str_size, "%-40s %-40lu\n",
        "send_success", packet_stats->send_success);
    UMQ_DFX_SNPRINTF_BUF(buf, max_buf_len, str_size, "%-40s %-40lu\n", "recv_cnt", packet_stats->recv_cnt);
    UMQ_DFX_SNPRINTF_BUF(buf, max_buf_len, str_size, "%-40s %-40lu\n",
                         "send_eagain_cnt", packet_stats->send_eagain_cnt);
    UMQ_DFX_SNPRINTF_BUF(buf, max_buf_len, str_size, "%-40s %-40lu\n",
        "send_error_cnt", packet_stats->send_error_cnt);
    UMQ_DFX_SNPRINTF_BUF(buf, max_buf_len, str_size, "%-40s %-40lu\n",
        "recv_error_cnt", packet_stats->recv_error_cnt);
    UMQ_DFX_SNPRINTF_BUF(buf, max_buf_len, str_size, "%s\n", UMQ_DFX_UNDERLINE);
    UMQ_DFX_SNPRINTF_BUF(buf, max_buf_len, str_size, "%s\n", UMQ_DFX_EQUALS);

    return str_size;
}

int umq_stats_perf_get(umq_perf_stats_t *umq_perf_stats)
{
    return umq_perf_info_get(umq_perf_stats);
}

int umq_stats_perf_reset(umq_perf_stats_cfg_t *perf_stats_cfg)
{
    return umq_perf_reset(perf_stats_cfg);
}

int umq_stats_perf_start(void)
{
    return umq_perf_start();
}

int umq_stats_perf_stop(void)
{
    return umq_perf_stop();
}

int umq_stats_perf_to_str(umq_perf_stats_t *umq_perf_stats, char *buf, int max_buf_len)
{
    if (umq_perf_stats == NULL || buf == NULL || max_buf_len <= 0) {
        UMQ_VLOG_ERR(VLOG_UMQ, "parameters invalid");
        return -UMQ_ERR_EINVAL;
    }
    static char perf_record_type_name[UMQ_PERF_RECORD_TYPE_MAX][UMQ_DFX_PERF_REC_NAME_MAX_LEN] = {
        "umq_enqueue", "umq_dequeue", "umq_dequeue_empty", "umq_post_all","umq_post_tx", "umq_post_rx",
        "umq_poll_all", "umq_poll_tx", "umq_poll_rx", "umq_poll_all_empty", "umq_poll_tx_empty", "umq_poll_rx_empty",
        "umq_rearm_tx", "umq_rearm_rx", "umq_wait_tx", "umq_wait_rx", "umq_ack_tx", "umq_ack_rx", "umq_notify",
        "tp_post_send", "tp_post_recv", "tp_poll_tx", "tp_poll_rx", "tp_poll_tx_empty", "tp_poll_rx_empty",
        "tp_rearm_tx", "tp_rearm_rx", "tp_wait_tx", "tp_wait_rx", "tp_ack_tx", "tp_ack_rx",
    };

    int str_size = 0;
    (void)memset(buf, 0, max_buf_len);

    UMQ_DFX_SNPRINTF_BUF(buf, max_buf_len, str_size, "%s\n", UMQ_DFX_PERF_EQUALS);
    UMQ_DFX_SNPRINTF_BUF(buf, max_buf_len, str_size, "%s\n",
        "                                                                    Analyse IO performance records");
    UMQ_DFX_SNPRINTF_BUF(buf, max_buf_len, str_size, "%s\n", UMQ_DFX_PERF_EQUALS);
    UMQ_DFX_SNPRINTF_BUF(buf, max_buf_len, str_size,
        "%-20s %-20s %-20s %-20s %-20s %-20s %-20s %-20s\n",
        "Type", "Sample Num", "Average (ns)", "Minimum (ns)", "Maxinum (ns)", "Median (ns)", "P90 (ns)", "P99 (ns)");
    UMQ_DFX_SNPRINTF_BUF(buf, max_buf_len, str_size, "%s\n", UMQ_DFX_PERF_UNDERLINE);
    for (uint32_t type = 0; type < UMQ_PERF_RECORD_TYPE_MAX; type++) {
        UMQ_DFX_SNPRINTF_BUF(buf, max_buf_len, str_size,
            "%-20s %-20lu %-20lu %-20lu %-20lu %-20lu %-20lu %-20lu\n",
            perf_record_type_name[type], umq_perf_stats->type_record[type].sample_num,
            umq_perf_stats->type_record[type].average, umq_perf_stats->type_record[type].mininum,
            umq_perf_stats->type_record[type].maxinum, umq_perf_stats->type_record[type].median,
            umq_perf_stats->type_record[type].p90, umq_perf_stats->type_record[type].p99);
    }
    UMQ_DFX_SNPRINTF_BUF(buf, max_buf_len, str_size, "%s\n", UMQ_DFX_PERF_UNDERLINE);
    UMQ_DFX_SNPRINTF_BUF(buf, max_buf_len, str_size, "%s\n", UMQ_DFX_PERF_EQUALS);

    return str_size;
}

int umq_stats_tp_perf_start(umq_trans_mode_t trans_mode)
{
#ifdef UMQ_STATIC_LIB
    if (trans_mode != UMQ_TRANS_MODE_UB && trans_mode != UMQ_TRANS_MODE_UB_PLUS) {
        UMQ_VLOG_ERR(VLOG_UMQ, "umq static library only support UB transport mode\n");
        return -UMQ_ERR_EINVAL;
    }
#endif

    if (trans_mode >= UMQ_TRANS_MODE_MAX) {
        UMQ_VLOG_ERR(VLOG_UMQ, "trans info mode[%u] is invalid\n", trans_mode);
        return -UMQ_ERR_EINVAL;
    }

    umq_dfx_ops_t *dfx_tp_ops = umq_get_dfx_tp_ops(trans_mode);
    if (dfx_tp_ops == NULL || dfx_tp_ops->umq_tp_stats_tp_perf_start == NULL) {
        UMQ_VLOG_ERR(VLOG_UMQ, "trans mode %u ops not support\n", trans_mode);
        return -UMQ_ERR_EINVAL;
    }

    return dfx_tp_ops->umq_tp_stats_tp_perf_start();
}

int umq_stats_tp_perf_stop(umq_trans_mode_t trans_mode)
{
#ifdef UMQ_STATIC_LIB
    if (trans_mode != UMQ_TRANS_MODE_UB && trans_mode != UMQ_TRANS_MODE_UB_PLUS) {
        UMQ_VLOG_ERR(VLOG_UMQ, "umq static library only support UB transport mode\n");
        return -UMQ_ERR_EINVAL;
    }
#endif

    if (trans_mode >= UMQ_TRANS_MODE_MAX) {
        UMQ_VLOG_ERR(VLOG_UMQ, "trans info mode[%u] is invalid\n", trans_mode);
        return -UMQ_ERR_EINVAL;
    }

    umq_dfx_ops_t *dfx_tp_ops = umq_get_dfx_tp_ops(trans_mode);
    if (dfx_tp_ops == NULL || dfx_tp_ops->umq_tp_stats_tp_perf_stop == NULL) {
        UMQ_VLOG_ERR(VLOG_UMQ, "trans mode %u ops not support\n", trans_mode);
        return -UMQ_ERR_EINVAL;
    }

    return dfx_tp_ops->umq_tp_stats_tp_perf_stop();
}

int umq_stats_tp_perf_info_get(umq_trans_mode_t trans_mode, char *perf_buf, uint32_t *length)
{
#ifdef UMQ_STATIC_LIB
    if (trans_mode != UMQ_TRANS_MODE_UB && trans_mode != UMQ_TRANS_MODE_UB_PLUS) {
        UMQ_VLOG_ERR(VLOG_UMQ, "umq static library only support UB transport mode\n");
        return -UMQ_ERR_EINVAL;
    }
#endif

    if (trans_mode >= UMQ_TRANS_MODE_MAX) {
        UMQ_VLOG_ERR(VLOG_UMQ, "trans info mode[%u] is invalid\n", trans_mode);
        return -UMQ_ERR_EINVAL;
    }

    umq_dfx_ops_t *dfx_tp_ops = umq_get_dfx_tp_ops(trans_mode);
    if (dfx_tp_ops == NULL || dfx_tp_ops->umq_tp_stats_tp_perf_info_get == NULL) {
        UMQ_VLOG_ERR(VLOG_UMQ, "trans mode %u ops not support\n", trans_mode);
        return -UMQ_ERR_EINVAL;
    }

    return dfx_tp_ops->umq_tp_stats_tp_perf_info_get(perf_buf, length);
}
