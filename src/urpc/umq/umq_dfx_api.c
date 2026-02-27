/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2026-2026. All rights reserved.
 * Description: realize func for umq dfx api
 * Create: 2026-2-4
 */

#include "umq_errno.h"
#include "umq_qbuf_pool.h"
#include "umq_huge_qbuf_pool.h"
#include "umq_inner.h"
#include <stdarg.h>

#define UMQ_DFX_EQUALS "=================================================================================="
#define UMQ_DFX_UNDERLINE "----------------------------------------------------------------------------------"
#define TRANS_MODE_NAME_SIZE 20

#define UMQ_DFX_SNPRINTF_BUF(__buf, __max_buf_len, __offset, __err_label, __format, ...)            \
    do {                                                                                            \
        int __ret = snprintf((__buf) + (__offset), (__max_buf_len) - (__offset),                    \
                            __format, ##__VA_ARGS__);                                               \
        if (__ret < 0 || __ret >= ((__max_buf_len) - (__offset))) {                                 \
            UMQ_VLOG_ERR(VLOG_UMQ,                                                                  \
                "format output failed, ret: %d, errno %d, str size %d, max buf len %d\n",           \
                __ret, errno, (__offset), (__max_buf_len));                                         \
            goto __err_label;                                                                       \
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
    UMQ_DFX_SNPRINTF_BUF(buf, max_buf_len, str_size, FORMAT_ERR, "%s\n", UMQ_DFX_EQUALS);
    UMQ_DFX_SNPRINTF_BUF(buf, max_buf_len, str_size, FORMAT_ERR, "%s\n",
        "                               Flow Control Statistics");
    UMQ_DFX_SNPRINTF_BUF(buf, max_buf_len, str_size, FORMAT_ERR, "%s\n", UMQ_DFX_EQUALS);
    UMQ_DFX_SNPRINTF_BUF(buf, max_buf_len, str_size, FORMAT_ERR, "%-40s %-40s\n", "Type", "Value");

    // format pool credit statistics
    UMQ_DFX_SNPRINTF_BUF(buf, max_buf_len, str_size, FORMAT_ERR, "%s\n", UMQ_DFX_UNDERLINE);
    UMQ_DFX_SNPRINTF_BUF(buf, max_buf_len, str_size, FORMAT_ERR, "%s\n",
        "                               Pool Credit Statistics");
    UMQ_DFX_SNPRINTF_BUF(buf, max_buf_len, str_size, FORMAT_ERR, "%s\n", UMQ_DFX_UNDERLINE);
    UMQ_DFX_SNPRINTF_BUF(buf, max_buf_len, str_size, FORMAT_ERR,
        "%-40s %-40lu\n", "Pool Idle", flow_control_stats->pool_credit.pool_idle);
    UMQ_DFX_SNPRINTF_BUF(buf, max_buf_len, str_size, FORMAT_ERR,
        "%-40s %-40lu\n", "Pool Allocated", flow_control_stats->pool_credit.pool_be_allocated);
    UMQ_DFX_SNPRINTF_BUF(buf, max_buf_len, str_size, FORMAT_ERR,
        "%-40s %-40lu\n", "Total Pool Idle", flow_control_stats->pool_credit.total_pool_idle);
    UMQ_DFX_SNPRINTF_BUF(buf, max_buf_len, str_size, FORMAT_ERR,
        "%-40s %-40lu\n", "Total Pool Allocated", flow_control_stats->pool_credit.total_pool_be_allocated);
    UMQ_DFX_SNPRINTF_BUF(buf, max_buf_len, str_size, FORMAT_ERR,
        "%-40s %-40lu\n", "Total Pool Post RX Err", flow_control_stats->pool_credit.total_pool_post_rx_err);

    // format queue credit statistics
    UMQ_DFX_SNPRINTF_BUF(buf, max_buf_len, str_size, FORMAT_ERR, "%s\n", UMQ_DFX_UNDERLINE);
    UMQ_DFX_SNPRINTF_BUF(buf, max_buf_len, str_size, FORMAT_ERR,
        "                              Queue Credit Statistics\n");
    UMQ_DFX_SNPRINTF_BUF(buf, max_buf_len, str_size, FORMAT_ERR, "%s\n", UMQ_DFX_UNDERLINE);
    UMQ_DFX_SNPRINTF_BUF(buf, max_buf_len, str_size, FORMAT_ERR,
        "%-40s %-40lu\n", "Queue Idle", flow_control_stats->queue_credit.queue_idle);
    UMQ_DFX_SNPRINTF_BUF(buf, max_buf_len, str_size, FORMAT_ERR,
        "%-40s %-40lu\n", "Queue Allocated", flow_control_stats->queue_credit.queue_be_allocated);
    UMQ_DFX_SNPRINTF_BUF(buf, max_buf_len, str_size, FORMAT_ERR,
        "%-40s %-40lu\n", "Queue Acquired", flow_control_stats->queue_credit.queue_acquired);
    UMQ_DFX_SNPRINTF_BUF(buf, max_buf_len, str_size, FORMAT_ERR,
        "%-40s %-40lu\n", "Total Queue Idle", flow_control_stats->queue_credit.total_queue_idle);
    UMQ_DFX_SNPRINTF_BUF(buf, max_buf_len, str_size, FORMAT_ERR,
        "%-40s %-40lu\n", "Total Queue Acquired", flow_control_stats->queue_credit.total_queue_acquired);
    UMQ_DFX_SNPRINTF_BUF(buf, max_buf_len, str_size, FORMAT_ERR,
        "%-40s %-40lu\n", "Total Queue Allocated", flow_control_stats->queue_credit.total_queue_be_allocated);
    UMQ_DFX_SNPRINTF_BUF(buf, max_buf_len, str_size, FORMAT_ERR,
        "%-40s %-40lu\n", "Total Queue Post TX Success", flow_control_stats->queue_credit.total_queue_post_tx_success);
    UMQ_DFX_SNPRINTF_BUF(buf, max_buf_len, str_size, FORMAT_ERR,
        "%-40s %-40lu\n", "Total Queue Post TX Err", flow_control_stats->queue_credit.total_queue_post_tx_err);
    UMQ_DFX_SNPRINTF_BUF(buf, max_buf_len, str_size, FORMAT_ERR,
        "%-40s %-40lu\n", "Total Queue Acquired Err", flow_control_stats->queue_credit.total_queue_acquired_err);

    // format packet statistics
    UMQ_DFX_SNPRINTF_BUF(buf, max_buf_len, str_size, FORMAT_ERR, "%s\n", UMQ_DFX_UNDERLINE);
    UMQ_DFX_SNPRINTF_BUF(buf, max_buf_len, str_size, FORMAT_ERR, "                              Packet Statistics\n");
    UMQ_DFX_SNPRINTF_BUF(buf, max_buf_len, str_size, FORMAT_ERR, "%s\n", UMQ_DFX_UNDERLINE);
    UMQ_DFX_SNPRINTF_BUF(buf, max_buf_len, str_size, FORMAT_ERR,
        "%-40s %-40lu\n", "Send Cnt", flow_control_stats->packet_stats.send_cnt);
    UMQ_DFX_SNPRINTF_BUF(buf, max_buf_len, str_size, FORMAT_ERR,
        "%-40s %-40lu\n", "Send Success", flow_control_stats->packet_stats.send_success);
    UMQ_DFX_SNPRINTF_BUF(buf, max_buf_len, str_size, FORMAT_ERR,
        "%-40s %-40lu\n", "Recv Cnt", flow_control_stats->packet_stats.recv_cnt);
    UMQ_DFX_SNPRINTF_BUF(buf, max_buf_len, str_size, FORMAT_ERR,
        "%-40s %-40lu\n", "Send Error Cnt", flow_control_stats->packet_stats.send_error_cnt);
    UMQ_DFX_SNPRINTF_BUF(buf, max_buf_len, str_size, FORMAT_ERR,
        "%-40s %-40lu\n", "Recv Error Cnt", flow_control_stats->packet_stats.recv_error_cnt);
    UMQ_DFX_SNPRINTF_BUF(buf, max_buf_len, str_size, FORMAT_ERR, "%s\n", UMQ_DFX_UNDERLINE);
    UMQ_DFX_SNPRINTF_BUF(buf, max_buf_len, str_size, FORMAT_ERR, "%s\n", UMQ_DFX_EQUALS);

    return str_size;

FORMAT_ERR:
    return -UMQ_ERR_EINVAL;
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
    if (qbuf_pool_stats == NULL || buf == NULL || max_buf_len <= 0) {
        UMQ_VLOG_ERR(VLOG_UMQ, "invalid parameter\n");
        return -UMQ_ERR_EINVAL;
    }

    int str_size = 0;
    (void)memset(buf, 0, max_buf_len);

    // format qbuf pool statistics
    UMQ_DFX_SNPRINTF_BUF(buf, max_buf_len, str_size, FORMAT_ERR, "%s\n", UMQ_DFX_EQUALS);
    UMQ_DFX_SNPRINTF_BUF(buf, max_buf_len, str_size, FORMAT_ERR,
        "%s\n", "                          Qbuf Pool Statistics\n");
    UMQ_DFX_SNPRINTF_BUF(buf, max_buf_len, str_size, FORMAT_ERR, "%s\n", UMQ_DFX_EQUALS);
    UMQ_DFX_SNPRINTF_BUF(buf, max_buf_len, str_size, FORMAT_ERR, "%-40s %-40s\n", "Type", "Value");
    
    for (uint32_t i = 0; i < qbuf_pool_stats->num; i++) {
        const umq_qbuf_pool_info_t *info = &qbuf_pool_stats->qbuf_pool_info[i];
        
        // Add Pool Index as a subheading
        UMQ_DFX_SNPRINTF_BUF(buf, max_buf_len, str_size, FORMAT_ERR, "%s\n", UMQ_DFX_UNDERLINE);
        UMQ_DFX_SNPRINTF_BUF(buf, max_buf_len, str_size, FORMAT_ERR,
            "                              Pool Index: %u\n", i);
        UMQ_DFX_SNPRINTF_BUF(buf, max_buf_len, str_size, FORMAT_ERR, "%s\n", UMQ_DFX_UNDERLINE);
        UMQ_DFX_SNPRINTF_BUF(buf, max_buf_len, str_size, FORMAT_ERR,
            "%-40s %-40s\n", "Mode", info->mode == UMQ_BUF_SPLIT ? "SPLIT" : "COMBINE");
        UMQ_DFX_SNPRINTF_BUF(buf, max_buf_len, str_size, FORMAT_ERR, "%-40s %-40lu\n", "Total Size", info->total_size);
        UMQ_DFX_SNPRINTF_BUF(buf, max_buf_len, str_size, FORMAT_ERR,
            "%-40s %-40lu\n", "Total Block Num", info->total_block_num);
        UMQ_DFX_SNPRINTF_BUF(buf, max_buf_len, str_size, FORMAT_ERR, "%-40s %-40u\n", "Block Size", info->block_size);
        UMQ_DFX_SNPRINTF_BUF(buf, max_buf_len, str_size, FORMAT_ERR,
            "%-40s %-40u\n", "Headroom Size", info->headroom_size);
        UMQ_DFX_SNPRINTF_BUF(buf, max_buf_len, str_size, FORMAT_ERR, "%-40s %-40u\n", "Data Size", info->data_size);
        UMQ_DFX_SNPRINTF_BUF(buf, max_buf_len, str_size, FORMAT_ERR, "%-40s %-40u\n", "Buf Size", info->buf_size);
        UMQ_DFX_SNPRINTF_BUF(buf, max_buf_len, str_size, FORMAT_ERR,
            "%-40s %-40u\n", "UMQ Buf Size", info->umq_buf_t_size);

        if (info->mode == UMQ_BUF_SPLIT) {
            UMQ_DFX_SNPRINTF_BUF(buf, max_buf_len, str_size, FORMAT_ERR,
                "%-40s %lu blocks, %lu size\n", "Available Mem - With Data",
                info->available_mem.split.block_num_with_data, info->available_mem.split.size_with_data);
            UMQ_DFX_SNPRINTF_BUF(buf, max_buf_len, str_size, FORMAT_ERR,
                "%-40s %lu blocks, %lu size\n", "Available Mem - Without Data",
                info->available_mem.split.block_num_without_data, info->available_mem.split.size_without_data);
        } else {
            UMQ_DFX_SNPRINTF_BUF(buf, max_buf_len, str_size, FORMAT_ERR,
                "%-40s %lu blocks, %lu size\n", "Available Mem - With Data",
                info->available_mem.combine.block_num_with_data, info->available_mem.combine.size_with_data);
        }
    }
    UMQ_DFX_SNPRINTF_BUF(buf, max_buf_len, str_size, FORMAT_ERR, "%s\n", UMQ_DFX_UNDERLINE);
    UMQ_DFX_SNPRINTF_BUF(buf, max_buf_len, str_size, FORMAT_ERR, "%s\n", UMQ_DFX_EQUALS);

    return str_size;

FORMAT_ERR:
    return -UMQ_ERR_EINVAL;
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
    if (umq_info == NULL || buf == NULL || max_buf_len <= 0) {
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
    UMQ_DFX_SNPRINTF_BUF(buf, max_buf_len, str_size, FORMAT_ERR, "%s\n", UMQ_DFX_EQUALS);
    UMQ_DFX_SNPRINTF_BUF(buf, max_buf_len, str_size, FORMAT_ERR, "%s\n", "                               UMQ Info\n");
    UMQ_DFX_SNPRINTF_BUF(buf, max_buf_len, str_size, FORMAT_ERR, "%s\n", UMQ_DFX_EQUALS);
    UMQ_DFX_SNPRINTF_BUF(buf, max_buf_len, str_size, FORMAT_ERR, "%-40s %-40s\n", "Info", "Value");
    UMQ_DFX_SNPRINTF_BUF(buf, max_buf_len, str_size, FORMAT_ERR, "%s\n", UMQ_DFX_UNDERLINE);
    UMQ_DFX_SNPRINTF_BUF(buf, max_buf_len, str_size, FORMAT_ERR,
        "%-40s %-40s\n", "Trans Mode", trans_mode_map[umq_info->trans_mode]);

    if (umq_info->trans_mode == UMQ_TRANS_MODE_UB || umq_info->trans_mode == UMQ_TRANS_MODE_UB_PLUS) {
        UMQ_DFX_SNPRINTF_BUF(buf, max_buf_len, str_size, FORMAT_ERR, "%-40s %-40u\n", "UMQ ID", umq_info->ub.umq_id);
        UMQ_DFX_SNPRINTF_BUF(buf, max_buf_len, str_size, FORMAT_ERR,
            "%-40s " EID_FMT "\n", "EID", EID_ARGS(umq_info->ub.eid));
        UMQ_DFX_SNPRINTF_BUF(buf, max_buf_len, str_size, FORMAT_ERR,
            "%-40s %-40s\n", "Dev Name", umq_info->ub.dev_name);
        UMQ_DFX_SNPRINTF_BUF(buf, max_buf_len, str_size, FORMAT_ERR,
            "%-40s %-40u\n", "Local IO Jetty ID", umq_info->ub.local_io_jetty_id);
        UMQ_DFX_SNPRINTF_BUF(buf, max_buf_len, str_size, FORMAT_ERR,
            "%-40s %-40u\n", "Local FC Jetty ID", umq_info->ub.local_fc_jetty_id);
        UMQ_DFX_SNPRINTF_BUF(buf, max_buf_len, str_size, FORMAT_ERR,
            "%-40s %-40u\n", "Remote IO Jetty ID", umq_info->ub.remote_io_jetty_id);
        UMQ_DFX_SNPRINTF_BUF(buf, max_buf_len, str_size, FORMAT_ERR,
            "%-40s %-40u\n", "Remote FC Jetty ID", umq_info->ub.remote_fc_jetty_id);
    }
    UMQ_DFX_SNPRINTF_BUF(buf, max_buf_len, str_size, FORMAT_ERR, "%s\n", UMQ_DFX_UNDERLINE);
    UMQ_DFX_SNPRINTF_BUF(buf, max_buf_len, str_size, FORMAT_ERR, "%s\n", UMQ_DFX_EQUALS);

    return str_size;

FORMAT_ERR:
    return -UMQ_ERR_EINVAL;
}

int umq_stats_io_get(uint64_t umqh, umq_packet_stats_t *packet_stats)
{
    return UMQ_SUCCESS;
}

int umq_stats_io_reset(uint64_t umqh)
{
    return UMQ_SUCCESS;
}

int umq_stats_perf_get(umq_perf_stats_t *umq_perf_stats)
{
    return UMQ_SUCCESS;
}

int umq_stats_perf_reset(umq_perf_stats_cfg_t *perf_stats_cfg)
{
    return UMQ_SUCCESS;
}
