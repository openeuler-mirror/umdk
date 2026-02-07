/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2026-2026. All rights reserved.
 * Description: Public header file of UMQ dfx
 * Create: 2026-2-4
 * Note:
 * History: 2026-2-4
 */

#include "umq_errno.h"
#include "umq_tp_dfx_api.h"

static int umq_tp_ub_plus_stats_flow_control_get(uint64_t umqh_tp, umq_flow_control_stats_t *flow_control_stats)
{
    return UMQ_SUCCESS;
}

static int umq_tp_ub_plus_stats_qbuf_pool_get(uint64_t umqh_tp, umq_qbuf_pool_stats_t *qbuf_pool_stats)
{
    return UMQ_SUCCESS;
}

static int umq_tp_ub_plus_info_get(uint64_t umqh_tp, umq_info_t *umq_info)
{
    return UMQ_SUCCESS;
}

static int umq_tp_ub_plus_stats_io_get(uint64_t umqh_tp, umq_packet_stats_t *packet_stats)
{
    return UMQ_SUCCESS;
}

static int umq_tp_ub_plus_stats_io_reset(uint64_t umqh_tp)
{
    return UMQ_SUCCESS;
}

static umq_dfx_ops_t g_umq_ub_plus_dfx_ops = {
    .mode = UMQ_TRANS_MODE_UB,
    .umq_tp_stats_flow_control_get = umq_tp_ub_plus_stats_flow_control_get,
    .umq_tp_stats_qbuf_pool_get = umq_tp_ub_plus_stats_qbuf_pool_get,
    .umq_tp_info_get = umq_tp_ub_plus_info_get,
    .umq_tp_stats_io_get = umq_tp_ub_plus_stats_io_get,
    .umq_tp_stats_io_reset = umq_tp_ub_plus_stats_io_reset,
};

umq_dfx_ops_t *umq_ub_plus_dfx_ops_get(void)
{
    return &g_umq_ub_plus_dfx_ops;
}