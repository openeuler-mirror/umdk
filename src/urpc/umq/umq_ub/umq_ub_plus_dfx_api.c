/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2026-2026. All rights reserved.
 * Description: realize func for umq ub plus dfx api
 * Create: 2026-2-4
 * Note:
 * History: 2026-2-4
 */

#include "umq_errno.h"
#include "umq_ub_impl.h"
#include "umq_tp_dfx_api.h"

static int umq_tp_ub_plus_stats_flow_control_get(uint64_t umqh_tp, umq_flow_control_stats_t *flow_control_stats)
{
    return umq_ub_plus_stats_flow_control_get_impl(umqh_tp, flow_control_stats);
}

static int umq_tp_ub_plus_stats_qbuf_pool_get(uint64_t umqh_tp, umq_qbuf_pool_stats_t *qbuf_pool_stats)
{
    return umq_ub_stats_qbuf_pool_get_impl(umqh_tp, qbuf_pool_stats);
}

static int umq_tp_ub_plus_info_get(uint64_t umqh_tp, umq_info_t *umq_info)
{
    return umq_ub_info_get_impl(umqh_tp, umq_info);
}

static int umq_tp_ub_plus_stats_io_get(uint64_t umqh_tp, umq_packet_stats_t *packet_stats)
{
    return umq_ub_stats_io_get_impl(umqh_tp, packet_stats);
}

static int umq_tp_ub_plus_stats_io_reset(uint64_t umqh_tp)
{
    return umq_ub_stats_io_reset_impl(umqh_tp);
}

static umq_dfx_ops_t g_umq_ub_plus_dfx_ops = {
    .mode = UMQ_TRANS_MODE_UB_PLUS,
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