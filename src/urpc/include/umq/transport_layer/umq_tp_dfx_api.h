/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2026-2026. All rights reserved.
 * Description: Public header file of UMQ dfx
 * Create: 2026-2-4
 * Note:
 * History: 2026-2-4
 */

#ifndef UMQ_TP_DFX_API_H
#define UMQ_TP_DFX_API_H

#include "umq_dfx_types.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct umq_dfx_ops {
    umq_trans_mode_t mode;
    /**
     * Thread safety function
     * Get flow control statistical results.
     * @param[in] umqh_tp: umq handle
     * @param[out] flow_control_stats: flow control statistical results
     * Return 0 on success, error code on failure
     */
    int (*umq_tp_stats_flow_control_get)(uint64_t umqh_tp, umq_flow_control_stats_t *flow_control_stats);

    /**
     * Thread safety function
     * Get qbuf pool statistical results.
     * @param[in] umqh_tp: umq handle
     * @param[out] qbuf_pool_stats: qbuf pool statistical results
     * Return 0 on success, error code on failure
     */
    int (*umq_tp_stats_qbuf_pool_get)(uint64_t umqh_tp, umq_qbuf_pool_stats_t *qbuf_pool_stats);

    /**
     * Thread safety function
     * Get umq info results.
     * @param[in] umqh_tp: umq handle
     * @param[out] umq_info: umq info results
     * Return 0 on success, error code on failure
     */
    int (*umq_tp_info_get)(uint64_t umqh_tp, umq_info_t *umq_info);

    /**
     * Thread safety function
     * Get io packet statistical results.
     * @param[in] umqh_tp: umq handle
     * @param[out] packet_state: io packet statistical results
     * Return 0 on success, error code on failure
     */
    int (*umq_tp_stats_io_get)(uint64_t umqh_tp, umq_packet_stats_t *packet_stats);

    /**
     * Reset the I/O statistical counters.
     * @param[in] umqh_tp: umq handle
     * Return 0 on success, error code on failure
     */
    int (*umq_tp_stats_io_reset)(uint64_t umqh_tp);

    /**
     * start tp performance statistics.
     * Return: 0 on success, other value on error
     */
    int (*umq_tp_stats_tp_perf_start)(void);

    /**
     * Stop tp performance statistics.
     * Return: 0 on success, other value on error
     */
    int (*umq_tp_stats_tp_perf_stop)(void);

    /**
     * Get tp performance info statistical results.
     * @param[out] perf_buf: buffer to store performance information;
     * @param[out] length: length of performance information;
     * Return: 0 on success, other value on error
     */
    int (*umq_tp_stats_tp_perf_info_get)(char *perf_buf, uint32_t *length);
} umq_dfx_ops_t;

typedef umq_dfx_ops_t* (*umq_dfx_ops_get_t)(void);

#ifdef __cplusplus
}
#endif

#endif