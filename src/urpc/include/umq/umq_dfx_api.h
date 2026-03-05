/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2026-2026. All rights reserved.
 * Description: Public header file of UMQ dfx
 * Create: 2026-2-4
 * Note:
 * History: 2026-2-4
 */

#ifndef UMQ_DFX_API_H
#define UMQ_DFX_API_H

#include "umq_dfx_types.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Thread safety function
 * Get flow control statistical results.
 * @param[in] umqh: umq handle
 * @param[out] flow_control_stats: flow control statistical results
 * Return 0 on success, error code on failure
 */
int umq_stats_flow_control_get(uint64_t umqh, umq_flow_control_stats_t *flow_control_stats);

/**
 * Thread safety function
 * Convert flow control statistical results to string.
 * @param[in] flow_control_stats: flow control statistical results
 * @param[out] buf: buffer to store the string
 * @param[in] max_buf_len: length of the buffer
 * Return 0 on success, error code on failure
 */
int umq_flow_control_stats_to_str(const umq_flow_control_stats_t *flow_control_stats, char *buf, int max_buf_len);

/**
 * Thread safety function
 * Get qbuf pool statistical results.
 * @param[in] umqh: umq handle
 * @param[out] qbuf_pool_stats: qbuf pool statistical results
 * Return 0 on success, error code on failure
 */
int umq_stats_qbuf_pool_get(uint64_t umqh, umq_qbuf_pool_stats_t *qbuf_pool_stats);

/**
 * Thread safety function
 * Convert qbuf pool statistical results to string.
 * @param[in] qbuf_pool_stats: qbuf pool statistical results
 * @param[out] buf: buffer to store the string
 * @param[in] max_buf_len: length of the buffer
 * Return string len on success, error code on failure
 */
int umq_qbuf_pool_stats_to_str(const umq_qbuf_pool_stats_t *qbuf_pool_stats, char *buf, int max_buf_len);

/**
 * Thread safety function
 * Get umq info results.
 * @param[in] umqh: umq handle
 * @param[out] umq_info: umq info results
 * Return 0 on success, error code on failure
 */
int umq_info_get(uint64_t umqh, umq_info_t *umq_info);

/**
 * Thread safety function
 * Convert umq info results to string.
 * @param[in] umq_info: umq info results
 * @param[out] buf: buffer to store the string
 * @param[in] max_buf_len: length of the buffer
 * Return string len on success, error code on failure
 */
int umq_info_to_str(const umq_info_t *umq_info, char *buf, int max_buf_len);

/**
 * Thread safety function
 * Get io packet statistical results.
 * @param[in] umqh: umq handle
 * @param[out] packet_stats: io packet statistical results
 * Return 0 on success, error code on failure
 */
int umq_stats_io_get(uint64_t umqh, umq_packet_stats_t *packet_stats);

/**
 * Reset the I/O statistical counters.
 * @param[in] umqh: umq handle
 * Return 0 on success, error code on failure
 */
int umq_stats_io_reset(uint64_t umqh);

/**
 * Thread safety function
 * Convert io packet statistical results to string.
 * @param[in] packet_stats: io packet statistical results
 * @param[out] buf: buffer to store the string
 * @param[in] max_buf_len: length of the buffer
 * Return string len on success, error code on failure
 */
int umq_io_stats_to_str(const umq_packet_stats_t *packet_stats, char *buf, int max_buf_len);

/**
 * Thread safety function
 * Get io packet statistical results.
 * @param[out] umq_perf_stats: perf statistical results
 * Return 0 on success, error code on failure
 */
int umq_stats_perf_get(umq_perf_stats_t *umq_perf_stats);

/**
 * Reset the perf statistical counters and config.
 * @param[out] perf_stats_cfg: perf statistical results
 * Return 0 on success, error code on failure
 */
int umq_stats_perf_reset(umq_perf_stats_cfg_t *perf_stats_cfg);

/**
 * Start perf statistics.
 * Return 0 on success, error code on failure
 */
int umq_stats_perf_start(void);

/**
 * Stop perf statistics.
 * Return 0 on success, error code on failure
 */
int umq_stats_perf_stop(void);

/**
 * Thread safety function
 * Convert the perf statistics result to a string.
 * @param[in] umq_perf_stats: perf statistical results
 * @param[in] buf: buffer to store the string
 * @param[in] max_buf_szie: length of the buffer
 * Return string len on success, the length of the character to be written.
 * -UMQ_ERR_EINVAL: Invalid parameter
 */
int umq_stats_perf_to_str(umq_perf_stats_t *umq_perf_stats, char *buf, int max_buf_len);

#ifdef __cplusplus
}
#endif

#endif