/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2025-2025. All rights reserved.
 * Description: Public header file of UMQ pro-function, for ib/ub mode
 * Create: 2025-7-7
 * Note:
 * History: 2025-7-7
 */

#ifndef UMQ_PRO_API_H
#define UMQ_PRO_API_H

#include "umq_pro_types.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * User should ensure thread safety if io_lock_free is true
 * Post tx/rx buf to umq
 * @param[in] umqh: umq handle
 * @param[in] qbuf: qbuf need to post. no more than UMQ_BATCH_SIZE work requeses in one call
 * @param[in] io_direction: Set post direction : tx or rx
 * @param[out] bad_qbuf: qbuf list faild to post. user should free these buf
 * Return 0 on success, error code on failure
 */
int umq_post(uint64_t umqh, umq_buf_t *qbuf, umq_io_direction_t io_direction, umq_buf_t **bad_qbuf);

/**
 * User should ensure thread safety if io_lock_free is true
 * Poll tx/rx buf from umq
 * @param[in] umqh: umq handle
 * @param[in] io_direction: Set poll direction : tx or rx, or both
 * @param[out] buf: buffer polled. user should assure length not less than max_buf_count
 * @param[in] max_buf_count: max count of buf, if UMQ_IO_ALL is used, max_buf_count must be at least 2
 * Return count of qbuf polled on success, error code on fail
 */
int umq_poll(uint64_t umqh, umq_io_direction_t io_direction, umq_buf_t **buf, uint32_t max_buf_count);

/**
 * User should ensure thread safety if io_lock_free is true
 * Query umq interrupt fd
 * @param[in] umqh: umq handle
 * @param[in] option: option param. user should specify UMQ_IO_TX or UMQ_IO_RX, or UMQ_FAIL will be returned
 * Return fd >= 0 on success, error code < 0 on failure
 */
int umq_interrupt_fd_get(uint64_t umqh, umq_interrupt_option_t *option);

/**
 * User should ensure thread safety if io_lock_free is true
 * Get interrupt event
 * @param[in] umqh: umq handle to get events
 * @param[in] option: option param. user should specify UMQ_IO_TX or UMQ_IO_RX, or UMQ_FAIL will be returned
 * Return num of interrupt events on success, error code on failure
 */
int umq_get_cq_event(uint64_t umqh, umq_interrupt_option_t *option);

/**
 * Thread safety function
 * User defined control of the context.
 * @param[in] umqh: umq handle
 * @param[in] in: user ioctl cmd;
 * @param[out] out: result of execution;
 * Return 0 on success, error code on failure
 */
int umq_user_ctl(uint64_t umqh, umq_user_ctl_in_t *in, umq_user_ctl_out_t *out);

#ifdef __cplusplus
}
#endif

#endif
