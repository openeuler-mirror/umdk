/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2025-2025. All rights reserved.
 * Description: Public header file of UMQ transport layer pro-function
 * Create: 2025-7-16
 * Note:
 * History: 2025-7-16
 */

#ifndef UMQ_PRO_TP_API_H
#define UMQ_PRO_TP_API_H

#include "umq_pro_types.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct umq_pro_ops {
    umq_trans_mode_t mode;

   /**
    * User should ensure thread safety if io_lock_free is true
    * Post tx/rx buf to umq
    * @param[in] umqh_tp: umq handle
    * @param[in] qbuf: qbuf need to post. no more than UMQ_BATCH_SIZE work requests once
    * @param[in] option: Set post direction : tx or rx
    * @param[out] bad_qbuf: qbuf list failed to post. user should free these buf
    * Return 0 on success, error code on failure
    */
    int (*umq_tp_post)(uint64_t umqh_tp, umq_buf_t *qbuf, umq_io_option_t *option, umq_buf_t **bad_qbuf);

    /**
    * User should ensure thread safety if io_lock_free is true
    * Poll tx/rx buf from umq
    * @param[in] umqh_tp: umq handle
    * @param[in] option: 1. Set poll direction : tx or rx
                         2. Set tp handle idx (for share transport main umq)
    * @param[out] buf: buffer polled. user should assure length not less than max_buf_count
    * @param[in] buf_count: max count of buf
    * Return count of qbuf polled
    */
    int (*umq_tp_poll)(uint64_t umqh_tp, umq_io_option_t *option, umq_buf_t **buf, uint32_t max_buf_count);

    /**
    * User should ensure thread safety if io_lock_free is true
    * Query umq interrupt fd
    * @param[in] umqh_tp: umq handle
    * @param[in] option: option param. user should specify UMQ_IO_TX or UMQ_IO_RX, or UMQ_FAIL will be returned
    * Return fd >= 0 on success, error code < 0 on failure
    */
    int (*umq_tp_interrupt_fd_get)(uint64_t umqh_tp, umq_interrupt_option_t *option);

    /**
    * User should ensure thread safety if io_lock_free is true
    * Query umq interrupt fd table
    * @param[in] umqh_tp: umq handle
    * @param[in] option: option param
    *                    1. user get io fd should specify UMQ_IO_TX or UMQ_IO_RX
    *                    2. user get tp handle fd should specify tp_handle_idx
    *                    otherwise UMQ_FAIL will be returned
    * @param[out] fd_table: interrupt fd table
    * if get event fd, fd_type set UMQ_FD_EVENT, return event fd (used to notify the user to return credit)
    * Return: 0 on success, other value on error
    */
    int (*umq_tp_interrupt_fd_list_get)(uint64_t umqh,
        umq_interrupt_option_t *option, umq_interrupt_fd_list_t *fd_list);

    /**
    * User should ensure thread safety if io_lock_free is true
    * Get interrupt event
    * @param[in] umqh_tp: umq handle to get events
    * @param[out] nevents: event num corresponding to umqh_tp
    * @param[in] option: option param. user should specify UMQ_IO_TX or UMQ_IO_RX, or UMQ_FAIL will be returned
    * Return num of interrupt events if >= 0, error code if < 0
    */
    int (*umq_tp_get_cq_event)(uint64_t umqh_tp, umq_interrupt_option_t *option);
} umq_pro_ops_t;

typedef umq_pro_ops_t* (*umq_pro_ops_get_t)(void);

#ifdef __cplusplus
}
#endif

#endif
