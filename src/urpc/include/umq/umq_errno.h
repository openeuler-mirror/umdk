/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2025-2025. All rights reserved.
 * Description: Public header file of UMQ errno
 * Create: 2025-7-16
 * Note:
 * History: 2025-7-16
 */

#ifndef UMQ_ERRNO_H
#define UMQ_ERRNO_H

#include <errno.h>

#ifdef __cplusplus
extern "C" {
#endif

#define UMQ_SUCCESS                                (0)
#define UMQ_FAIL                                   (-1)
#define UMQ_INVALID_HANDLE                         (0)
#define UMQ_INVALID_FD                             (-1)

#define UMQ_ERR_EPERM                              (EPERM)
#define UMQ_ERR_EAGAIN                             (EAGAIN)
#define UMQ_ERR_ENOMEM                             (ENOMEM)
#define UMQ_ERR_EBUSY                              (EBUSY)
#define UMQ_ERR_EEXIST                             (EEXIST)
#define UMQ_ERR_EINVAL                             (EINVAL)
#define UMQ_ERR_ENODEV                             (ENODEV)

typedef enum umq_buf_status {
    UMQ_BUF_SUCCESS = 0,
    UMQ_BUF_UNSUPPORTED_OPCODE_ERR,     /* Opcode in the WR is not supported */
    UMQ_BUF_LOC_LEN_ERR,                /* Local data too long error */
    UMQ_BUF_LOC_OPERATION_ERR,          /* Local operation err */
    UMQ_BUF_LOC_ACCESS_ERR,             /* Access to local memory error */
    UMQ_BUF_REM_RESP_LEN_ERR,           /* Local Operation Error, with sub-status of Remote Response Length Error */
    UMQ_BUF_REM_UNSUPPORTED_REQ_ERR,
    UMQ_BUF_REM_OPERATION_ERR,          /* Error when target jetty can not complete the operation */
    UMQ_BUF_REM_ACCESS_ABORT_ERR,       /* Error when target jetty access memory error or abort the operation */
    UMQ_BUF_ACK_TIMEOUT_ERR,            /* Retransmission exceeds the maximum number of times */
    UMQ_BUF_RNR_RETRY_CNT_EXC_ERR,      /* RNR retries exceeded the maximum number: remote jfr has no buffer */
    UMQ_BUF_WR_FLUSH_ERR,               /* Jetty in the error state, and the hardware has processed the WR. */
    UMQ_BUF_WR_SUSPEND_DONE,            /* Hardware constructs a fake CQE, and user_ctx is invalid. */
    UMQ_BUF_WR_FLUSH_ERR_DONE,          /* Hardware constructs a fake CQE, and user_ctx is invalid. */
    UMQ_BUF_WR_UNHANDLED,               /* Return of flush jetty/jfs, and the hardware has not processed the WR. */
    UMQ_BUF_LOC_DATA_POISON,            /* Local Data Poison */
    UMQ_BUF_REM_DATA_POISON,            /* Remote Data Poison */

    UMQ_BUF_FLOW_CONTROL_UPDATE = 128,  /* Umq flow control window is updated, this is not error case */
    UMQ_MEMPOOL_UPDATE_SUCCESS,
    UMQ_MEMPOOL_UPDATE_FAILED,
} umq_buf_status_t;

#ifdef __cplusplus
}
#endif

#endif