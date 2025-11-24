/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2025-2025. All rights reserved.
 * Description: realize func for umq api
 * Create: 2025-7-17
 */
#include <stdio.h>
#include <stdlib.h>
#include <dlfcn.h>

#include "perf.h"
#include "umq_vlog.h"
#include "umq_inner.h"
#include "umq_errno.h"

int umq_post(uint64_t umqh, umq_buf_t *qbuf, umq_io_direction_t io_direction, umq_buf_t **bad_qbuf)
{
    uint64_t start_timestamp = umq_perf_get_start_timestamp();
    umq_t *umq = (umq_t *)(uintptr_t)umqh;

    if ((umq == NULL) || (umq->umqh_tp == UMQ_INVALID_HANDLE) || (umq->pro_tp_ops == NULL) ||
        (umq->pro_tp_ops->umq_tp_post == NULL) || qbuf == NULL || bad_qbuf == NULL) {
        UMQ_LIMIT_VLOG_ERR("umqh or qbuf invalid\n");
        return -UMQ_ERR_EINVAL;
    }

    int ret = umq->pro_tp_ops->umq_tp_post(umq->umqh_tp, qbuf, io_direction, bad_qbuf);
    umq_perf_record_write_with_direction(UMQ_PERF_RECORD_POST_ALL, start_timestamp, io_direction);
    return ret;
}

static inline void umq_perf_record_write_poll(uint64_t start, umq_io_direction_t io_direction, bool is_empty)
{
    if (is_empty) {
        umq_perf_record_write_with_direction(UMQ_PERF_RECORD_POLL_ALL_EMPTY, start, io_direction);
        return;
    }
    umq_perf_record_write_with_direction(UMQ_PERF_RECORD_POLL_ALL, start, io_direction);
}

int umq_poll(uint64_t umqh, umq_io_direction_t io_direction, umq_buf_t **buf, uint32_t max_buf_count)
{
    uint64_t start_timestamp = umq_perf_get_start_timestamp();
    umq_t *umq = (umq_t *)(uintptr_t)umqh;

    if ((umq == NULL) || (umq->umqh_tp == UMQ_INVALID_HANDLE) || (umq->pro_tp_ops == NULL) ||
        (umq->pro_tp_ops->umq_tp_poll == NULL) || buf == NULL || max_buf_count == 0) {
        UMQ_LIMIT_VLOG_ERR("param invalid\n");
        return -UMQ_ERR_EINVAL;
    }

    if (io_direction == UMQ_IO_ALL && max_buf_count == 1) {
        UMQ_LIMIT_VLOG_ERR("poll umq tx and rx needs at least 2 buf\n");
        return -UMQ_ERR_EINVAL;
    }

    int ret = umq->pro_tp_ops->umq_tp_poll(umq->umqh_tp, io_direction, buf, max_buf_count);
    umq_perf_record_write_poll(start_timestamp, io_direction, ret == 0);
    return ret;
}

int umq_interrupt_fd_get(uint64_t umqh, umq_interrupt_option_t *option)
{
    umq_t *umq = (umq_t *)(uintptr_t)umqh;

    if (option == NULL || (umq == NULL) || (umq->umqh_tp == UMQ_INVALID_HANDLE) || (umq->pro_tp_ops == NULL) ||
        (umq->pro_tp_ops->umq_tp_interrupt_fd_get == NULL)) {
        UMQ_VLOG_ERR("umqh or option invalid\n");
        return -UMQ_ERR_EINVAL;
    }

    return umq->pro_tp_ops->umq_tp_interrupt_fd_get(umq->umqh_tp, option);
}

int umq_get_cq_event(uint64_t umqh, umq_interrupt_option_t *option)
{
    umq_t *umq = (umq_t *)(uintptr_t)umqh;

    if (option == NULL || (umq == NULL) || (umq->umqh_tp == UMQ_INVALID_HANDLE) || (umq->pro_tp_ops == NULL) ||
        (umq->pro_tp_ops->umq_tp_get_cq_event == NULL)) {
        UMQ_VLOG_ERR("umqh or option invalid\n");
        return -UMQ_ERR_EINVAL;
    }

    return umq->pro_tp_ops->umq_tp_get_cq_event(umq->umqh_tp, option);
}
