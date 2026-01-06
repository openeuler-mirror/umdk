/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2025-2025. All rights reserved.
 * Description: realize func for umq pro ub api
 * Create: 2025-8-4
 */

#include "umq_vlog.h"
#include "umq_ub_api.h"
#include "umq_ub_impl.h"

static int umq_tp_ub_post(uint64_t umqh_tp, umq_buf_t *qbuf, umq_io_direction_t io_direction, umq_buf_t **bad_qbuf)
{
    return umq_ub_post_impl(umqh_tp, qbuf, io_direction, bad_qbuf);
}

static int umq_tp_ub_poll(uint64_t umqh_tp, umq_io_direction_t io_direction, umq_buf_t **buf, uint32_t max_buf_count)
{
    return umq_ub_poll_impl(umqh_tp, io_direction, buf, max_buf_count);
}

static int umq_tp_ub_interrupt_fd_get(uint64_t umqh_tp, umq_interrupt_option_t *option)
{
    return umq_ub_interrupt_fd_get_impl(umqh_tp, option);
}

static int umq_tp_ub_get_cq_event(uint64_t umqh_tp, umq_interrupt_option_t *option)
{
    return umq_ub_get_cq_event_impl(umqh_tp, option);
}

static umq_pro_ops_t g_umq_pro_ub_ops = {
    .mode = UMQ_TRANS_MODE_UB,
    .umq_tp_post = umq_tp_ub_post,
    .umq_tp_poll = umq_tp_ub_poll,
    .umq_tp_interrupt_fd_get = umq_tp_ub_interrupt_fd_get,
    .umq_tp_get_cq_event = umq_tp_ub_get_cq_event,
};

umq_pro_ops_t *umq_pro_ub_ops_get(void)
{
    return &g_umq_pro_ub_ops;
}
