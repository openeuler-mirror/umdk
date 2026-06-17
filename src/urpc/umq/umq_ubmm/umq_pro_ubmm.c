/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2025-2025. All rights reserved.
 * Description: realize func for umq ubmm pro-api
 * Create: 2025-8-18
 */

#include "umq_ubmm_api.h"
#include "umq_ubmm_impl.h"

static int umq_tp_ubmm_post(uint64_t umqh_tp, umq_buf_t *qbuf, umq_io_option_t *option, umq_buf_t **bad_qbuf)
{
    return -1;
}

static int umq_tp_ubmm_poll(uint64_t umqh_tp, umq_poll_option_t *poll_option, umq_buf_t **buf, uint32_t max_buf_count)
{
    return -1;
}

static int umq_tp_ubmm_interrupt_fd_get(uint64_t umqh_tp, umq_interrupt_option_t *option)
{
    return umq_ubmm_interrupt_fd_get_impl(umqh_tp, option);
}

static int umq_tp_ubmm_get_cq_event(uint64_t umqh_tp, umq_interrupt_option_t *option)
{
    return umq_ubmm_get_cq_event_impl(umqh_tp, option);
}

static umq_pro_ops_t g_umq_pro_ubmm_ops = {
    .mode = UMQ_TRANS_MODE_UBMM,
    .umq_tp_post = umq_tp_ubmm_post,
    .umq_tp_poll = umq_tp_ubmm_poll,
    .umq_tp_interrupt_fd_get = umq_tp_ubmm_interrupt_fd_get,
    .umq_tp_get_cq_event = umq_tp_ubmm_get_cq_event,
};

umq_pro_ops_t *umq_pro_ubmm_ops_get(void)
{
    return &g_umq_pro_ubmm_ops;
}