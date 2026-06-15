/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2025-2025. All rights reserved.
 * Description: realize func for umq ipc pro-api
 */

#include "umq_ipc_impl.h"
#include "umq_ipc_api.h"

static int umq_tp_ipc_post(uint64_t umqh_tp, umq_buf_t *qbuf, umq_io_option_t *option, umq_buf_t **bad_qbuf)
{
    return umq_ipc_post_impl(umqh_tp, qbuf, option, bad_qbuf);
}

static int umq_tp_ipc_poll(uint64_t umqh_tp, umq_io_option_t *option, umq_buf_t **buf, uint32_t max_buf_count)
{
    return umq_ipc_poll_impl(umqh_tp, option, buf, max_buf_count);
}

static int umq_tp_ipc_interrupt_fd_get(uint64_t umqh_tp, umq_interrupt_option_t *option)
{
    return -1;
}

static int umq_tp_ipc_get_cq_event(uint64_t umqh_tp, umq_interrupt_option_t *option)
{
    return -1;
}

static umq_pro_ops_t g_umq_pro_ipc_ops = {
    .mode = UMQ_TRANS_MODE_IPC,
    .umq_tp_post = umq_tp_ipc_post,
    .umq_tp_poll = umq_tp_ipc_poll,
    .umq_tp_interrupt_fd_get = umq_tp_ipc_interrupt_fd_get,
    .umq_tp_get_cq_event = umq_tp_ipc_get_cq_event,
};

umq_pro_ops_t *umq_pro_ipc_ops_get(void)
{
    return &g_umq_pro_ipc_ops;
}