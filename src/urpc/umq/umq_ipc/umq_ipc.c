/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2025-2025. All rights reserved.
 * Description: realize func for umq ipc api
 */
#include <stdio.h>
#include <stdlib.h>
#include <dlfcn.h>
#include <unistd.h>

#include "umq_vlog.h"
#include "umq_errno.h"
#include "umq_ipc_api.h"
#include "umq_qbuf_pool.h"
#include "umq_ipc_impl.h"

static uint8_t *umq_tp_ipc_init(umq_init_cfg_t *cfg, void *addr, uint64_t len)
{
    return umq_ipc_ctx_init_impl(cfg);
}

static void umq_tp_ipc_uninit(uint8_t *ctx)
{
    umq_ipc_ctx_uninit_impl(ctx);
}

static uint64_t umq_tp_ipc_create(uint64_t umqh, uint8_t *ctx, umq_create_option_t *option)
{
    return umq_ipc_create_impl(umqh, ctx, option);
}

static int umq_tp_ipc_destroy(uint64_t umqh_tp)
{
    return umq_ipc_destroy_impl(umqh_tp);
}

static uint32_t umq_tp_ipc_bind_info_get(uint64_t umqh_tp, uint8_t *bind_info, uint32_t bind_info_size)
{
    return umq_ipc_bind_info_get_impl(umqh_tp, bind_info, bind_info_size);
}

static int umq_tp_ipc_bind(uint64_t umqh_tp, uint8_t *bind_info, uint32_t bind_info_size)
{
    return umq_ipc_bind_impl(umqh_tp, bind_info, bind_info_size);
}

static int umq_tp_ipc_unbind(uint64_t umqh_tp)
{
    return umq_ipc_unbind_impl(umqh_tp);
}

static umq_state_t umq_tp_ipc_state_get(uint64_t umqh_tp)
{
    return QUEUE_STATE_READY;
}

static umq_buf_t *umq_tp_ipc_buf_alloc(uint32_t request_size, uint32_t request_qbuf_num, uint64_t umqh_tp,
    umq_alloc_option_t *option)
{
    return umq_ipc_buf_alloc_impl(request_size, request_qbuf_num, umqh_tp, option);
}

static void umq_tp_ipc_buf_free(umq_buf_t *qbuf, uint64_t umqh_tp)
{
    umq_tp_ipc_buf_free_impl(qbuf, umqh_tp);
}

static void umq_tp_ipc_log_config_set(umq_log_config_t *config)
{
    return;
}

static int umq_tp_ipc_buf_headroom_reset(umq_buf_t *qbuf, uint16_t headroom_size)
{
    return umq_tp_ipc_buf_headroom_reset_impl(qbuf, headroom_size);
}

static int umq_tp_ipc_enqueue(uint64_t umqh_tp, umq_buf_t *qbuf, umq_buf_t **bad_qbuf)
{
    return umq_ipc_enqueue_impl(umqh_tp, qbuf, bad_qbuf);
}

static umq_buf_t *umq_tp_ipc_dequeue(uint64_t umqh_tp)
{
    return umq_ipc_dequeue_impl(umqh_tp);
}

static void umq_tp_ipc_notify(uint64_t umqh_tp)
{
    umq_ipc_notify_impl(umqh_tp);
}

static int umq_tp_ipc_rearm_interrupt(uint64_t umqh_tp, bool solicated, umq_interrupt_option_t *option)
{
    return umq_ipc_rearm_interrupt_impl(umqh_tp, solicated, option);
}

static int32_t umq_tp_ipc_wait_interrupt(uint64_t wait_umqh_tp, int time_out, umq_interrupt_option_t *option)
{
    return umq_ipc_wait_interrupt_impl(wait_umqh_tp, time_out, option);
}

static void umq_tp_ipc_ack_interrupt(uint64_t umqh_tp, uint32_t nevents, umq_interrupt_option_t *option)
{
    umq_ipc_ack_interrupt_impl(umqh_tp, nevents, option);
}

static umq_ops_t g_umq_ipc_ops = {
    .mode = UMQ_TRANS_MODE_IPC,
    .umq_tp_init = umq_tp_ipc_init,
    .umq_tp_uninit = umq_tp_ipc_uninit,
    .umq_tp_create = umq_tp_ipc_create,
    .umq_tp_destroy = umq_tp_ipc_destroy,
    .umq_tp_bind_info_get = umq_tp_ipc_bind_info_get,
    .umq_tp_bind = umq_tp_ipc_bind,
    .umq_tp_unbind = umq_tp_ipc_unbind,
    .umq_tp_state_get = umq_tp_ipc_state_get,
    .umq_tp_buf_alloc = umq_tp_ipc_buf_alloc,
    .umq_tp_buf_free = umq_tp_ipc_buf_free,
    .umq_tp_log_config_set = umq_tp_ipc_log_config_set,
    .umq_tp_buf_headroom_reset = umq_tp_ipc_buf_headroom_reset,
    .umq_tp_enqueue = umq_tp_ipc_enqueue,
    .umq_tp_dequeue = umq_tp_ipc_dequeue,
    .umq_tp_notify = umq_tp_ipc_notify,
    .umq_tp_rearm_interrupt = umq_tp_ipc_rearm_interrupt,
    .umq_tp_wait_interrupt = umq_tp_ipc_wait_interrupt,
    .umq_tp_ack_interrupt = umq_tp_ipc_ack_interrupt,
};

umq_ops_t *umq_ipc_ops_get(void)
{
    return &g_umq_ipc_ops;
}