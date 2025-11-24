/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2025-2025. All rights reserved.
 * Description: realize func for umq ub plus api
 * Create: 2025-8-4
 */
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include "umq_vlog.h"
#include "umq_errno.h"
#include "umq_ub_impl.h"
#include "umq_ub_api.h"
#include "umq_qbuf_pool.h"

static uint8_t *umq_tp_ub_plus_init(umq_init_cfg_t *cfg, void *addr, uint64_t len)
{
    uint8_t *ub_ctx = umq_ub_ctx_init_impl(cfg);
    if (ub_ctx == NULL) {
        UMQ_VLOG_ERR("umq ub ctx init failed\n");
        return NULL;
    }

    if (umq_ub_register_memory_impl(ub_ctx, addr, len) != UMQ_SUCCESS) {
        UMQ_VLOG_ERR("register memory failed\n");
        goto UNINIT;
    }

    if (umq_ub_huge_qbuf_pool_init(cfg) != UMQ_SUCCESS) {
        UMQ_VLOG_ERR("init huge qbuf pool configuration failed\n");
        goto UNINIT_MEM;
    }

    return ub_ctx;

UNINIT_MEM:
    umq_ub_unregister_memory_impl(ub_ctx);

UNINIT:
    umq_ub_ctx_uninit_impl(ub_ctx);
    return NULL;
}

static void umq_tp_ub_plus_uninit(uint8_t *ctx)
{
    if (ctx == NULL) {
        UMQ_VLOG_ERR("ub_ctx is null\n");
        return;
    }
    umq_ub_huge_qbuf_pool_uninit();
    umq_ub_unregister_memory_impl(ctx);
    umq_ub_ctx_uninit_impl(ctx);
}

static uint64_t umq_tp_ub_plus_create(uint64_t umqh __attribute__((unused)), uint8_t *ctx, umq_create_option_t *option)
{
    return umq_ub_create_impl(umqh, ctx, option);
}

static int umq_tp_ub_plus_destroy(uint64_t umqh_tp)
{
    return umq_ub_destroy_impl(umqh_tp);
}

static uint32_t umq_tp_ub_plus_bind_info_get(uint64_t umqh_tp, uint8_t *bind_info, uint32_t max_bind_info_size)
{
    return umq_ub_bind_info_get_impl(umqh_tp, bind_info, max_bind_info_size);
}

static int umq_tp_ub_plus_bind(uint64_t umqh_tp, uint8_t *bind_info, uint32_t bind_info_size)
{
    return umq_ub_bind_impl(umqh_tp, bind_info, bind_info_size);
}

static int umq_tp_ub_plus_unbind(uint64_t umqh_tp)
{
    return umq_ub_unbind_impl(umqh_tp);
}

static umq_state_t umq_tp_ub_plus_state_get(uint64_t umqh_tp)
{
    return umq_ub_state_get_impl(umqh_tp);
}

static umq_buf_t *umq_tp_ub_plus_buf_alloc(uint32_t request_size, uint32_t request_qbuf_num, uint64_t umqh_tp,
    umq_alloc_option_t *option)
{
    return umq_ub_plus_buf_alloc_impl(request_size, request_qbuf_num, umqh_tp, option);
}

static void umq_tp_ub_plus_buf_free(umq_buf_t *qbuf, uint64_t umqh_tp)
{
    umq_ub_plus_buf_free_impl(qbuf, umqh_tp);
}

static int umq_tp_ub_plus_log_config_set(umq_log_config_t *config)
{
    return umq_ub_log_config_set_impl(config);
}

static int umq_tp_ub_plus_log_config_reset(void)
{
    return umq_ub_log_config_reset_impl();
}

static int umq_tp_ub_plus_enqueue(uint64_t umqh_tp, umq_buf_t *qbuf, umq_buf_t **bad_qbuf)
{
    return umq_ub_enqueue_impl_plus(umqh_tp, qbuf, bad_qbuf);
}

static umq_buf_t *umq_tp_ub_plus_dequeue(uint64_t umqh_tp)
{
    return umq_ub_dequeue_impl_plus(umqh_tp);
}

static void umq_tp_ub_plus_notify(uint64_t umqh_tp)
{
    return;
}

static int umq_tp_ub_plus_rearm_interrupt(uint64_t umqh_tp, bool solicated, umq_interrupt_option_t *option)
{
    return umq_ub_rearm_impl(umqh_tp, solicated, option);
}

static int umq_tp_ub_plus_wait_interrupt(uint64_t wait_umqh_tp, int time_out, umq_interrupt_option_t *option)
{
    return umq_ub_wait_interrupt_impl(wait_umqh_tp, time_out, option);
}

static void umq_tp_ub_plus_ack_interrupt(uint64_t umqh_tp, uint32_t nevents, umq_interrupt_option_t *option)
{
    umq_ub_ack_interrupt_impl(umqh_tp, nevents, option);
}

static int umq_tp_ub_plus_async_event_fd_get(umq_trans_info_t *trans_info)
{
    return umq_ub_async_event_fd_get(trans_info);
}

static int umq_tp_ub_plus_async_event_get(umq_trans_info_t *trans_info, umq_async_event_t *event)
{
    return 0;
}

static void umq_tp_ub_plus_async_event_ack(umq_async_event_t *event)
{
    return;
}

static umq_ops_t g_umq_ub_plus_ops = {
    .mode = UMQ_TRANS_MODE_UB_PLUS,
    // control plane api
    .umq_tp_init = umq_tp_ub_plus_init,
    .umq_tp_uninit = umq_tp_ub_plus_uninit,
    .umq_tp_create = umq_tp_ub_plus_create,
    .umq_tp_destroy = umq_tp_ub_plus_destroy,
    .umq_tp_bind_info_get = umq_tp_ub_plus_bind_info_get,
    .umq_tp_bind = umq_tp_ub_plus_bind,
    .umq_tp_unbind = umq_tp_ub_plus_unbind,
    .umq_tp_state_get = umq_tp_ub_plus_state_get,
    .umq_tp_log_config_set = umq_tp_ub_plus_log_config_set,
    .umq_tp_log_config_reset = umq_tp_ub_plus_log_config_reset,

    // datapath plane api
    .umq_tp_buf_alloc = umq_tp_ub_plus_buf_alloc,
    .umq_tp_buf_free = umq_tp_ub_plus_buf_free,
    .umq_tp_enqueue = umq_tp_ub_plus_enqueue,
    .umq_tp_dequeue = umq_tp_ub_plus_dequeue,
    .umq_tp_notify = umq_tp_ub_plus_notify,
    .umq_tp_rearm_interrupt = umq_tp_ub_plus_rearm_interrupt,
    .umq_tp_wait_interrupt = umq_tp_ub_plus_wait_interrupt,
    .umq_tp_ack_interrupt = umq_tp_ub_plus_ack_interrupt,
    .umq_tp_async_event_fd_get = umq_tp_ub_plus_async_event_fd_get,
    .umq_tp_async_event_get = umq_tp_ub_plus_async_event_get,
    .umq_tp_aync_event_ack = umq_tp_ub_plus_async_event_ack,
};

umq_ops_t *umq_ub_plus_ops_get(void)
{
    return &g_umq_ub_plus_ops;
}

