/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2025-2025. All rights reserved.
 * Description: realize func for umq ubmm api
 * Create: 2025-8-18
 */
#include <stdio.h>
#include <stdlib.h>
#include <dlfcn.h>
#include <unistd.h>

#include "umq_vlog.h"
#include "umq_errno.h"
#include "umq_ubmm_api.h"
#include "umq_ubmm_impl.h"
#include "umq_qbuf_pool.h"

static uint8_t *umq_tp_ubmm_init(umq_init_cfg_t *cfg)
{
    uint8_t *ubmm_ctx = umq_ubmm_ctx_init_impl(cfg);
    if (ubmm_ctx == NULL) {
        UMQ_VLOG_ERR("umq ub ctx init failed\n");
        return NULL;
    }

    if (umq_ubmm_register_memory_impl(umq_io_buf_addr(), umq_io_buf_size()) != UMQ_SUCCESS) {
        UMQ_VLOG_ERR("register memory failed\n");
        goto UNINIT;
    }
    return ubmm_ctx;

UNINIT:
    umq_ubmm_ctx_uninit_impl(ubmm_ctx);
    return NULL;
}

static void umq_tp_ubmm_uninit(uint8_t *ctx)
{
    umq_ubmm_unregister_memory_impl();
    umq_ubmm_ctx_uninit_impl(ctx);
}

static uint64_t umq_tp_ubmm_create(uint64_t umqh, uint8_t *ctx, umq_create_option_t *option)
{
    return umq_ubmm_create_impl(umqh, ctx, option);
}

static int umq_tp_ubmm_destroy(uint64_t umqh_tp)
{
    return umq_ubmm_destroy_impl(umqh_tp);
}

static uint32_t umq_tp_ubmm_bind_info_get(uint64_t umqh_tp, uint8_t *bind_info, uint32_t bind_info_size)
{
    return umq_ubmm_bind_info_get_impl(umqh_tp, bind_info, bind_info_size);
}

static int umq_tp_ubmm_bind(uint64_t umqh_tp, uint8_t *bind_info, uint32_t bind_info_size)
{
    return umq_ubmm_bind_impl(umqh_tp, bind_info, bind_info_size);
}

static int umq_tp_ubmm_unbind(uint64_t umqh_tp)
{
    return umq_ubmm_unbind_impl(umqh_tp);
}

static umq_state_t umq_tp_ubmm_state_get(uint64_t umqh_tp)
{
    return QUEUE_STATE_READY;
}

static umq_buf_t *umq_tp_ubmm_buf_alloc(uint32_t request_size, uint32_t request_qbuf_num, uint64_t umqh_tp,
    umq_alloc_option_t *option)
{
    return umq_ubmm_buf_alloc_impl(request_size, request_qbuf_num, umqh_tp, option);
}

static void umq_tp_ubmm_buf_free(umq_buf_t *qbuf, uint64_t umqh_tp)
{
    umq_tp_ubmm_buf_free_impl(qbuf, umqh_tp);
}

static int umq_tp_ubmm_log_config_set(umq_log_config_t *config)
{
    return umq_ubmm_log_config_set_impl(config);
}

static int umq_tp_ubmm_log_config_reset(void)
{
    return umq_ubmm_log_config_reset_impl();
}

static int umq_tp_ubmm_buf_headroom_reset(umq_buf_t *qbuf, uint16_t headroom_size)
{
    return umq_tp_ubmm_buf_headroom_reset_impl(qbuf, headroom_size);
}

static int umq_tp_ubmm_enqueue(uint64_t umqh_tp, umq_buf_t *qbuf, umq_buf_t **bad_qbuf)
{
    return -1;
}

static umq_buf_t *umq_tp_ubmm_dequeue(uint64_t umqh_tp)
{
    return NULL;
}

static void umq_tp_ubmm_notify(uint64_t umqh_tp)
{
    return umq_ubmm_notify_impl(umqh_tp);
}

static int umq_tp_ubmm_rearm_interrupt(uint64_t umqh_tp, bool solicated, umq_interrupt_option_t *option)
{
    return umq_ubmm_rearm_interrupt_impl(umqh_tp, solicated, option);
}

static int32_t umq_tp_ubmm_wait_interrupt(uint64_t wait_umqh_tp, int time_out, umq_interrupt_option_t *option)
{
    return umq_ubmm_wait_interrupt_impl(wait_umqh_tp, time_out, option);
}

static void umq_tp_ubmm_ack_interrupt(uint64_t umqh_tp, uint32_t nevents, umq_interrupt_option_t *option)
{
    umq_ubmm_ack_interrupt_impl(umqh_tp, nevents, option);
}

static umq_ops_t g_umq_ubmm_ops = {
    .mode = UMQ_TRANS_MODE_UBMM,
    .umq_tp_init = umq_tp_ubmm_init,
    .umq_tp_uninit = umq_tp_ubmm_uninit,
    .umq_tp_create = umq_tp_ubmm_create,
    .umq_tp_destroy = umq_tp_ubmm_destroy,
    .umq_tp_bind_info_get = umq_tp_ubmm_bind_info_get,
    .umq_tp_bind = umq_tp_ubmm_bind,
    .umq_tp_unbind = umq_tp_ubmm_unbind,
    .umq_tp_state_get = umq_tp_ubmm_state_get,
    .umq_tp_buf_alloc = umq_tp_ubmm_buf_alloc,
    .umq_tp_buf_free = umq_tp_ubmm_buf_free,
    .umq_tp_log_config_set = umq_tp_ubmm_log_config_set,
    .umq_tp_log_config_reset = umq_tp_ubmm_log_config_reset,
    .umq_tp_buf_headroom_reset = umq_tp_ubmm_buf_headroom_reset,
    .umq_tp_enqueue = umq_tp_ubmm_enqueue,
    .umq_tp_dequeue = umq_tp_ubmm_dequeue,
    .umq_tp_notify = umq_tp_ubmm_notify,
    .umq_tp_rearm_interrupt = umq_tp_ubmm_rearm_interrupt,
    .umq_tp_wait_interrupt = umq_tp_ubmm_wait_interrupt,
    .umq_tp_ack_interrupt = umq_tp_ubmm_ack_interrupt,
};

umq_ops_t *umq_ubmm_ops_get(void)
{
    return &g_umq_ubmm_ops;
}