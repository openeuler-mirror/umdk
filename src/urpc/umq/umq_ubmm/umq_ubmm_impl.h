/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2025-2025. All rights reserved.
 * Description: ubmm impl header for UMQ
 */

#ifndef UMQ_UBMM_IMPL_H
#define UMQ_UBMM_IMPL_H

#include "umq_types.h"
#include "umq_pro_types.h"

uint8_t *umq_ubmm_ctx_init_impl(umq_init_cfg_t *cfg);

void umq_ubmm_ctx_uninit_impl(uint8_t *ubmm_ctx);

uint64_t umq_ubmm_create_impl(uint64_t umqh, uint8_t *ubmm_ctx, umq_create_option_t *option);

int32_t umq_ubmm_destroy_impl(uint64_t umqh_tp);

int32_t umq_ubmm_bind_info_get_impl(uint64_t umqh_tp, uint8_t *bind_info, uint32_t bind_info_size);

int32_t umq_ubmm_bind_impl(uint64_t umqh_tp, uint8_t *bind_info, uint32_t bind_info_size);

int32_t umq_ubmm_unbind_impl(uint64_t umqh_tp);

umq_buf_t *umq_ubmm_buf_alloc_impl(uint32_t request_size, uint32_t request_qbuf_num, uint64_t umqh_tp,
    umq_alloc_option_t *option);

int umq_ubmm_log_config_set_impl(umq_log_config_t *config);
int umq_ubmm_log_config_reset_impl(void);

void umq_tp_ubmm_buf_free_impl(umq_buf_t *qbuf, uint64_t umqh_tp);

int umq_tp_ubmm_buf_headroom_reset_impl(umq_buf_t *qbuf, uint16_t headroom_size);

int umq_ubmm_plus_enqueue_impl(uint64_t umqh_tp, umq_buf_t *qbuf, umq_buf_t **bad_qbuf);

umq_buf_t *umq_ubmm_plus_dequeue_impl(uint64_t umqh_tp);

void umq_ubmm_notify_impl(uint64_t umqh_tp);

int umq_ubmm_rearm_interrupt_impl(uint64_t umqh_tp, bool solicated, umq_interrupt_option_t *option);

int32_t umq_ubmm_wait_interrupt_impl(uint64_t wait_umqh_tp, int time_out, umq_interrupt_option_t *option);

void umq_ubmm_ack_interrupt_impl(uint64_t umqh_tp, uint32_t nevents, umq_interrupt_option_t *option);

int umq_ubmm_get_cq_event_impl(uint64_t umqh_tp, umq_interrupt_option_t *option);

int umq_ubmm_interrupt_fd_get_impl(uint64_t umqh_tp, umq_interrupt_option_t *option);

int32_t umq_ubmm_register_memory_impl(uint8_t *ubmm_ctx, void *buf, uint64_t size);

void umq_ubmm_unregister_memory_impl(void);

#endif