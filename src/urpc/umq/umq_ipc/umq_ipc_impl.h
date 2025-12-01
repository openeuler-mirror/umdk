/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2025-2025. All rights reserved.
 * Description: ipc impl header for UMQ
 * Create: 2025-8-18
 * Note:
 * History: 2025-8-18
 */

#ifndef UMQ_IPC_IMPL_H
#define UMQ_IPC_IMPL_H

#include "umq_types.h"
#include "umq_pro_types.h"

#ifdef __cplusplus
extern "C" {
#endif

uint8_t *umq_ipc_ctx_init_impl(umq_init_cfg_t *cfg);

void umq_ipc_ctx_uninit_impl(uint8_t *ipc_ctx);

uint64_t umq_ipc_create_impl(uint64_t umqh, uint8_t *ipc_ctx, umq_create_option_t *option);

int32_t umq_ipc_destroy_impl(uint64_t umqh_tp);

int32_t umq_ipc_bind_info_get_impl(uint64_t umqh_tp, uint8_t *bind_info, uint32_t bind_info_size);

int32_t umq_ipc_bind_impl(uint64_t umqh_tp, uint8_t *bind_info, uint32_t bind_info_size);

int32_t umq_ipc_unbind_impl(uint64_t umqh_tp);

umq_buf_t *umq_ipc_buf_alloc_impl(uint32_t request_size, uint32_t request_qbuf_num, uint64_t umqh_tp,
    umq_alloc_option_t *option);

void umq_tp_ipc_buf_free_impl(umq_buf_t *qbuf, uint64_t umqh_tp);

int umq_tp_ipc_buf_headroom_reset_impl(umq_buf_t *qbuf, uint16_t headroom_size);

int umq_ipc_post_impl(uint64_t umqh_tp, umq_buf_t *qbuf, umq_io_direction_t io_direction, umq_buf_t **bad_qbuf);

int umq_ipc_poll_impl(uint64_t umqh_tp, umq_io_direction_t io_direction, umq_buf_t **buf, uint32_t max_buf_count);

int umq_ipc_enqueue_impl(uint64_t umqh_tp, umq_buf_t *qbuf, umq_buf_t **bad_qbuf);

umq_buf_t *umq_ipc_dequeue_impl(uint64_t umqh_tp);

void umq_ipc_notify_impl(uint64_t umqh_tp);

int umq_ipc_rearm_interrupt_impl(uint64_t umqh_tp, bool solicated, umq_interrupt_option_t *option);

int32_t umq_ipc_wait_interrupt_impl(uint64_t wait_umqh_tp, int time_out, umq_interrupt_option_t *option);

void umq_ipc_ack_interrupt_impl(uint64_t umqh_tp, uint32_t nevents, umq_interrupt_option_t *option);

#ifdef __cplusplus
}
#endif

#endif