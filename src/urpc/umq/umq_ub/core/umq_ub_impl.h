/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2025-2025. All rights reserved.
 * Description: UB helper for UMQ
 * Create: 2025-7-19
 * Note:
 * History: 2025-7-19
 */

#ifndef UMQ_UB_IMPL_H
#define UMQ_UB_IMPL_H

#include "umq_types.h"
#include "umq_pro_types.h"
#include "umq_ub_imm_data.h"
#include "umq_qbuf_pool.h"
#include "util_id_generator.h"

#ifdef __cplusplus
extern "C" {
#endif

uint8_t *umq_ub_ctx_init_impl(umq_init_cfg_t *cfg);
void umq_ub_ctx_uninit_impl(uint8_t *ctx);

uint64_t umq_ub_create_impl(uint64_t umqh, uint8_t *ctx, umq_create_option_t *option);
int32_t umq_ub_destroy_impl(uint64_t umqh);

int umq_ub_bind_info_get_impl(uint64_t umqh, uint8_t *bind_info, uint32_t bind_info_size);
int umq_ub_bind_impl(uint64_t umqh, uint8_t *bind_info, uint32_t bind_info_size);
int umq_ub_unbind_impl(uint64_t umqh);
umq_state_t umq_ub_state_get_impl(uint64_t umqh_tp);

int32_t umq_ub_register_memory_impl(void *buf, uint64_t size);
void umq_ub_unregister_memory_impl(void);

int umq_ub_log_config_set_impl(umq_log_config_t *config);
int umq_ub_log_config_reset_impl(void);
int32_t umq_ub_huge_qbuf_pool_init(umq_init_cfg_t *cfg);
void umq_ub_huge_qbuf_pool_uninit(void);

umq_buf_t *umq_ub_buf_alloc_impl(uint32_t request_size, uint32_t request_qbuf_num, uint64_t umqh_tp,
    umq_alloc_option_t *option);
umq_buf_t *umq_ub_plus_buf_alloc_impl(uint32_t request_size, uint32_t request_qbuf_num, uint64_t umqh_tp,
    umq_alloc_option_t *option);
void umq_ub_buf_free_impl(umq_buf_t *qbuf, uint64_t umqh_tp);
void umq_ub_plus_buf_free_impl(umq_buf_t *qbuf, uint64_t umqh_tp);
int umq_ub_post_impl(uint64_t umqh_tp, umq_buf_t *qbuf, umq_io_direction_t io_direction, umq_buf_t **bad_qbuf);
int umq_ub_poll_impl(uint64_t umqh_tp, umq_io_direction_t io_direction, umq_buf_t **buf, uint32_t max_buf_count);

int32_t umq_ub_enqueue_impl(uint64_t umqh_tp, umq_buf_t *qbuf, umq_buf_t **bad_qbuf);
int32_t umq_ub_enqueue_impl_plus(uint64_t umqh_tp, umq_buf_t *qbuf, umq_buf_t **bad_qbuf);
umq_buf_t *umq_ub_dequeue_impl(uint64_t umqh_tp);
umq_buf_t *umq_ub_dequeue_impl_plus(uint64_t umqh_tp);
int umq_ub_rearm_impl(uint64_t umqh_tp, bool solicated, umq_interrupt_option_t *option);

int umq_ub_get_cq_event_impl(uint64_t umqh_tp, umq_interrupt_option_t *option);

int umq_ub_wait_interrupt_impl(uint64_t wait_umqh_tp, int time_out, umq_interrupt_option_t *option);

void umq_ub_ack_interrupt_impl(uint64_t umqh_tp, uint32_t nevents, umq_interrupt_option_t *option);

int umq_ub_interrupt_fd_get_impl(uint64_t umqh_tp, umq_interrupt_option_t *option);

int umq_ub_write_imm(uint64_t umqh_tp, uint64_t target_addr, uint32_t len, uint64_t imm_value);

// ubmm rendezvous related functions
void umq_ub_record_rendezvous_buf(uint64_t umqh_tp, uint16_t msg_id, umq_buf_t *buf);
void umq_ub_remove_rendezvous_buf(uint64_t umqh_tp, uint16_t msg_id);
util_id_allocator_t *umq_ub_get_msg_id_generator(uint64_t umqh_tp);

void ubmm_fill_umq_imm_head(void *imm_head_buf, umq_buf_t *buffer);

int umq_ub_async_event_fd_get(umq_trans_info_t *trans_info);
int umq_ub_async_event_get(umq_trans_info_t *trans_info, umq_async_event_t *event);
void umq_ub_async_event_ack(umq_async_event_t *event);
int umq_ub_dev_add_impl(umq_trans_info_t *info, umq_init_cfg_t *cfg);
int umq_ub_get_route_list_impl(const umq_route_t *route, umq_route_list_t *route_list);

int umq_ub_user_ctl_impl(uint64_t umqh_tp, umq_user_ctl_in_t *in, umq_user_ctl_out_t *out);
int umq_ub_mempool_state_get_impl(uint64_t umqh_tp, uint32_t mempool_id, umq_mempool_state_t *mempool_state);
int umq_ub_mempool_state_refresh_impl(uint64_t umqh_tp, uint32_t mempool_id);
int umq_ub_dev_info_get_impl(char *umq_dev_name, umq_trans_mode_t umq_trans_mode, umq_dev_info_t *umq_dev_info);

#ifdef __cplusplus
}
#endif

#endif
