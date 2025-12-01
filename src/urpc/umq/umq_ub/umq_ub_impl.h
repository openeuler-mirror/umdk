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

#define MEMPOOL_UBVA_SIZE 28
#define UMQ_IMM_VERSION 0

typedef enum umq_size_interval {
    UMQ_SIZE_INVALID_INTERVAL = 0,  // invalid size, buffer lengths are inconsistent.
    UMQ_SIZE_0K_SMALL_INTERVAL = 1, // (0K, umq_buf_size_small()] size
    UMQ_SIZE_SMALL_MID_INTERVAL,    // (umq_buf_size_small(), umq_buf_size_middle()] size
    UMQ_SIZE_MID_BIG_INTERVAL,      // (umq_buf_size_middle(), umq_buf_size_big()] size
    UMQ_SIZE_INTERVAL_MAX,
} umq_size_interval_t;

typedef enum umq_imm_protocol_type {
    IMM_PROTOCAL_TYPE_NONE = 0,
    IMM_PROTOCAL_TYPE_IMPORT_MEM = 1,
} umq_imm_protocol_type_t;

typedef struct umq_imm_head {
    uint32_t version : 8;
    uint32_t type : 8;
    uint32_t mem_interval : 2;
    uint32_t recv : 6;
    uint32_t mempool_num : 8;
} umq_imm_head_t;

typedef struct ub_ref_sge {
    uint64_t addr;
    uint32_t length;
    uint32_t token_id : 20;
    uint32_t rsvd : 4;
    uint32_t mempool_id : 8;
    uint32_t token_value;
} ub_ref_sge_t;

typedef struct ub_import_mempool_info {
    char mempool_ubva[MEMPOOL_UBVA_SIZE];
    uint32_t mempool_seg_flag;
    uint32_t mempool_length;
    uint32_t mempool_token_id : 20;
    uint32_t rsvd : 4;
    uint32_t mempool_id : 8;
    uint32_t mempool_token_value;
} ub_import_mempool_info_t;

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
int umq_ub_read(uint64_t umqh_tp, umq_buf_t *rx_buf, umq_ub_imm_t imm);

// ubmm rendezvous related functions
void umq_ub_get_token(uint64_t umqh_tp, uint8_t mempool_id, uint32_t *token_id, uint32_t *token_value);
void umq_ub_record_rendezvous_buf(uint64_t umqh_tp, uint16_t msg_id, umq_buf_t *buf);
void umq_ub_remove_rendezvous_buf(uint64_t umqh_tp, uint16_t msg_id);
util_id_allocator_t *umq_ub_get_msg_id_generator(uint64_t umqh_tp);

static inline uint32_t get_mem_interval(uint32_t used_mem_size)
{
    if (used_mem_size <= umq_buf_size_small()) {
        return UMQ_SIZE_0K_SMALL_INTERVAL;
    } else if (used_mem_size <= umq_buf_size_middle()) {
        return UMQ_SIZE_SMALL_MID_INTERVAL;
    }
    return UMQ_SIZE_MID_BIG_INTERVAL;
}

static inline void ub_fill_umq_imm_head(umq_imm_head_t *umq_imm_head, umq_buf_t *buffer)
{
    umq_imm_head->version = UMQ_IMM_VERSION;
    umq_imm_head->type = IMM_PROTOCAL_TYPE_NONE;
    umq_imm_head->mempool_num = 0;
    umq_imm_head->mem_interval = get_mem_interval(buffer->data_size);
}

void ubmm_fill_big_data_ref_sge(uint64_t umqh_tp, ub_ref_sge_t *ref_sge,
    umq_buf_t *buffer, ub_import_mempool_info_t *import_mempool_info, umq_imm_head_t *umq_imm_head);

int umq_ub_async_event_fd_get(umq_trans_info_t *trans_info);
int umq_ub_async_event_get(umq_trans_info_t *trans_info, umq_async_event_t *event);
void umq_ub_async_event_ack(umq_async_event_t *event);
int umq_ub_dev_add_impl(umq_trans_info_t *info, umq_init_cfg_t *cfg);
int umq_ub_get_route_list_impl(const umq_route_t *route, umq_route_list_t *route_list);

int umq_ub_user_ctl_impl(uint64_t umqh_tp, umq_user_ctl_in_t *in, umq_user_ctl_out_t *out);

#ifdef __cplusplus
}
#endif

#endif
