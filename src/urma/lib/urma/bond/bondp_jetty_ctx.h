/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2025-2025. All rights reserved.
 * Description: Bond provider jetty context header file
 * Author: Ma Chuan
 * Create: 2025-02-21
 * Note:
 * History: 2025-02-21   Create File
 */
#ifndef BONDP_JETTY_CTX_H
#define BONDP_JETTY_CTX_H

#include "urma_types.h"
#include "wr_buffer.h"
#include "bondp_types.h"
#include "urma_ubagg.h"
#include "bondp_hash_table.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef enum pjetty_error_done_type {
    PJETTY_SUSPEND_DONE       = 1,
    PJETTY_FLUSH_ERROR_DONE   = 2
} pjetty_error_done_type_t;

typedef struct bondp_jetty_ctx {
    bondp_context_t *bond_ctx;
    bondp_comp_t *bdp_comp;
    int dev_num;
    urma_jetty_t **pjettys; // store the pointer array of bdp_comp->members, which could be jfs*/jfr*/jetty*.
    bool pjettys_valid[URMA_UBAGG_DEV_MAX_NUM];
    uint8_t pjettys_error_done[URMA_UBAGG_DEV_MAX_NUM];
    int send_idx;
    int post_recv_idx;
    // -- wr buf --
    // caching WRs
    jfs_wr_buf_t *jfs_bufs[URMA_UBAGG_DEV_MAX_NUM];  // store unacked jfs wr, in case of re-transmission
    jfr_wr_buf_t *jfr_bufs[URMA_UBAGG_DEV_MAX_NUM];  // store unacked jfr wr, in case of rearm
    // id to distinguish posted WRs
    uint32_t send_wr_id;
    uint32_t recv_wr_id;
    // slide window and other status for de-duplication
    bondp_hash_table_t v_conn_table;
    // single path
    int direct_local_port;
    int direct_target_port;
} bjetty_ctx_t;
// Caller check param
bjetty_ctx_t *create_bjetty_ctx(urma_context_t *ctx, bondp_comp_t *bdp_jetty, size_t wr_buf_size);
void destroy_bjetty_ctx(bjetty_ctx_t *bjetty);

#ifdef __cplusplus
}
#endif
#endif // BONDP_JETTY_CTX_H