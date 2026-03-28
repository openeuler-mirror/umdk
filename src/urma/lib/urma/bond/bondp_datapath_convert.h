/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2026-2026. All rights reserved.
 * Description: Bond provider datapath convert header file
 * Author: Wang Hang
 * Create: 2026-04-02
 * Note:
 * History: 2026-04-02   Create File
 */

#ifndef BONDP_DATAPATH_CONVERT_H
#define BONDP_DATAPATH_CONVERT_H

#include <stdint.h>

#include "bondp_connection.h"
#include "bondp_jetty_ctx.h"

static inline bool is_rw_wr(const urma_jfs_wr_t *wr)
{
    return wr->opcode == URMA_OPC_WRITE || wr->opcode == URMA_OPC_WRITE_IMM ||
           wr->opcode == URMA_OPC_WRITE_NOTIFY || wr->opcode == URMA_OPC_READ;
}
static inline bool is_send_wr(const urma_jfs_wr_t *wr)
{
    return wr->opcode == URMA_OPC_SEND || wr->opcode == URMA_OPC_SEND_IMM ||
           wr->opcode == URMA_OPC_SEND_INVALIDATE;
}

int copy_jfs_wr(const urma_jfs_wr_t *src, urma_jfs_wr_t *dst,
                urma_sge_t *prealloc_src_sge, urma_sge_t *prealloc_dst_sge);
int copy_jfr_wr(const urma_jfr_wr_t *src, urma_jfr_wr_t *dst,
                urma_sge_t *prealloc_src_sge);

void free_jfr_wr(urma_jfr_wr_t *wr);
void free_jfs_wr(urma_jfs_wr_t *wr);

int convert_jfs_vwr_to_pwr(urma_jfs_wr_t *wr, int send_idx, int target_idx,
                           bjetty_ctx_t *bjetty_ctx, bdp_v_conn_t *v_conn);

int convert_jfr_vwr_to_pwr(urma_jfr_wr_t *wr, int recv_idx);

int convert_jfs_pwr_to_another_path(urma_jfs_wr_t *wr, urma_target_jetty_t *vtjetty, int send_idx, int target_idx);

void convert_pcr_to_vcr(urma_cr_t *cr, bondp_context_t *bdp_ctx, uint32_t *msn);

#endif // BONDP_DATAPATH_CONVERT_H
