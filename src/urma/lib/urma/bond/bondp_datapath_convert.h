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

urma_status_t copy_jfs_wr(const urma_jfs_wr_t *src, urma_jfs_wr_t *dst,
                          urma_sge_t *prealloc_src_sge, urma_sge_t *prealloc_dst_sge);
urma_status_t copy_jfr_wr(const urma_jfr_wr_t *src, urma_jfr_wr_t *dst,
                          urma_sge_t *prealloc_src_sge);

void free_jfr_wr(urma_jfr_wr_t *wr);
void free_jfs_wr(urma_jfs_wr_t *wr);

urma_status_t convert_jfs_vwr_to_pwr(urma_jfs_wr_t *wr, int send_idx, int target_idx,
                                     bondp_comp_t *bdp_comp, bdp_v_conn_t *v_conn);

void convert_jfs_pwr_to_vwr_resend(urma_jfs_wr_t *wr, urma_target_jetty_t *vtjetty);

void convert_jfs_vwr_to_pwr_for_resend(urma_jfs_wr_t *wr, int send_idx, int target_idx);

void add_vwr_use_cnt(urma_jfs_wr_t *wr);

void release_vwr_use_cnt(urma_jfs_wr_t *wr);

urma_status_t convert_jfr_vwr_to_pwr(urma_jfr_wr_t *wr, int recv_idx);

void convert_pcr_to_vcr(urma_cr_t *cr, bondp_context_t *bdp_ctx, uint32_t *msn);

static inline bool is_recv_cr(const urma_cr_t *cr)
{
    return cr->flag.bs.s_r == 1;
}

/*
 * When the cr status is URMA_CR_WR_SUSPEND_DONE or URMA_CR_WR_FLUSH_ERR_DONE,
 * it indicates that the CR is a fake one constructed by hardware.
 * At this time, the `urma_ctx` field in CR is invalid and most likely 0.
 */
static inline bool is_fake_cr(const urma_cr_t *cr)
{
    return cr->status == URMA_CR_WR_SUSPEND_DONE ||
           cr->status == URMA_CR_WR_FLUSH_ERR_DONE;
}

/*
 * We currently consider the following status codes on the sender side
 * as indicators of a fault that should recover.
 */
static inline bool is_failover_cr(const urma_cr_t *cr)
{
    return cr->status == URMA_CR_LOC_LEN_ERR ||
           cr->status == URMA_CR_LOC_ACCESS_ERR ||
           cr->status == URMA_CR_ACK_TIMEOUT_ERR;
}

/*
 * Control packet mark rules:
 * - A control WR is identified by setting bit 63 of user_ctx.
 * - A RECV CR is identified as control when opcode == URMA_CR_OPC_SEND.
 * - A SEND CR is identified as control when bit 63 of user_ctx is set.
 */
#define BONDP_CTRL_USER_CTX_BIT  63
#define BONDP_CTRL_USER_CTX_MASK (1ULL << BONDP_CTRL_USER_CTX_BIT)

static inline void mark_jfs_wr_ctrl(urma_jfs_wr_t *wr)
{
    wr->user_ctx |= BONDP_CTRL_USER_CTX_MASK;
}

static inline bool is_ctrl_cr(const urma_cr_t *cr)
{
    if (is_recv_cr(cr)) {
        // RECV CR
        return cr->opcode == URMA_CR_OPC_SEND;
    } else {
        // SEND CR
        return (cr->user_ctx & BONDP_CTRL_USER_CTX_MASK) != 0;
    }
}

#endif // BONDP_DATAPATH_CONVERT_H
