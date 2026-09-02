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

#ifdef __cplusplus
extern "C" {
#endif

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
static inline bool is_atomic_wr(const urma_jfs_wr_t *wr)
{
    return wr->opcode == URMA_OPC_CAS || wr->opcode == URMA_OPC_FADD;
}

static inline uint32_t jfs_wr_src_num_sge(const urma_jfs_wr_t *wr)
{
    if (is_rw_wr(wr)) {
        return wr->rw.src.num_sge;
    }
    if (is_send_wr(wr)) {
        return wr->send.src.num_sge;
    }
    return 1; // atomic ops use single SGE
}

urma_status_t copy_jfs_wr(const urma_jfs_wr_t *src, urma_jfs_wr_t *dst,
                          urma_sge_t *prealloc_src_sge, urma_sge_t *prealloc_dst_sge,
                          uint32_t max_sge, uint32_t max_rsge);
urma_status_t copy_jfr_wr(const urma_jfr_wr_t *src, urma_jfr_wr_t *dst,
                          urma_sge_t *prealloc_src_sge, uint32_t max_sge);

void free_jfr_wr(urma_jfr_wr_t *wr);
void free_jfs_wr(urma_jfs_wr_t *wr);

void encode_jfs_wr_msn(urma_jfs_wr_t *wr, bondp_comp_t *bdp_comp, uint32_t msn, bool enable_msn);

/* SGE role per opcode: remote SGEs may run import-free via user_tseg. */
static inline bool jfs_wr_sge_is_remote(const urma_jfs_wr_t *wr, bool is_src)
{
    /* READ pulls data from the remote src; every other opcode with a remote
     * side (WRITE, WRITE_IMM, WRITE_NOTIFY, CAS, FADD) targets the remote dst.
     * SEND (and variants) only has local src SGEs. */
    return wr->opcode == URMA_OPC_READ ? is_src : !is_src;
}

/* Parse helpers for the bonding user_tseg extension (import-free remote SGE).
 * The buffer must be the whole block produced by urma_get_user_tseg. */

/* Total byte length of a bonding user_tseg buffer; 0 when it has no valid
 * extension or exceeds BONDP_USER_TSEG_MAX_LEN. */
uint32_t bondp_user_tseg_total_len(const urma_user_tseg_t *ut);

/* Validate and return the bonding extension of @ut, NULL on any violation
 * (has_user_info not set, bad lengths/version/peer_cnt, peer_idx out of
 * range or duplicated). */
const urma_bond_user_tseg_ext_v0_t *bondp_user_tseg_get_ext(const urma_user_tseg_t *ut);

/* Find the token_id of peer peer_idx == target_idx; 0 on success, -1 if not found. */
int bondp_user_tseg_lookup_token(const urma_bond_user_tseg_ext_v0_t *ext, int target_idx,
                                 uint32_t *token_id);

/* Count the remote SGEs of one WR that run import-free via user_tseg. */
uint32_t jfs_wr_count_remote_user_tseg(const urma_jfs_wr_t *wr);

/**
 * Deep-copy the bonding user_tseg buffer of every import-free remote SGE of
 * @wr into @ut_ext_slots (slot_stride-sized slots, cursor @slot_idx in/out),
 * then rewrite sge->user_tseg to point at the copy. After this call the WR no
 * longer holds any pointer into the caller's buffer, so the caller's (possibly
 * stack) buffer can be released once post returns. SGEs with tseg != NULL are
 * untouched except that their user_tseg is dropped (ignored per API contract).
 * Return: URMA_SUCCESS / URMA_EINVAL (invalid buffer or slots exhausted).
 */
urma_status_t bondp_clone_wr_user_tseg(urma_jfs_wr_t *wr, uint8_t *ut_ext_slots,
                                       uint32_t slot_stride, uint32_t *slot_idx, uint32_t max_slots);

urma_status_t check_jfs_wr_path(urma_jfs_wr_t *wr, int send_idx, int target_idx);

/**
 * Convert a virtual-form WR to physical form for path [send_idx, target_idx]:
 *   - tjetty / local & import-path SGEs -> per-path physical pointers;
 *   - import-free remote SGEs -> bare_ut_scratch[] is filled with the bare
 *     urma_user_tseg_t (per-slave token_id, has_user_info cleared) and the
 *     deep-copied extension pointer is recorded in ut_ext_ptr_save[] so that
 *     convert_jfs_pwr_to_vwr can restore it. Both arrays hold one entry per
 *     import-free remote SGE, assigned in a fixed order (rw: src then dst,
 *     atomic: src then dst), the same order used by bondp_clone_wr_user_tseg.
 */
void convert_jfs_vwr_to_pwr(urma_jfs_wr_t *wr, int send_idx, int target_idx,
                            urma_user_tseg_t *bare_ut_scratch, urma_user_tseg_t **ut_ext_ptr_save);

/**
 * Restore a physical-form WR to virtual form. Import-free remote SGEs get
 * their user_tseg pointed back to the deep-copied extension (ut_ext_ptr_save,
 * never the caller's original buffer).
 */
void convert_jfs_pwr_to_vwr(urma_jfs_wr_t *wr, urma_target_jetty_t *vtjetty,
                            urma_user_tseg_t **ut_ext_ptr_save);

void convert_jfr_vwr_to_pwr(urma_jfr_wr_t *wr, int recv_idx);
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

static inline bool is_need_rebuild_jetty(const urma_cr_t *cr)
{
    return cr->status == URMA_CR_ACK_TIMEOUT_ERR;
}

static inline bool is_rnr_retry_cr(const urma_cr_t *cr)
{
    return cr->status == URMA_CR_RNR_RETRY_CNT_EXC_ERR;
}

#ifdef __cplusplus
}
#endif

#endif // BONDP_DATAPATH_CONVERT_H
