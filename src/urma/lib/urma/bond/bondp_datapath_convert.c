/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2026-2026. All rights reserved.
 * Description: Bond provider datapath convert implementation file
 * Author: Wang Hang
 * Create: 2026-04-02
 * Note:
 * History: 2026-04-02   Create File
 */

#include <string.h>

#include "bondp_api.h"
#include "bondp_segment.h"
#include "bondp_types.h"
#include "topo_info.h"
#include "urma_log.h"

#include "bondp_datapath_convert.h"

void free_jfs_wr(urma_jfs_wr_t *wr)
{
    if (is_rw_wr(wr)) {
        if (wr->rw.src.sge != NULL) {
            free(wr->rw.src.sge);
            wr->rw.src.sge = NULL;
        }
        if (wr->rw.dst.sge != NULL) {
            free(wr->rw.dst.sge);
            wr->rw.dst.sge = NULL;
        }
    } else if (is_send_wr(wr)) {
        if (wr->send.src.sge != NULL) {
            free(wr->send.src.sge);
            wr->send.src.sge = NULL;
        }
    } else if (is_atomic_wr(wr)) {
        if (wr->cas.src != NULL) {
            free(wr->cas.src);
            wr->cas.src = NULL;
        }
        if (wr->cas.dst != NULL) {
            free(wr->cas.dst);
            wr->cas.dst = NULL;
        }
    }
}

void free_jfr_wr(urma_jfr_wr_t *wr)
{
    if (wr->src.sge != NULL) {
        free(wr->src.sge);
        wr->src.sge = NULL;
    }
}

static int copy_sg_list(const urma_sg_t *src, urma_sg_t *dst, urma_sge_t *prealloc_sge)
{
    dst->num_sge = src->num_sge;
    dst->sge = NULL;

    if (dst->num_sge > 0) {
        if (prealloc_sge != NULL) {
            if (dst->num_sge > BONDP_MAX_SGE_NUM) {
                URMA_LOG_ERR("The number of SGE(%u) exceeds the limit(%u)",
                    dst->num_sge, BONDP_MAX_SGE_NUM);
                return -1;
            }
            dst->sge = prealloc_sge;
        } else {
            dst->sge = (urma_sge_t *)malloc(dst->num_sge * sizeof(urma_sge_t));
            if (dst->sge == NULL) {
                return -1;
            }
        }
        (void)memcpy(dst->sge, src->sge, src->num_sge * sizeof(urma_sge_t));
    }
    return 0;
}

static int copy_atomic_sge(const urma_sge_t *src, urma_sge_t **dst, urma_sge_t *prealloc_sge)
{
    if (src == NULL) {
        *dst = NULL;
        return 0;
    }

    if (prealloc_sge != NULL) {
        *dst = prealloc_sge;
    } else {
        *dst = (urma_sge_t *)malloc(sizeof(urma_sge_t));
        if (*dst == NULL) {
            return -1;
        }
    }
    (void)memcpy(*dst, src, sizeof(urma_sge_t));
    return 0;
}

/**
 * Performs a deep copy of a JFS work request.
 *
 * Copies all fields from @src to @dst except:
 *   next_wr, target_jetty, target_seg, user_tseg
 *
 * Supported opcodes:
 *   URMA_OPC_WRITE, URMA_OPC_WRITE_IMM, URMA_OPC_WRITE_NOTIFY, URMA_OPC_READ
 *   URMA_OPC_SEND, URMA_OPC_SEND_IMM, URMA_OPC_SEND_INVALIDATE
 *   URMA_OPC_CAS, URMA_OPC_FADD
 */
urma_status_t copy_jfs_wr(const urma_jfs_wr_t *src, urma_jfs_wr_t *dst,
                          urma_sge_t *prealloc_src_sge, urma_sge_t *prealloc_dst_sge)
{
    *dst = *src;
    dst->next = NULL;

    if (is_rw_wr(src)) {
        if (copy_sg_list(&src->rw.src, &dst->rw.src, prealloc_src_sge) != 0 ||
            copy_sg_list(&src->rw.dst, &dst->rw.dst, prealloc_dst_sge) != 0) {
            return URMA_ENOMEM;
        }
    } else if (is_send_wr(src)) {
        if (copy_sg_list(&src->send.src, &dst->send.src, prealloc_src_sge) != 0) {
            return URMA_ENOMEM;
        }
    } else if (is_atomic_wr(src)) {
        if (copy_atomic_sge(src->cas.src, &dst->cas.src, prealloc_src_sge) != 0 ||
            copy_atomic_sge(src->cas.dst, &dst->cas.dst, prealloc_dst_sge) != 0) {
            return URMA_ENOMEM;
        }
    } else {
        return URMA_EINVAL;
    }
    return 0;
}

/**
 * Performs a deep copy of a JFR work request.
 */
urma_status_t copy_jfr_wr(const urma_jfr_wr_t *src, urma_jfr_wr_t *dst,
                          urma_sge_t *prealloc_src_sge)
{
    *dst = *src;
    dst->next = NULL;

    if (copy_sg_list(&src->src, &dst->src, prealloc_src_sge) != 0) {
        return URMA_ENOMEM;
    }
    return URMA_SUCCESS;
}

/**
 * 64-bit imm_data format:
 *
 *   Bits   | Field       | Bits | Description
 *   -------|-------------|------|--------------------------------
 *   0-19   | user_data   | 20   | User-defined custom data
 *   20-21  | reserved    | 2    | Reserved
 *   22-37  | vjetty_id   | 16   | Virtual jetty identifier (0-65535)
 *   38-39  | cr_opcode   | 2    | Operation code tag (0-3)
 *   40-63  | msn         | 24   | Message sequence number (0-16M)
 *
 * Use encode_imm_data() and decode_imm_data() to pack/unpack fields.
 */

#define IMM_USER_BITS      20
#define IMM_RESERVED_BITS  2
#define IMM_VJETTY_ID_BITS 16
#define IMM_CR_OPCODE_BITS 2
#define IMM_MSN_BITS       24

#define IMM_USER_SHIFT      0
#define IMM_RESERVED_SHIFT  (IMM_USER_SHIFT + IMM_USER_BITS)
#define IMM_VJETTY_ID_SHIFT (IMM_RESERVED_SHIFT + IMM_RESERVED_BITS)
#define IMM_CR_OPCODE_SHIFT (IMM_VJETTY_ID_SHIFT + IMM_VJETTY_ID_BITS)
#define IMM_MSN_SHIFT       (IMM_CR_OPCODE_SHIFT + IMM_CR_OPCODE_BITS)

#define IMM_USER_MASK      ((1ULL << IMM_USER_BITS) - 1)
#define IMM_VJETTY_ID_MASK ((1ULL << IMM_VJETTY_ID_BITS) - 1)
#define IMM_CR_OPCODE_MASK ((1ULL << IMM_CR_OPCODE_BITS) - 1)
#define IMM_MSN_MASK       ((1ULL << IMM_MSN_BITS) - 1)

static inline uint64_t encode_imm_data(uint32_t cr_opcode, uint32_t msn, uint32_t vjetty_id,
                                       uint64_t user_data, bool msn_enable)
{
    uint64_t imm_data = 0;

    imm_data |= ((uint64_t)cr_opcode & IMM_CR_OPCODE_MASK) << IMM_CR_OPCODE_SHIFT;
    if (msn_enable) {
        imm_data |= ((uint64_t)msn & IMM_MSN_MASK) << IMM_MSN_SHIFT;
    } else {
        imm_data |= (((uint64_t)user_data >> IMM_MSN_SHIFT) & IMM_MSN_MASK) << IMM_MSN_SHIFT;
    }
    imm_data |= ((uint64_t)vjetty_id & IMM_VJETTY_ID_MASK) << IMM_VJETTY_ID_SHIFT;
    imm_data |= ((uint64_t)user_data & IMM_USER_MASK) << IMM_USER_SHIFT;
    return imm_data;
}

static inline void decode_imm_data(uint64_t imm_data, uint32_t *cr_opcode, uint32_t *msn,
                                   uint32_t *vjetty_id, uint64_t *user_data, bool msn_enable)
{
    *cr_opcode = (uint32_t)((imm_data >> IMM_CR_OPCODE_SHIFT) & IMM_CR_OPCODE_MASK);
    *vjetty_id = (uint32_t)((imm_data >> IMM_VJETTY_ID_SHIFT) & IMM_VJETTY_ID_MASK);
    *user_data = (uint64_t)((imm_data >> IMM_USER_SHIFT) & IMM_USER_MASK);
    if (msn_enable) {
        *msn = (uint32_t)((imm_data >> IMM_MSN_SHIFT) & IMM_MSN_MASK);
    } else {
        *user_data |= (uint64_t)(((imm_data >> IMM_MSN_SHIFT) & IMM_MSN_MASK) << IMM_MSN_SHIFT);
    }
}

static inline urma_target_jetty_t *get_p_tjetty(urma_target_jetty_t *tjetty, int send_idx, int target_idx)
{
    return CONTAINER_OF_FIELD(tjetty, bondp_target_jetty_t, v_tjetty)->p_tjetty[send_idx][target_idx];
}

static inline urma_target_seg_t *get_p_tseg(urma_target_seg_t *tseg, int local_idx, int remote_idx)
{
    /* Use token_id to distinguish local register seg and imported seg
       This is useful for write ops */
    if (tseg->token_id != NULL) {
        return CONTAINER_OF_FIELD(tseg, bondp_tseg_t, v_tseg)->p_tseg[local_idx];
    } else {
        return CONTAINER_OF_FIELD(tseg, bondp_import_tseg_t, v_tseg)->p_tseg[local_idx][remote_idx];
    }
}

static inline urma_target_seg_t *get_v_tseg(urma_target_seg_t *tseg)
{
    return (urma_target_seg_t *)(uintptr_t)tseg->handle;
}

static void map_send_vwr_to_path(urma_jfs_wr_t *send_wr, int send_idx, int target_idx)
{
    if (send_wr->send.src.num_sge > 0 && send_wr->send.src.sge != NULL) {
        for (int i = 0; i < send_wr->send.src.num_sge; ++i) {
            send_wr->send.src.sge[i].tseg = get_p_tseg(send_wr->send.src.sge[i].tseg, send_idx, target_idx);
        }
    }
    send_wr->tjetty = get_p_tjetty(send_wr->tjetty, send_idx, target_idx);
}

static void restore_send_pwr_to_vwr(urma_jfs_wr_t *send_wr, urma_target_jetty_t *vtjetty)
{
    if (send_wr->send.src.num_sge > 0 && send_wr->send.src.sge != NULL) {
        for (int i = 0; i < send_wr->send.src.num_sge; ++i) {
            send_wr->send.src.sge[i].tseg = get_v_tseg(send_wr->send.src.sge[i].tseg);
        }
    }
    send_wr->tjetty = vtjetty;
}

static void map_write_vwr_to_path(urma_jfs_wr_t *send_wr, int send_idx, int target_idx)
{
    for (int i = 0; i < send_wr->rw.src.num_sge; ++i) {
        send_wr->rw.src.sge[i].tseg = get_p_tseg(send_wr->rw.src.sge[i].tseg, send_idx, target_idx);
    }
    for (int i = 0; i < send_wr->rw.dst.num_sge; ++i) {
        send_wr->rw.dst.sge[i].tseg = get_p_tseg(send_wr->rw.dst.sge[i].tseg, send_idx, target_idx);
    }
    send_wr->tjetty = get_p_tjetty(send_wr->tjetty, send_idx, target_idx);
}

static void restore_write_pwr_to_vwr(urma_jfs_wr_t *send_wr, urma_target_jetty_t *vtjetty)
{
    for (int i = 0; i < send_wr->rw.src.num_sge; ++i) {
        send_wr->rw.src.sge[i].tseg = get_v_tseg(send_wr->rw.src.sge[i].tseg);
    }
    for (int i = 0; i < send_wr->rw.dst.num_sge; ++i) {
        send_wr->rw.dst.sge[i].tseg = get_v_tseg(send_wr->rw.dst.sge[i].tseg);
    }
    send_wr->tjetty = vtjetty;
}

static void restore_cas_pwr_to_vwr(urma_jfs_wr_t *send_wr, urma_target_jetty_t *vtjetty)
{
    if (send_wr->cas.src != NULL) {
        send_wr->cas.src->tseg = get_v_tseg(send_wr->cas.src->tseg);
    }
    if (send_wr->cas.dst != NULL) {
        send_wr->cas.dst->tseg = get_v_tseg(send_wr->cas.dst->tseg);
    }
    send_wr->tjetty = vtjetty;
}

static void restore_faa_pwr_to_vwr(urma_jfs_wr_t *send_wr, urma_target_jetty_t *vtjetty)
{
    if (send_wr->faa.src != NULL) {
        send_wr->faa.src->tseg = get_v_tseg(send_wr->faa.src->tseg);
    }
    if (send_wr->faa.dst != NULL) {
        send_wr->faa.dst->tseg = get_v_tseg(send_wr->faa.dst->tseg);
    }
    send_wr->tjetty = vtjetty;
}

static void map_cas_vwr_to_path(urma_jfs_wr_t *send_wr, int send_idx, int target_idx)
{
    send_wr->cas.src->tseg = get_p_tseg(send_wr->cas.src->tseg, send_idx, target_idx);
    send_wr->cas.dst->tseg = get_p_tseg(send_wr->cas.dst->tseg, send_idx, target_idx);
    send_wr->tjetty = get_p_tjetty(send_wr->tjetty, send_idx, target_idx);
}

static void map_fadd_vwr_to_path(urma_jfs_wr_t *send_wr, int send_idx, int target_idx)
{
    send_wr->faa.src->tseg = get_p_tseg(send_wr->faa.src->tseg, send_idx, target_idx);
    send_wr->faa.dst->tseg = get_p_tseg(send_wr->faa.dst->tseg, send_idx, target_idx);
    send_wr->tjetty = get_p_tjetty(send_wr->tjetty, send_idx, target_idx);
}

void encode_jfs_wr_msn(urma_jfs_wr_t *wr, bondp_comp_t *bdp_comp, uint32_t msn, bool msn_enable)
{
    uint64_t opcode_tag = 0;

    switch (wr->opcode) {
        case URMA_OPC_SEND:
        case URMA_OPC_SEND_IMM:
        case URMA_OPC_SEND_INVALIDATE:
            if (wr->opcode == URMA_OPC_SEND) {
                opcode_tag = URMA_CR_OPC_SEND;
            } else if (wr->opcode == URMA_OPC_SEND_IMM) {
                opcode_tag = URMA_CR_OPC_SEND_WITH_IMM;
            } else if (wr->opcode == URMA_OPC_SEND_INVALIDATE) {
                opcode_tag = URMA_CR_OPC_SEND_WITH_INV;
            }
            wr->opcode = URMA_OPC_SEND_IMM;
            wr->send.imm_data = encode_imm_data(
                opcode_tag,
                msn,
                bdp_comp->v_jetty.jetty_id.id,
                wr->send.imm_data,
                msn_enable);
            return;
        case URMA_OPC_WRITE_IMM:
            opcode_tag = URMA_CR_OPC_WRITE_WITH_IMM;
            wr->rw.notify_data = encode_imm_data(
                opcode_tag,
                msn,
                bdp_comp->v_jetty.jetty_id.id,
                wr->rw.notify_data,
                msn_enable);
            return;
        case URMA_OPC_WRITE:
        case URMA_OPC_WRITE_NOTIFY:
        case URMA_OPC_READ:
        case URMA_OPC_CAS:
        case URMA_OPC_FADD:
            /* No MSN encoding needed for these opcodes */
            return;
        default:
            URMA_LOG_ERR("Unsupported send opcode\n");
            return;
    }
}

void bind_jfs_wr_to_send_path(urma_jfs_wr_t *wr, int send_idx, int target_idx)
{
    switch (wr->opcode) {
        case URMA_OPC_SEND:
        case URMA_OPC_SEND_IMM:
        case URMA_OPC_SEND_INVALIDATE:
            map_send_vwr_to_path(wr, send_idx, target_idx);
            return;
        case URMA_OPC_WRITE:
        case URMA_OPC_WRITE_IMM:
        case URMA_OPC_WRITE_NOTIFY:
        case URMA_OPC_READ:
            map_write_vwr_to_path(wr, send_idx, target_idx);
            return;
        case URMA_OPC_CAS:
            map_cas_vwr_to_path(wr, send_idx, target_idx);
            return;
        case URMA_OPC_FADD:
            map_fadd_vwr_to_path(wr, send_idx, target_idx);
            return;
        default:
            return;
    }
}

void unbind_jfs_wr_from_send_path(urma_jfs_wr_t *wr, urma_target_jetty_t *vtjetty)
{
    switch (wr->opcode) {
        case URMA_OPC_SEND:
        case URMA_OPC_SEND_IMM:
        case URMA_OPC_SEND_INVALIDATE:
            restore_send_pwr_to_vwr(wr, vtjetty);
            return;
        case URMA_OPC_WRITE:
        case URMA_OPC_WRITE_IMM:
        case URMA_OPC_WRITE_NOTIFY:
        case URMA_OPC_READ:
            restore_write_pwr_to_vwr(wr, vtjetty);
            return;
        case URMA_OPC_CAS:
            restore_cas_pwr_to_vwr(wr, vtjetty);
            return;
        case URMA_OPC_FADD:
            restore_faa_pwr_to_vwr(wr, vtjetty);
            return;
        default:
            return;
    }
}

void add_vwr_use_cnt(urma_jfs_wr_t *wr)
{
    if (wr->tjetty != NULL) {
        bondp_tjetty_get(wr->tjetty);
    }

    switch (wr->opcode) {
        case URMA_OPC_SEND:
        case URMA_OPC_SEND_IMM:
        case URMA_OPC_SEND_INVALIDATE:
            if (wr->send.src.sge != NULL) {
                for (int i = 0; i < wr->send.src.num_sge; ++i) {
                    bondp_tseg_get(wr->send.src.sge[i].tseg);
                }
            }
            return;
        case URMA_OPC_WRITE:
        case URMA_OPC_WRITE_IMM:
        case URMA_OPC_WRITE_NOTIFY:
        case URMA_OPC_READ:
            for (int i = 0; i < wr->rw.src.num_sge; ++i) {
                bondp_tseg_get(wr->rw.src.sge[i].tseg);
            }
            for (int i = 0; i < wr->rw.dst.num_sge; ++i) {
                bondp_tseg_get(wr->rw.dst.sge[i].tseg);
            }
            return;
        case URMA_OPC_CAS:
        case URMA_OPC_FADD:
            if (wr->cas.src != NULL && wr->cas.src->tseg != NULL) {
                bondp_tseg_get(wr->cas.src->tseg);
            }
            if (wr->cas.dst != NULL && wr->cas.dst->tseg != NULL) {
                bondp_tseg_get(wr->cas.dst->tseg);
            }
            return;
        default:
            return;
    }
}

void release_vwr_use_cnt(urma_jfs_wr_t *wr)
{
    if (wr->tjetty != NULL) {
        bondp_tjetty_put(wr->tjetty);
    }

    switch (wr->opcode) {
        case URMA_OPC_SEND:
        case URMA_OPC_SEND_IMM:
        case URMA_OPC_SEND_INVALIDATE:
            if (wr->send.src.sge != NULL) {
                for (int i = 0; i < wr->send.src.num_sge; ++i) {
                    bondp_tseg_put(wr->send.src.sge[i].tseg);
                }
            }
            return;
        case URMA_OPC_WRITE:
        case URMA_OPC_WRITE_IMM:
        case URMA_OPC_WRITE_NOTIFY:
        case URMA_OPC_READ:
            for (int i = 0; i < wr->rw.src.num_sge; ++i) {
                bondp_tseg_put(wr->rw.src.sge[i].tseg);
            }
            for (int i = 0; i < wr->rw.dst.num_sge; ++i) {
                bondp_tseg_put(wr->rw.dst.sge[i].tseg);
            }
            return;
        case URMA_OPC_CAS:
        case URMA_OPC_FADD:
            if (wr->cas.src != NULL && wr->cas.src->tseg != NULL) {
                bondp_tseg_put(wr->cas.src->tseg);
            }
            if (wr->cas.dst != NULL && wr->cas.dst->tseg != NULL) {
                bondp_tseg_put(wr->cas.dst->tseg);
            }
            return;
        default:
            return;
    }
}

urma_status_t convert_jfr_vwr_to_pwr(urma_jfr_wr_t *wr, int recv_idx)
{
    for (int i = 0; i < wr->src.num_sge; ++i) {
        wr->src.sge[i].tseg = get_p_tseg(wr->src.sge[i].tseg, recv_idx, 0);
    }
    return URMA_SUCCESS;
}

/* Thread-local cache for EID mapping lookup in convert_pcr_to_vcr */
#define TL_EID_CACHE_SLOTS 8

static urma_eid_t lookup_bonding_eid_cached(topo_map_t *topo_map, const urma_eid_t *target_eid)
{
    static __thread topo_map_t *tl_topo;
    static __thread uint32_t   tl_gen;
    static __thread int        tl_fill_pos;
    static __thread int        tl_evict_pos;
    static __thread struct {
        urma_eid_t target;
        urma_eid_t bonding;
        bool       valid;
    } tl_slots[TL_EID_CACHE_SLOTS];

    if (topo_map == NULL) {
        return *target_eid;
    }
    /* Invalidate entire cache if topo_map pointer or gen changed. */
    uint32_t cur_gen = atomic_load(&topo_map->eid_mapping_hash_table.gen);
    if (tl_topo != topo_map || tl_gen != cur_gen) {
        for (int i = 0; i < TL_EID_CACHE_SLOTS; i++) {
            tl_slots[i].valid = false;
        }
        tl_topo      = topo_map;
        tl_gen       = cur_gen;
        tl_fill_pos  = 0;
        tl_evict_pos = 0;
    }
    /* Fast path: TL cache hit */
    for (int i = 0; i < TL_EID_CACHE_SLOTS; i++) {
        if (tl_slots[i].valid &&
            memcmp(&tl_slots[i].target, target_eid, sizeof(urma_eid_t)) == 0) {
            return tl_slots[i].bonding;
        }
    }
    /* Slow path: rwlock + hash-table lookup */
    urma_eid_t bonding;
    if (get_bonding_eid_by_target_eid(topo_map, (urma_eid_t *)target_eid, &bonding) != 0) {
        return *target_eid;
    }
    int slot;
    if (tl_fill_pos < TL_EID_CACHE_SLOTS) {
        slot = tl_fill_pos++;
    } else {
        slot = tl_evict_pos;
        tl_evict_pos = (tl_evict_pos + 1) & (TL_EID_CACHE_SLOTS - 1);
    }
    tl_slots[slot].target  = *target_eid;
    tl_slots[slot].bonding = bonding;
    tl_slots[slot].valid   = true;

    return bonding;
}

void convert_pcr_to_vcr(urma_cr_t *cr, bondp_context_t *bdp_ctx, uint32_t *msn)
{
    bool msn_enable = bdp_ctx->msn_enable;

    if (is_recv_cr(cr)) {
        decode_imm_data(cr->imm_data, &cr->opcode, msn, &cr->remote_id.id, &cr->imm_data, msn_enable);

        cr->remote_id.eid = lookup_bonding_eid_cached(bdp_ctx->topo_map, &cr->remote_id.eid);
    } else {
        /*
         * NOTE: imm_data should only be valid for RECV CR.
         * However, for some reason, it is also valid for SEND CR.
         * This unexpected behavior is intentionally used to convert SEND CR.
         */
        decode_imm_data(cr->imm_data, &cr->opcode, msn, &cr->remote_id.id, &cr->imm_data, msn_enable);
    }
}
