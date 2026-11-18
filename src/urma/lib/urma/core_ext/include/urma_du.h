/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2021-2026. All rights reserved.
 * Description: Direct URMA user-managed data path. The view is exported by
 *              the existing urma_get_*_opt APIs; the application writes SQE
 *              bytes, rings the doorbell and parses CQE by itself.
 *              This header only provides layout helpers and stateless
 *              primitives. It does not take ownership of any URMA object.
 * Create: 2026-10-08
 */

#ifndef URMA_DU_H
#define URMA_DU_H

#include <stdbool.h>
#include <stdint.h>

#include "urma_types.h"
#include "urma_du_hw.h"
#include "urma_du_poll_inline.h"

#ifdef __cplusplus
extern "C" {
#endif

/*
 * SQE owner bit: owner = ((pi & baseblk_cnt) == 0) ? 1 : 0, flipped once
 * per ring wrap. CQE owner: valid_owner = (ci >> cq_shift) & 1, a CQE is
 * valid when (cqe->owner ^ valid_owner) != 0.
 */

/* Hardware view of a JFS send queue */
struct urma_du_jfs {
    void *qbuf;              /* SQ ring user virtual address */
    void *qbuf_end;          /* SQ ring end address, for wrap-around */
    uint32_t qbuf_size;      /* SQ ring size in bytes */
    uint32_t baseblk_shift;  /* WQEBB shift: 6 means 64 bytes */
    uint32_t baseblk_cnt;    /* total WQEBB count, power of 2 */
    uint32_t max_inline_size;
    uint32_t max_sge_num;
    urma_transport_mode_t trans_mode;
    uint32_t jfs_id;
    uint32_t pi;             /* producer index, maintained by application */
    uint32_t ci;             /* consumer index, advanced by completion */
    urma_target_jetty_t *rc_tjetty; /* bind cached target jetty, RC only */
    volatile void *db_addr;  /* SQ doorbell register, offset already included */
    void *dwqe_addr;         /* direct WQE mmio region base, NULL when unsupported */
    bool dwqe_enable;
    bool st64b_en;           /* cpu supports st64b, single 64B atomic mmio store */
    uintptr_t *wrid;         /* optional application-owned WR id ring */
};

/* Hardware view of a JFC completion queue */
struct urma_du_jfc {
    void *qbuf;              /* CQE ring user virtual address */
    uint32_t qbuf_size;
    uint32_t baseblk_shift;  /* CQE entry shift: 4 means 16B, 6 means 64B */
    uint32_t baseblk_cnt;    /* total CQE count, power of 2 */
    uint32_t baseblk_mask;
    uint32_t cq_shift;       /* log2(baseblk_cnt), for CQE owner calculation */
    uint32_t ci;             /* consumer index, maintained by application */
    uint32_t idx;            /* JFC ID */
    volatile uint32_t *sw_db; /* CI doorbell record, written to recycle CQEs */
};

/* One WQEBB (64 bytes): 48-byte control segment plus 16-byte SGE or inline data */
struct urma_du_sqe_bb {
    struct urma_du_sqe_ctl ctl;
    uint8_t tail[URMA_DU_WQEBB - URMA_DU_SQE_NORMAL_CTL_LEN];
};

static inline void urma_du_swap_endian128(const uint8_t *src, uint8_t *dst)
{
    *(uint64_t *)(dst + sizeof(uint64_t)) = __builtin_bswap64(*(const uint64_t *)(const void *)src);
    *(uint64_t *)(void *)dst = __builtin_bswap64(*(const uint64_t *)(const void *)(src + sizeof(uint64_t)));
}

static inline void *urma_du_inc_ptr_wrap(const struct urma_du_jfs *dj, void *ptr, uint32_t inc)
{
    uint8_t *p = (uint8_t *)ptr;

    return (p + inc) < (uint8_t *)dj->qbuf_end ?
        (void *)(p + inc) : (void *)((uint8_t *)dj->qbuf + (p + inc - (uint8_t *)dj->qbuf_end));
}

static inline bool urma_du_sq_has_room(const struct urma_du_jfs *dj, uint32_t pi, uint32_t bb_cnt)
{
    return pi - dj->ci + bb_cnt <= dj->baseblk_cnt;
}

static inline void urma_du_ring_sq_db(struct urma_du_jfs *dj, uint32_t pi)
{
    urma_du_to_device_barrier();
    *(volatile uint32_t *)dj->db_addr = pi;
}

/*
 * DWQE fast path: copy the whole WQEBB through the dwqe mmio region instead
 * of ringing the normal doorbell. Caller ensures the SQE occupies exactly one
 * WQEBB, is the only in-flight WQE, and pi is the producer index AFTER it.
 */
static inline void urma_du_write_dsqe(struct urma_du_jfs *dj,
                                      struct urma_du_sqe_bb *sqe,
                                      uint32_t pi)
{
    sqe->ctl.sqe_bb_idx = pi;
    urma_du_to_device_barrier();
    if (dj->st64b_en) {
        urma_du_st64b((const uint64_t *)(const void *)sqe, (uint64_t *)dj->dwqe_addr);
        return;
    }
    urma_du_mmio_memcpy_x64((uint64_t *)dj->dwqe_addr,
                            (const uint64_t *)(const void *)sqe);
}

static inline struct urma_du_cqe *urma_du_get_cqe(const struct urma_du_jfc *dc, uint32_t ci)
{
    return (struct urma_du_cqe *)((uint8_t *)dc->qbuf +
        ((uint64_t)(ci & dc->baseblk_mask) << dc->baseblk_shift));
}

static inline bool urma_du_cqe_valid(const struct urma_du_jfc *dc, uint32_t ci,
                                     const struct urma_du_cqe *cqe)
{
    uint32_t valid_owner = (ci >> dc->cq_shift) & URMA_DU_JFC_DB_VALID_OWNER_M;

    return (cqe->owner ^ valid_owner) != URMA_DU_CQE_INVALID;
}

/*
 * Move the SQ consumer index to the WQE index reported by a CQE. It only
 * skips WQEs that did not generate a CQE; the caller increments ci after
 * reading its wrid entry.
 */
static inline void urma_du_advance_sq_ci(struct urma_du_jfs *dj, uint32_t entry_idx)
{
    dj->ci += (entry_idx - dj->ci) & (dj->baseblk_cnt - 1);
}

static inline void urma_du_update_jfc_ci(struct urma_du_jfc *dc, uint32_t ci)
{
    dc->ci = ci;
    urma_du_to_device_barrier();
    *dc->sw_db = ci & URMA_DU_JFC_DB_CI_IDX_M;
}

#ifdef __cplusplus
}
#endif

#endif /* URMA_DU_H */
