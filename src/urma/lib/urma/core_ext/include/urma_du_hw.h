/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2021-2026. All rights reserved.
 * Description: Direct URMA hardware contract (byte-level layout of SQE/CQE,
 *              doorbell offset, owner bit rules and memory barriers).
 *              The layout must stay consistent with hw/udma/udma_u_jfs.h and
 *              hw/udma/udma_u_jfc.h. Any change on either side must be synced.
 * Create: 2026-10-08
 */

#ifndef URMA_DU_HW_H
#define URMA_DU_HW_H

#include <stdint.h>

#include <arm_neon.h>

#ifdef __cplusplus
extern "C" {
#endif

/* SQE control segment, 48 bytes for write, followed by SGE array (16B each) */
struct urma_du_sqe_ctl {
    /* byte 4 */
    uint32_t sqe_bb_idx : 16;
    uint32_t flag : 7;
    uint32_t udf_flag : 1;
    uint32_t rsv0 : 3;
    uint32_t nf : 1;
    uint32_t token_en : 1;
    uint32_t rmt_jetty_type : 2;
    uint32_t owner : 1;
    /* byte 8 */
    uint32_t target_hint : 8;
    uint32_t opcode : 8;
    uint32_t rsv1 : 6;
    uint32_t inline_msg_len : 10;
    /* byte 12 */
    uint32_t tp_id : 24;
    uint32_t sge_num : 8;
    /* byte 16 */
    uint32_t rmt_jetty_or_seg_id : 20;
    uint32_t write_len : 10;
    uint32_t rsv2 : 2;
    /* byte 20 - 32 */
    uint8_t rmt_eid[16];
    /* byte 36 */
    uint32_t rmt_token_value;
    /* byte 40 */
    uint32_t udf_type : 8;
    uint32_t reduce_data_type : 4;
    uint32_t reduce_opcode : 4;
    uint32_t rsv3 : 16;
    /* byte 44 - 48 */
    uint32_t rmt_addr_l_or_token_id;
    uint32_t rmt_addr_h_or_token_value;
};

/* SGE segment, 16 bytes each, located right after the SQE control segment */
struct urma_du_wqe_sge {
    uint32_t length;
    uint32_t token_id;
    uint64_t va;
};

/* CQE layout, entry size is cqe_size (16 or 64 bytes), see baseblk_shift */
struct urma_du_cqe {
    /* DW0 */
    uint32_t s_r : 1;
    uint32_t is_jetty : 1;
    uint32_t owner : 1;
    uint32_t inline_en : 1;
    uint32_t opcode : 3;
    uint32_t fd : 1;
    uint32_t rsv : 8;
    uint32_t substatus : 8;
    uint32_t status : 8;
    /* DW1 */
    uint32_t entry_idx : 16;
    uint32_t local_num_l : 16;
    /* DW2 */
    uint32_t local_num_h : 4;
    uint32_t rmt_idx : 20;
    uint32_t rsv1 : 8;
    /* DW3 */
    uint32_t tpn : 24;
    uint32_t rsv2 : 8;
    /* DW4 */
    uint32_t byte_cnt;
    /* DW5 ~ DW6 */
    uint32_t user_data_l;
    uint32_t user_data_h;
    /* DW7 ~ DW10 */
    uint32_t rmt_eid[4];
    /* DW11 ~ DW12 */
    uint32_t data_l;
    uint32_t data_h;
    /* DW13 ~ DW15, only valid when cqe_size is 64 */
    uint32_t inline_data[3];
};

enum urma_du_opcode {
    URMA_DU_OPCODE_SEND = 0x00,
    URMA_DU_OPCODE_SEND_WITH_IMM,
    URMA_DU_OPCODE_SEND_WITH_INVALID,
    URMA_DU_OPCODE_WRITE,
    URMA_DU_OPCODE_WRITE_WITH_IMM,
    URMA_DU_OPCODE_WRITE_WITH_NOTIFY,
    URMA_DU_OPCODE_READ,
    URMA_DU_OPCODE_CAS,
    URMA_DU_OPCODE_FAA = 0xb,
    URMA_DU_OPCODE_NOP = 0x11,
    URMA_DU_OPCODE_WRITE_WITH_ATOMICSTORE_ADD = 0x19,
};

#define URMA_DU_MAX_SQE_BB_NUM 4
#define URMA_DU_SGE_SIZE 16
#define URMA_DU_WQEBB 64
#define URMA_DU_WQEBB_SHIFT 6
#define URMA_DU_SQE_NORMAL_CTL_LEN 48
#define URMA_DU_AUTO_INLINE_MAX (URMA_DU_WQEBB - URMA_DU_SQE_NORMAL_CTL_LEN)
#define URMA_DU_TID_SHIFT 8U
#define URMA_DU_JFC_DB_CI_IDX_M 0x3fffff
#define URMA_DU_JFC_DB_VALID_OWNER_M 1
#define URMA_DU_CQE_INVALID 0U
#define URMA_DU_FLUSH_DONE 1U
#define URMA_DU_CQE_FOR_SEND 0
#define URMA_DU_CQE_FOR_RECEIVE 1
#define URMA_DU_SRC_IDX_SHIFT 16
#define URMA_DU_ADDR_SHIFT 32
#define URMA_DU_SQE_CTL_RMA_ADDR_BIT 0xffffffffu
#define URMA_DU_SQE_CTL_RMA_ADDR_OFFSET 32
#define URMA_DU_SQE_FLAG_MASK 0x7f
#define URMA_DU_SQE_FLAG_COMPLETE_ENABLE (1u << 5) /* bit5 of urma_jfs_wr_flag_t */
#define URMA_DU_SQE_FLAG_INLINE (1u << 6) /* bit6 of urma_jfs_wr_flag_t */

static inline void urma_du_to_device_barrier(void)
{
    asm volatile("dmb st" ::: "memory");
}

static inline void urma_du_from_device_barrier(void)
{
    asm volatile("dmb ld" ::: "memory");
}

/* copy one WQEBB (64 bytes) to the dwqe mmio region, same as udma mmio_memcpy_x64 */
static inline void urma_du_mmio_memcpy_x64(uint64_t *dest, const uint64_t *src)
{
    vst4q_u64(dest, vld4q_u64(src));
}

/* single 64-byte atomic mmio store (LD/ST64B extension), same encoding as udma st64b */
static inline void urma_du_st64b(const uint64_t *src, uint64_t *dst)
{
    asm volatile("mov x9, %0\n"
                 "mov x10, %1\n"
                 "ldr x0, [x9]\nldr x1, [x9, #8]\nldr x2, [x9, #16]\nldr x3, [x9, #24]\n"
                 "ldr x4, [x9, #32]\nldr x5, [x9, #40]\nldr x6, [x9, #48]\nldr x7, [x9, #56]\n"
                 ".inst 0xf83f9140\n"
                 ::"r" (src), "r"(dst)
                 : "x0", "x1", "x2", "x3", "x4", "x5", "x6", "x7",
                   "x9", "x10", "cc", "memory");
}

#ifdef __cplusplus
}
#endif

#endif /* URMA_DU_HW_H */
