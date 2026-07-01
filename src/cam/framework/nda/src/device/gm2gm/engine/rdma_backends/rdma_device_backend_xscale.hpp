/**
 * Copyright (c) 2026 Huawei Technologies Co., Ltd.
 * This program is free software, you can redistribute it and/or modify it under the terms and conditions of
 * CANN Open Software License Agreement Version 2.0 (the "License").
 * Please refer to the License for details. You may not use this file except in compliance with the License.
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR IMPLIED,
 * INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY, OR FITNESS FOR A PARTICULAR PURPOSE.
 * See LICENSE in the root of the software repository for the full text of the License.
 */
#ifndef ACLSHMEM_RDMA_DEVICE_BACKEND_XSCALE_HPP
#define ACLSHMEM_RDMA_DEVICE_BACKEND_XSCALE_HPP

#include <type_traits>
#include "rdma_device_backend_base.h"

constexpr int ACLSHMEMI_XSCALE_API_VERSION_VAR = 2;
constexpr int ACLSHMEMI_XSCALE_API_VERSION_V1 = 1;
constexpr int ACLSHMEMI_XSCALE_API_VERSION_V2 = 2;

static_assert(ACLSHMEMI_XSCALE_API_VERSION_VAR == ACLSHMEMI_XSCALE_API_VERSION_V1 ||
                  ACLSHMEMI_XSCALE_API_VERSION_VAR == ACLSHMEMI_XSCALE_API_VERSION_V2,
              "ACLSHMEMI_XSCALE_API_VERSION must be 1 or 2");

struct aclshmemi_xscdv_wqe_ctrl_seg_v1 {
    uint8_t msg_opcode;
    uint8_t with_imm    : 1;
    uint8_t csum_en     : 2;
    uint8_t ds_data_num : 5;
    uint16_t wqe_id; // wqe ds index = wqe_idx << 3 (ACLSHMEMI_XSCALE_SND_WQE_SHIFT - ACLSHMEMI_XSCALE_BASE_WQE_SHIFT)
    uint32_t msg_len;
    /**** 8 bytes ****/
    uint32_t opcode_data;
    /**** 12 bytes ****/
    uint32_t se         : 1;
    uint32_t ce         : 1; // If set to 1, a CQE will be generated
    uint32_t in_line    : 1;
    uint32_t fence_mode : 2;
    uint32_t mask       : 2;
    uint32_t rsv        : 25;
    /**** 16 bytes ****/
};

struct aclshmemi_xscdv_wqe_ctrl_seg_v2 {
    uint8_t msg_opcode;
    uint8_t with_imm    : 1;
    uint8_t csum_en     : 2;
    uint8_t ds_data_num : 5;
    uint16_t rsv1;
    uint32_t msg_len;
    /**** 8 bytes ****/
    uint32_t opcode_data;
    /**** 12 bytes ****/
    uint32_t se         : 1;
    uint32_t ce         : 1; // If set to 1, a CQE will be generated
    uint32_t in_line    : 1;
    uint32_t fence_mode : 2;
    uint32_t mask       : 2;
    uint32_t rsv        : 5;
    uint32_t wqe_id     : 20; // wqe ds index = wqe_idx << 3
                              // (ACLSHMEMI_XSCALE_SND_WQE_SHIFT - ACLSHMEMI_XSCALE_BASE_WQE_SHIFT)
    /**** 16 bytes ****/
};

using aclshmemi_xscdv_wqe_ctrl_seg_t =
    std::conditional_t<ACLSHMEMI_XSCALE_API_VERSION_VAR == 1, aclshmemi_xscdv_wqe_ctrl_seg_v1,
                       aclshmemi_xscdv_wqe_ctrl_seg_v2>;

struct aclshmemi_xscdv_wqe_data_seg_t {
    union {
        struct {
            uint32_t rsv     : 1;
            uint32_t seg_len : 31;
            uint32_t m_key; // Use lkey for local address, rkey for remote address
            /**** 8 bytes ****/
            uint64_t va;
            /**** 16 bytes ****/
        };
        struct {
            uint8_t inline_data[16];
        };
    };
    /**** 16 bytes ****/
};

struct aclshmemi_xscdv_diamond_cqe_v1 {
    uint32_t error_code : 8;
    uint32_t qp_id      : 15; // Corresponds to the QP's qpn
    uint32_t rsv        : 1;
    uint32_t se         : 1;
    uint32_t has_pph    : 1;
    uint32_t type       : 1;
    uint32_t with_imm   : 1;
    uint32_t csum_err   : 4;
    /**** 4 bytes ****/
    uint32_t imm_data;
    /**** 8 bytes ****/
    uint32_t msg_len;
    uint32_t vni;
    /**** 16 bytes ****/
    uint64_t ts     : 48;
    uint64_t wqe_id : 16; // Corresponds to wqe_id << 3 in the WQE
                          // (ACLSHMEMI_XSCALE_SND_WQE_SHIFT - ACLSHMEMI_XSCALE_BASE_WQE_SHIFT)
    /**** 24 bytes ****/
    uint8_t msg_opcode;
    uint8_t rsv0;
    uint16_t rsv1[2];
    uint16_t rsv2  : 15;
    uint16_t owner : 1; // Checking the owner bit confirms whether the current CQE can be parsed by software
    /**** 32 bytes ****/
};

struct aclshmemi_xscdv_diamond_cqe_v2 {
    union {
        struct {
            uint32_t error_code : 8;  // [0:7]
            uint32_t qp_id      : 15; // [8:22] Corresponds to the QP's qpn
            // [23:31] flags
            uint32_t rsv        : 1;
            uint32_t se         : 1;
            uint32_t has_pph    : 1;
            uint32_t type       : 1;
            uint32_t with_imm   : 1;
            uint32_t csum_err   : 4;
        };
        uint32_t flags_qp_id_err_code;
    };
    /**** 4 bytes ****/
    uint32_t imm_data; // immediate value
    /**** 8 bytes ****/
    uint32_t msg_len; // message length
    /**** 12 bytes ****/
    uint32_t vni;
    /**** 16 bytes ****/
    uint32_t ts_l;
    /**** 20 bytes ****/
    uint32_t ts_h;
    /**** 24 bytes ****/
    union {
        struct {
            uint32_t msg_opcode : 8; // [0:7] msg_opcode of corresponding finished wqe, check aclshmemi_xscdv_msg_type_t
            uint32_t rsv1       : 4; // [8:11]
            uint32_t wqe_id     : 20; // [12:31] Corresponds to wqe_id << 3 in the WQE
        };
        uint32_t wqe_id_rsv_opcode;
    };
    /**** 28 bytes ****/
    union {
        struct {
            uint32_t rsv2  : 31;
            uint32_t owner : 1; // Owner bit, checking the owner bit confirms whether the current CQE can be parsed by
                                // software
        };
        uint32_t owner_rsv;
    };
    /**** 32 bytes ****/
};

using aclshmemi_xscdv_diamond_cqe_t =
    std::conditional_t<ACLSHMEMI_XSCALE_API_VERSION_VAR == 1, aclshmemi_xscdv_diamond_cqe_v1,
                       aclshmemi_xscdv_diamond_cqe_v2>;

struct aclshmemi_xscdv_cqe64_t {
    aclshmemi_xscdv_diamond_cqe_t cqe;
    /**** 32 bytes ****/
    uint8_t padding[32];
    /**** 64 bytes ****/
};

union aclshmemi_xscdv_diamond_cq_doorbell_t {
    struct {
        uint64_t cq_next_cid : 23; // ID of the next CQE to be processed in the CQ, e.g., if 4 CQEs have been processed,
                                   // cq_next_cid is 4
        uint64_t cq_id       : 16; // Corresponds to the CQ's cqn
        uint64_t cq_sta      : 2;
        /**** 8 bytes ****/
    };
    uint64_t raw;
};

union aclshmemi_xscdv_diamond_recv_doorbell_t {
    struct {
        uint64_t next_pid : 17; // ID of the next WQE to be processed in the RQ, e.g., if WQEs 0-3 are to be sent,
                                // next_pid is 4
        uint64_t qp_id    : 16; // Corresponds to the RQ's qpn
        /**** 8 bytes ****/
    };
    uint64_t raw;
};

union aclshmemi_xscdv_diamond_send_doorbell_v1 {
    struct {
        uint64_t next_pid : 17; // ID of the next WQE to be processed in the SQ, e.g., if WQEs 0-3 are to be sent,
                                // next_pid is 4
        uint64_t qp_id    : 16; // Corresponds to the SQ's qpn
        /**** 8 bytes ****/
    };
    uint64_t raw;
};

union aclshmemi_xscdv_diamond_send_doorbell_v2 {
    struct {
        uint64_t next_pid : 21; // ID of the next WQE to be processed in the SQ, e.g., if WQEs 0-3 are to be sent,
                                // next_pid is 4
        uint64_t qp_id    : 16; // Corresponds to the SQ's qpn
        /**** 8 bytes ****/
    };
    uint64_t raw;
};

using aclshmemi_xscdv_diamond_send_doorbell_t =
    std::conditional_t<ACLSHMEMI_XSCALE_API_VERSION_VAR == 1, aclshmemi_xscdv_diamond_send_doorbell_v1,
                       aclshmemi_xscdv_diamond_send_doorbell_v2>;

struct aclshmemi_xscdv_diamond_data_seg_t {
    uint32_t length;
    uint32_t key;
    /**** 8 bytes ****/
    uint64_t addr;
    /**** 16 bytes ****/
};

struct aclshmemi_xsc_wqe_atomic_seg_t {
    uint64_t swap_add;
    /**** 8 bytes ****/
    uint64_t compare;
    /**** 16 bytes ****/
};

struct aclshmemi_xsc_wqe_atomic_64_masked_fa_seg_t {
    uint64_t add_data;
    /**** 8 bytes ****/
    uint64_t field_boundary;
    /**** 16 bytes ****/
};

struct aclshmemi_xsc_wqe_atomic_32_masked_fa_seg_t {
    uint32_t add_data;
    /**** 4 bytes ****/
    uint32_t field_boundary;
    /**** 8 bytes ****/
    uint64_t reserved;
    /**** 16 bytes ****/
};

struct aclshmemi_xsc_wqe_atomic_64_masked_cas_seg_t {
    uint64_t swap_add;
    /**** 8 bytes ****/
    uint64_t compare;
    /**** 16 bytes ****/
};

struct aclshmemi_xsc_wqe_atomic_32_masked_cas_seg_t {
    uint32_t swap_data;
    /**** 4 bytes ****/
    uint32_t compare_data;
    /**** 8 bytes ****/
    uint32_t swap_mask;
    /**** 12 bytes ****/
    uint32_t compare_mask;
    /**** 16 bytes ****/
};

enum class aclshmemi_xscdv_msg_type_t : uint32_t {
    ACLSHMEMI_XSCALE_MSG_OPCODE_RDMA_WRITE = 1,
    ACLSHMEMI_XSCALE_MSG_OPCODE_RDMA_READ = 2,
    ACLSHMEMI_XSCALE_MSG_OPCODE_RDMA_ATOMIC_CMP_AND_SWAP = 26,
    ACLSHMEMI_XSCALE_MSG_OPCODE_RDMA_ATOMIC_FETCH_AND_ADD = 27,
    ACLSHMEMI_XSCALE_MSG_OPCODE_RDMA_ATOMIC_8B_MSK_CMP_AND_SWAP = 31,
    ACLSHMEMI_XSCALE_MSG_OPCODE_RDMA_ATOMIC_8B_MSK_FETCH_AND_ADD = 32,
    ACLSHMEMI_XSCALE_MSG_OPCODE_RDMA_ATOMIC_4B_MSK_CMP_AND_SWAP = 33,
    ACLSHMEMI_XSCALE_MSG_OPCODE_RDMA_ATOMIC_4B_MSK_FETCH_AND_ADD = 34,
};

enum class aclshmemi_xsc_opcode_t : uint32_t {
    ACLSHMEMI_XSC_OPCODE_RDMA_REQ_SEND = 0,
    ACLSHMEMI_XSC_OPCODE_RDMA_REQ_SEND_IMMDT = 1,
    ACLSHMEMI_XSC_OPCODE_RDMA_RSP_RECV = 2,
    ACLSHMEMI_XSC_OPCODE_RDMA_RSP_RECV_IMMDT = 3,
    ACLSHMEMI_XSC_OPCODE_RDMA_REQ_WRITE = 4,
    ACLSHMEMI_XSC_OPCODE_RDMA_REQ_WRITE_IMMDT = 5,
    ACLSHMEMI_XSC_OPCODE_RDMA_RSP_WRITE_IMMDT = 6,
    ACLSHMEMI_XSC_OPCODE_RDMA_REQ_READ = 7,
    ACLSHMEMI_XSC_OPCODE_RDMA_REQ_ERROR = 8,
    ACLSHMEMI_XSC_OPCODE_RDMA_RSP_ERROR = 9,
    ACLSHMEMI_XSC_OPCODE_RDMA_CQE_ERROR = 10,
    ACLSHMEMI_XSC_OPCODE_RDMA_MAD_REQ_SEND = 11,
    ACLSHMEMI_XSC_OPCODE_RDMA_MAD_RSP_RECV = 12,
    ACLSHMEMI_XSC_OPCODE_RDMA_CQE_RAW_SNF = 13,
};

constexpr int ACLSHMEMI_XSCALE_BASE_WQE_SHIFT = 4;
constexpr int ACLSHMEMI_XSCALE_SND_WQE_SHIFT = 7;
constexpr uint32_t ACLSHMEMI_XSCALE_SND_WQE_SIZE = 1 << ACLSHMEMI_XSCALE_SND_WQE_SHIFT;

constexpr uint32_t ACLSHMEMI_XSC_CQE_OWNER_MASK = 1;

constexpr uint64_t ACLSHMEMI_BYTE_WIDTH = 8;
constexpr uint64_t ACLSHMEMI_BYTE_MASK = 0xFF;

constexpr uint32_t BYTES_32 = sizeof(uint32_t);
constexpr uint32_t BYTES_64 = sizeof(uint64_t);

constexpr uint64_t ACLSHMEMI_HOST_BYTE_7_SHIFT = 0;
constexpr uint64_t ACLSHMEMI_HOST_BYTE_6_SHIFT = ACLSHMEMI_BYTE_WIDTH * 1; // 8
constexpr uint64_t ACLSHMEMI_HOST_BYTE_5_SHIFT = ACLSHMEMI_BYTE_WIDTH * 2; // 16
constexpr uint64_t ACLSHMEMI_HOST_BYTE_4_SHIFT = ACLSHMEMI_BYTE_WIDTH * 3; // 24
constexpr uint64_t ACLSHMEMI_HOST_BYTE_3_SHIFT = ACLSHMEMI_BYTE_WIDTH * 4; // 32
constexpr uint64_t ACLSHMEMI_HOST_BYTE_2_SHIFT = ACLSHMEMI_BYTE_WIDTH * 5; // 40
constexpr uint64_t ACLSHMEMI_HOST_BYTE_1_SHIFT = ACLSHMEMI_BYTE_WIDTH * 6; // 48
constexpr uint64_t ACLSHMEMI_HOST_BYTE_0_SHIFT = ACLSHMEMI_BYTE_WIDTH * 7; // 56

constexpr uint64_t ACLSHMEMI_BE_BYTE_0_SHIFT = ACLSHMEMI_BYTE_WIDTH * 7; // 56
constexpr uint64_t ACLSHMEMI_BE_BYTE_1_SHIFT = ACLSHMEMI_BYTE_WIDTH * 6; // 48
constexpr uint64_t ACLSHMEMI_BE_BYTE_2_SHIFT = ACLSHMEMI_BYTE_WIDTH * 5; // 40
constexpr uint64_t ACLSHMEMI_BE_BYTE_3_SHIFT = ACLSHMEMI_BYTE_WIDTH * 4; // 32
constexpr uint64_t ACLSHMEMI_BE_BYTE_4_SHIFT = ACLSHMEMI_BYTE_WIDTH * 3; // 24
constexpr uint64_t ACLSHMEMI_BE_BYTE_5_SHIFT = ACLSHMEMI_BYTE_WIDTH * 2; // 16
constexpr uint64_t ACLSHMEMI_BE_BYTE_6_SHIFT = ACLSHMEMI_BYTE_WIDTH * 1; // 8
constexpr uint64_t ACLSHMEMI_BE_BYTE_7_SHIFT = 0;

#if defined(__DAV_C220_VEC__) || defined(__DAV_C220_CUBE__)
constexpr uint64_t ACLSHMEMI_XSC_CYCLE_TO_TIME_BASE = 50;
#else
constexpr uint64_t ACLSHMEMI_XSC_CYCLE_TO_TIME_BASE = 1000;
#endif
constexpr uint64_t ACLSHMEMI_XSC_POLL_CQ_TIMEOUT_DURATION = 5ULL * 60 * 1000000; // 5 minutes in microseconds
constexpr uint64_t ACLSHMEMI_XSC_POLL_CQ_TIMEOUT_CYCLES =
    ACLSHMEMI_XSC_POLL_CQ_TIMEOUT_DURATION *
    ACLSHMEMI_XSC_CYCLE_TO_TIME_BASE; // the maximum cycles to wait for a single CQE
// Set the error code to exceed the maximum value of cqe->error_code to ensure it can be used for judgment
constexpr uint32_t ACLSHMEMI_XSC_POLL_CQ_TIMEOUT_ERROR = 0x10000;

ACLSHMEM_DEVICE uint64_t aclshmemi_htobe64(uint64_t host_val)
{
    return ((host_val >> ACLSHMEMI_HOST_BYTE_7_SHIFT) & ACLSHMEMI_BYTE_MASK) << ACLSHMEMI_BE_BYTE_0_SHIFT |
           ((host_val >> ACLSHMEMI_HOST_BYTE_6_SHIFT) & ACLSHMEMI_BYTE_MASK) << ACLSHMEMI_BE_BYTE_1_SHIFT |
           ((host_val >> ACLSHMEMI_HOST_BYTE_5_SHIFT) & ACLSHMEMI_BYTE_MASK) << ACLSHMEMI_BE_BYTE_2_SHIFT |
           ((host_val >> ACLSHMEMI_HOST_BYTE_4_SHIFT) & ACLSHMEMI_BYTE_MASK) << ACLSHMEMI_BE_BYTE_3_SHIFT |
           ((host_val >> ACLSHMEMI_HOST_BYTE_3_SHIFT) & ACLSHMEMI_BYTE_MASK) << ACLSHMEMI_BE_BYTE_4_SHIFT |
           ((host_val >> ACLSHMEMI_HOST_BYTE_2_SHIFT) & ACLSHMEMI_BYTE_MASK) << ACLSHMEMI_BE_BYTE_5_SHIFT |
           ((host_val >> ACLSHMEMI_HOST_BYTE_1_SHIFT) & ACLSHMEMI_BYTE_MASK) << ACLSHMEMI_BE_BYTE_6_SHIFT |
           ((host_val >> ACLSHMEMI_HOST_BYTE_0_SHIFT) & ACLSHMEMI_BYTE_MASK) << ACLSHMEMI_BE_BYTE_7_SHIFT;
}

ACLSHMEM_DEVICE uint32_t aclshmemi_htobe32(uint32_t host_val)
{
    return ((host_val >> ACLSHMEMI_HOST_BYTE_4_SHIFT) & ACLSHMEMI_BYTE_MASK) << ACLSHMEMI_BE_BYTE_7_SHIFT |
           ((host_val >> ACLSHMEMI_HOST_BYTE_5_SHIFT) & ACLSHMEMI_BYTE_MASK) << ACLSHMEMI_BE_BYTE_6_SHIFT |
           ((host_val >> ACLSHMEMI_HOST_BYTE_6_SHIFT) & ACLSHMEMI_BYTE_MASK) << ACLSHMEMI_BE_BYTE_5_SHIFT |
           ((host_val >> ACLSHMEMI_HOST_BYTE_7_SHIFT) & ACLSHMEMI_BYTE_MASK) << ACLSHMEMI_BE_BYTE_4_SHIFT;
}

/**
 * @brief Write data from UB local buffer to GM global memory with synchronization
 *
 * This function writes data from local UB (Uniform Buffer) to specified GM (Global Memory) address
 * with complete hardware synchronization sequence to ensure data write completion.
 *
 * @tparam T Data type template parameter
 * @param addr GM target address where data will be written
 * @param ub_local Local UB buffer containing data to write
 * @param size Data size in bytes to write
 * @param sync_id Synchronization event ID for hardware event synchronization
 *
 * @note Synchronization sequence:
 *   1. S_MTE3: Scalar to MTE3 synchronization before data copy
 *   2. DataCopyPad: Execute data copy from UB to GM
 *   3. PIPE_MTE3: MTE3 pipeline barrier to ensure all MTE3 operations complete
 *   4. MTE3_S: MTE3 to Scalar synchronization after data copy
 *
 * @note Usage: Used in RDMA operations to update critical data structures in global memory
 *       (e.g., CQ tail pointer, SQ head pointer, doorbell registers) with strict synchronization.
 */
template <typename T>
ACLSHMEM_DEVICE void aclshmemi_roce_write_ub_to_gm_with_sync(uint64_t addr, AscendC::LocalTensor<T> &ub_local,
                                                             uint32_t size, uint32_t sync_id)
{
    AscendC::SetFlag<AscendC::HardEvent::S_MTE3>(sync_id);
    AscendC::GlobalTensor<T> tmp_global_tensor;
    tmp_global_tensor.SetGlobalBuffer((__gm__ T *)addr);
    AscendC::DataCopyExtParams copy_params{1, size, 0, 0, 0};
    AscendC::WaitFlag<AscendC::HardEvent::S_MTE3>(sync_id);
    AscendC::DataCopyPad(tmp_global_tensor, ub_local, copy_params);
    AscendC::PipeBarrier<PIPE_MTE3>();
    AscendC::SetFlag<AscendC::HardEvent::MTE3_S>(sync_id);
    AscendC::WaitFlag<AscendC::HardEvent::MTE3_S>(sync_id);
}

ACLSHMEM_DEVICE bool aclshmemi_roce_xscale_check_cqe_owner(
    __gm__ aclshmemi_xscdv_cqe64_t *cqe64, uint32_t cur_tail, uint32_t depth)
{
    bool owner_bit = (cqe64->cqe.owner & ACLSHMEMI_XSC_CQE_OWNER_MASK);
    // ! For performance reasons, depth should be a power of two, which will be optimized to bitwise operations by the
    // ! compiler at compile time
    bool expect_bit = ((cur_tail / depth) & 1); // same as (cur_tail >> log2(depth)) & 1
    return owner_bit == expect_bit;
}
template <>
ACLSHMEM_DEVICE void aclshmemi_roce_ring_cq_doorbell<aclshmemi_rdma_backend_t::XSCALE>(
    uint32_t pe, uint32_t qp_idx, uint32_t cur_tail, AscendC::LocalTensor<uint64_t> &ub_local64,
    AscendC::LocalTensor<uint32_t> &ub_local32, uint32_t sync_id)
{
    __gm__ aclshmemi_rdma_info *rdma_info = aclshmemi_qp_info_fetch();

    uint32_t qp_num = rdma_info->qp_num;
    __gm__ aclshmemi_rdma_cq_ctx *cq_context =
        (__gm__ aclshmemi_rdma_cq_ctx *)(rdma_info->scq_ptr +
                                         ((uint64_t)pe * qp_num + qp_idx) * sizeof(aclshmemi_rdma_cq_ctx));
    // Update cur_tail in global memory
    ub_local32.SetValue(0, cur_tail);
    aclshmemi_roce_write_ub_to_gm_with_sync(cq_context->tail_addr, ub_local32, sizeof(uint32_t), sync_id);

    aclshmemi_xscdv_diamond_cq_doorbell_t cq_db_buf;
    cq_db_buf.raw = 0;
    cq_db_buf.cq_next_cid = cur_tail;
    cq_db_buf.cq_id = cq_context->cqn;
    cq_db_buf.cq_sta = 0;
    ub_local64.SetValue(0, cq_db_buf.raw);

    aclshmemi_roce_write_ub_to_gm_with_sync(
        cq_context->db_addr, ub_local64, sizeof(aclshmemi_xscdv_diamond_cq_doorbell_t), sync_id);
}

// This function expects cur_tail to reach target_idx within the internally set timeout period. If this requirement is
// not met when exiting, the function is considered to have an error.
template <>
ACLSHMEM_DEVICE uint32_t aclshmemi_roce_poll_cq<aclshmemi_rdma_backend_t::XSCALE>(
    uint32_t pe, uint32_t qp_idx, uint32_t target_idx, AscendC::LocalTensor<uint64_t> &ub_local64,
    AscendC::LocalTensor<uint32_t> &ub_local32, uint32_t sync_id)
{
    __gm__ aclshmemi_rdma_info *rdma_info = aclshmemi_qp_info_fetch();
    uint32_t qp_num = rdma_info->qp_num;
    __gm__ aclshmemi_rdma_cq_ctx *cq_context =
        (__gm__ aclshmemi_rdma_cq_ctx *)(rdma_info->scq_ptr +
                                         ((uint64_t)pe * qp_num + qp_idx) * sizeof(aclshmemi_rdma_cq_ctx));
    auto cq_base_addr = cq_context->buf_addr;
    auto cqe_size = cq_context->cqe_size;
    auto depth = cq_context->depth;
    auto cur_hardware_tail_addr = cq_context->tail_addr;
    dcci_cachelines((__gm__ uint8_t *)cur_hardware_tail_addr, 8);
    uint32_t cur_tail = *(__gm__ uint32_t *)(cur_hardware_tail_addr);
    uint32_t original_cur_tail = cur_tail;
    uint64_t run_cycles = 0;
    uint32_t status = 0;
    uint32_t wqn = 0;

    while (cur_tail != target_idx) {
        run_cycles = 0;
        __gm__ aclshmemi_xscdv_cqe64_t *cqe_addr =
            (__gm__ aclshmemi_xscdv_cqe64_t *)(cq_base_addr + cqe_size * (cur_tail % depth));
        while (!aclshmemi_roce_xscale_check_cqe_owner(cqe_addr, cur_tail, depth) &&
               run_cycles < ACLSHMEMI_XSC_POLL_CQ_TIMEOUT_CYCLES) {
            run_cycles++;
            dcci_cachelines((__gm__ uint8_t *)cqe_addr, sizeof(aclshmemi_xscdv_cqe64_t));
        }
        if (run_cycles >= ACLSHMEMI_XSC_POLL_CQ_TIMEOUT_CYCLES) {
            // timeout and not received CQE with owner bit set
            status = ACLSHMEMI_XSC_POLL_CQ_TIMEOUT_ERROR;
            ACLSHMEM_DEBUG_FUNC(
                aclshmemi_kernel_printf,
                "Poll CQE timeout: pe=%u, qp_idx=%u, cur_tail=%u, target_idx=%u, original_tail=%u, backend=%u\n", pe,
                qp_idx, cur_tail, target_idx, original_cur_tail, (uint32_t)aclshmemi_rdma_backend_t::XSCALE);
            break;
        }
        cur_tail++;
        wqn = cqe_addr->cqe.qp_id & 0x7FFF; // reserved for multi WQ share the same CQ
        // Check CQE status
        status = cqe_addr->cqe.error_code;
        if (status) {
            // when we receive CQE with error, return
            ACLSHMEM_DEBUG_FUNC(
                aclshmemi_kernel_printf,
                "Receive CQE with error: %d in pe %u, cur_tail: %u, wqn: %u, qp_idx: %u, backend %u\n", status, pe,
                cur_tail, wqn, qp_idx, (uint32_t)aclshmemi_rdma_backend_t::XSCALE);
            break;
        }
    }

    aclshmemi_roce_ring_cq_doorbell<aclshmemi_rdma_backend_t::XSCALE>(
        pe, qp_idx, cur_tail, ub_local64, ub_local32, sync_id);

    return status;
}

ACLSHMEM_DEVICE __gm__ uint8_t *aclshmemi_roce_xscale_fill_wqe_ctrl_seg(
    __gm__ uint8_t *wqe_addr, uint32_t ds_data_num, uint32_t cur_head, aclshmemi_xscdv_msg_type_t opcode,
    uint32_t msg_len, uint32_t inline_mode)
{
    __gm__ aclshmemi_xscdv_wqe_ctrl_seg_t *ctrl_seg = (__gm__ aclshmemi_xscdv_wqe_ctrl_seg_t *)wqe_addr;
    uint32_t wqe_id = cur_head << (ACLSHMEMI_XSCALE_SND_WQE_SHIFT - ACLSHMEMI_XSCALE_BASE_WQE_SHIFT);
    if constexpr (ACLSHMEMI_XSCALE_API_VERSION_VAR == 1) {
        ctrl_seg->wqe_id = wqe_id & 0xFFFF;
    } else {
        ctrl_seg->wqe_id = wqe_id & 0xFFFFF;
    }
    ctrl_seg->with_imm = 0;
    ctrl_seg->ds_data_num = ds_data_num;
    ctrl_seg->ce = 1;
    ctrl_seg->msg_opcode = (uint8_t)opcode;
    ctrl_seg->msg_len = msg_len;
    ctrl_seg->in_line = inline_mode;

    return wqe_addr + sizeof(aclshmemi_xscdv_wqe_ctrl_seg_t);
}

ACLSHMEM_DEVICE __gm__ uint8_t *aclshmemi_roce_xscale_fill_wqe_data_seg(
    __gm__ uint8_t *wqe_addr, uint32_t rkey, __gm__ uint8_t *remote_addr, uint32_t lkey, __gm__ uint8_t *local_addr,
    uint32_t data_len)
{
    __gm__ aclshmemi_xscdv_diamond_data_seg_t *rdata_seg = (__gm__ aclshmemi_xscdv_diamond_data_seg_t *)wqe_addr;
    rdata_seg->length = data_len;
    rdata_seg->key = rkey;
    rdata_seg->addr = (uint64_t)remote_addr;

    __gm__ aclshmemi_xscdv_diamond_data_seg_t *ldata_seg = (__gm__ aclshmemi_xscdv_diamond_data_seg_t *)(rdata_seg + 1);
    ldata_seg->length = data_len;
    ldata_seg->key = lkey;
    ldata_seg->addr = (uint64_t)local_addr;
    return wqe_addr + sizeof(aclshmemi_xscdv_diamond_data_seg_t) + sizeof(aclshmemi_xscdv_diamond_data_seg_t);
}

ACLSHMEM_DEVICE uint32_t aclshmemi_roce_xscale_fill_wqe_write_read(
    aclshmemi_rdma_send_wr &wr, __gm__ aclshmemi_rdma_sq_ctx *&sq_context, __gm__ uint8_t *wqe_addr, uint32_t cur_head,
    aclshmemi_xscdv_msg_type_t opcode)
{
    constexpr uint32_t ACLSHMEMI_XSCDV_WRITE_READ_DS_DATA_NUM = 2;
    constexpr uint32_t XSCDV_WRITE_READ_WQE_SIZE = 128;

    __gm__ uint8_t *cur_wqe_addr = wqe_addr;

    cur_wqe_addr = aclshmemi_roce_xscale_fill_wqe_ctrl_seg(
        cur_wqe_addr, ACLSHMEMI_XSCDV_WRITE_READ_DS_DATA_NUM, cur_head, opcode, wr.message_len, 0);
    cur_wqe_addr = aclshmemi_roce_xscale_fill_wqe_data_seg(
        cur_wqe_addr, wr.rkey, wr.remote_addr, wr.lkey, wr.local_addr, wr.message_len);

    return XSCDV_WRITE_READ_WQE_SIZE;
}

template <>
ACLSHMEM_DEVICE uint32_t
aclshmemi_roce_fill_wqe<aclshmemi_rdma_backend_t::XSCALE, aclshmemi_rdma_opcode_t::OP_RDMA_WRITE>(
    aclshmemi_rdma_send_wr &wr, __gm__ aclshmemi_rdma_sq_ctx *&sq_context, __gm__ uint8_t *wqe_addr, uint32_t cur_head)
{
    return aclshmemi_roce_xscale_fill_wqe_write_read(
        wr, sq_context, wqe_addr, cur_head, aclshmemi_xscdv_msg_type_t::ACLSHMEMI_XSCALE_MSG_OPCODE_RDMA_WRITE);
}

template <>
ACLSHMEM_DEVICE uint32_t
aclshmemi_roce_fill_wqe<aclshmemi_rdma_backend_t::XSCALE, aclshmemi_rdma_opcode_t::OP_RDMA_READ>(
    aclshmemi_rdma_send_wr &wr, __gm__ aclshmemi_rdma_sq_ctx *&sq_context, __gm__ uint8_t *wqe_addr, uint32_t cur_head)
{
    return aclshmemi_roce_xscale_fill_wqe_write_read(
        wr, sq_context, wqe_addr, cur_head, aclshmemi_xscdv_msg_type_t::ACLSHMEMI_XSCALE_MSG_OPCODE_RDMA_READ);
}

#endif // ACLSHMEM_RDMA_DEVICE_BACKEND_XSCALE_HPP
