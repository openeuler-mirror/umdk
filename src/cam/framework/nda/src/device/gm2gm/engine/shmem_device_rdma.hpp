/**
 * Copyright (c) 2025 Huawei Technologies Co., Ltd.
 * This program is free software, you can redistribute it and/or modify it under the terms and conditions of
 * CANN Open Software License Agreement Version 2.0 (the "License").
 * Please refer to the License for details. You may not use this file except in compliance with the License.
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR IMPLIED,
 * INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY, OR FITNESS FOR A PARTICULAR PURPOSE.
 * See LICENSE in the root of the software repository for the full text of the License.
 */
#ifndef ACLSHMEM_DEVICE_RDMA_HPP
#define ACLSHMEM_DEVICE_RDMA_HPP

#include <cstdint>
#include <type_traits>
#include "kernel_operator.h"
#include "device/shmem_def.h"
#include "shmemi_device_rdma.h"
#include "rdma_backends/rdma_device_backend_base.h"
#include "rdma_backends/rdma_device_backend_base.hpp"

// Decide Current RDMA Backend
#include "rdma_backends/rdma_device_backend_in_die.hpp"
#include "rdma_backends/rdma_device_backend_xscale.hpp"

#if defined(ACLSHMEMI_RDMA_K_BACKEND_XSCALE)
#define ACLSHMEMI_K_RDMA_BACKEND (aclshmemi_rdma_backend_t::XSCALE)
#else
#define ACLSHMEMI_K_RDMA_BACKEND (aclshmemi_rdma_backend_t::IN_DIE)
#endif

ACLSHMEM_DEVICE __gm__ aclshmemi_rdma_info *aclshmemi_qp_info_fetch()
{
    __gm__ aclshmemi_rdma_info *rdma_info = (__gm__ aclshmemi_rdma_info *)(aclshmemi_get_qp_info_address(0));
    return rdma_info;
}

template <typename T>
ACLSHMEM_DEVICE void aclshmemi_roce_write(__gm__ T *dst, __gm__ T *src, uint32_t pe, uint32_t qp_idx,
                                          uint64_t message_len, AscendC::LocalTensor<uint64_t> ub_local64,
                                          AscendC::LocalTensor<uint32_t> ub_local32, uint32_t sync_id)
{
    aclshmemi_roce_write<T, ACLSHMEMI_K_RDMA_BACKEND>(dst, src, pe, qp_idx, message_len, ub_local64, ub_local32,
                                                      sync_id);
}

template <typename T>
ACLSHMEM_DEVICE void aclshmemi_roce_read(__gm__ T *dst, __gm__ T *src, uint32_t pe, uint32_t qp_idx,
                                         uint64_t message_len, AscendC::LocalTensor<uint64_t> ub_local64,
                                         AscendC::LocalTensor<uint32_t> ub_local32, uint32_t sync_id)
{
    aclshmemi_roce_read<T, ACLSHMEMI_K_RDMA_BACKEND>(dst, src, pe, qp_idx, message_len, ub_local64, ub_local32,
                                                     sync_id);
}

ACLSHMEM_DEVICE void aclshmemi_roce_quiet(uint32_t pe, uint32_t qp_idx, AscendC::LocalTensor<uint64_t> ub_local64,
                                          AscendC::LocalTensor<uint32_t> ub_local32, uint32_t sync_id)
{
    __gm__ aclshmemi_rdma_info *rdma_info = aclshmemi_qp_info_fetch();
    uint32_t qp_num = rdma_info->qp_num;

    __gm__ aclshmemi_rdma_sq_ctx *sq_context =
        (__gm__ aclshmemi_rdma_sq_ctx *)(rdma_info->sq_ptr + (pe * qp_num + qp_idx) * sizeof(aclshmemi_rdma_sq_ctx));

    auto sq_pi_addr = sq_context->head_addr;
    dcci_cachelines((__gm__ uint8_t *)sq_pi_addr, 8);
    uint32_t cur_head = *(__gm__ uint32_t *)(sq_pi_addr);
    aclshmemi_roce_poll_cq<ACLSHMEMI_K_RDMA_BACKEND>(pe, qp_idx, cur_head, ub_local64, ub_local32, sync_id);
}

#endif // ACLSHMEM_DEVICE_RDMA_HPP
