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

#endif // ACLSHMEM_DEVICE_RDMA_HPP
