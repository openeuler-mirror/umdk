/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2026-2026. All rights reserved.
 * Description: helpers to allocate SHMEM-backed tensors for ZB ops
 * Create: 2026-08-01
 * Note:
 * History: 2026-08-01 create zb_shmem_utils header
 */

#ifndef CAM_PYBIND_ZB_SHMEM_UTILS_H_
#define CAM_PYBIND_ZB_SHMEM_UTILS_H_

#include <stdexcept>
#include <vector>

#include <ATen/ATen.h>
#include <c10/core/Device.h>
#include <c10/core/ScalarType.h>
#include <torch/extension.h>

#include "torch_npu/csrc/aten/common/from_blob.h"

#ifdef SHMEM_ENABLED
#include "shmem.h"
#endif

namespace cam_zb {

inline at::Tensor CreateTensorFromShmem(const std::vector<int64_t> &shape, at::ScalarType dtype, c10::Device device)
{
#ifdef SHMEM_ENABLED
    int64_t numel = 1;
    for (auto v : shape) {
        if (v <= 0) {
            throw std::runtime_error("CreateTensorFromShmem: invalid shape dimension");
        }
        if (numel > (INT64_MAX / v)) {
            throw std::runtime_error("CreateTensorFromShmem: numel overflow");
        }
        numel *= v;
    }

    size_t eleSize = c10::elementSize(dtype);
    if (eleSize == 0) {
        throw std::runtime_error("CreateTensorFromShmem: invalid dtype element size");
    }
    if (static_cast<uint64_t>(numel) > (UINT64_MAX / eleSize)) {
        throw std::runtime_error("CreateTensorFromShmem: byte size overflow");
    }
    size_t bytes = static_cast<size_t>(numel) * eleSize;

    void *devPtr = aclshmem_malloc(bytes);
    if (devPtr == nullptr) {
        throw std::runtime_error(
            "CreateTensorFromShmem: aclshmem_malloc failed. "
            "Ensure aclshmem is initialized and local_mem_size has enough free space.");
    }

    // torch_npu from_blob (see torch_npu/csrc/aten/common/from_blob.h). No deleter overload
    // in current packages — memory is reclaimed by aclshmem_finalize / process exit.
    auto options = torch::TensorOptions().dtype(dtype).device(device);
    return at_npu::native::from_blob(devPtr, c10::IntArrayRef(shape), options);
#else
    (void)shape;
    (void)dtype;
    (void)device;
    throw std::runtime_error(
        "ZB ops require SHMEM. Export SHMEM_HOME_PATH and rebuild umdk_cam_op_lib.");
#endif
}

}  // namespace cam_zb

#endif  // CAM_PYBIND_ZB_SHMEM_UTILS_H_
