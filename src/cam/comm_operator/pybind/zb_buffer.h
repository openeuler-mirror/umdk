/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2026-2026. All rights reserved.
 * Description: ZB normal MoE session Buffer (deepep-style SHMEM slot ownership)
 * Create: 2026-08-05
 */

#ifndef CAM_PYBIND_ZB_BUFFER_H_
#define CAM_PYBIND_ZB_BUFFER_H_

#include <cstdint>
#include <string>
#include <tuple>

#include <ATen/ATen.h>
#include <torch/extension.h>

namespace cam_zb {

class ZbBuffer {
public:
    ZbBuffer(int64_t rank, int64_t numRanks, int64_t localMemSize, const std::string &ipPort, int64_t hidden,
        int64_t numExperts, bool useQuant, int64_t globalBs);

    ~ZbBuffer() noexcept(false);

    ZbBuffer(const ZbBuffer &) = delete;
    ZbBuffer &operator=(const ZbBuffer &) = delete;

    bool is_initialized() const { return initialized_; }
    int64_t get_comm_meta_ptr() const { return reinterpret_cast<int64_t>(metaPtr_); }

    std::tuple<at::Tensor, at::Tensor> get_dispatch_layout(const at::Tensor &topkIdx);

    std::tuple<at::Tensor, at::Tensor, at::Tensor> dispatch(const at::Tensor &x, const at::Tensor &topkIdx,
        const at::Tensor &sendTokenIdx, const at::Tensor &numTokensPerExpert, int64_t quantMode);

    at::Tensor combine(const at::Tensor &expertOut, const at::Tensor &topkWeights, const at::Tensor &topkIdx,
        const at::Tensor &handle);

private:
    void InitShmem(int64_t localMemSize, const std::string &ipPort);
    void PreallocateLayoutNotifySlots(c10::Device device);
    void EnsureDispatchCombineSlots(at::ScalarType dtype, c10::Device device, int64_t topk);
    void FreeSlots();
    void FinalizeShmem();

    int64_t rank_{-1};
    int64_t numRanks_{-1};
    int64_t deviceIndex_{-1};  // from aclrtGetDevice, not EP rank
    int64_t hidden_{0};
    int64_t numExperts_{0};
    int64_t globalBs_{0};
    int64_t slotCount_{0};
    bool useQuant_{false};
    at::ScalarType dtype_{at::ScalarType::Undefined};
    bool initialized_{false};

    void *metaPtr_{nullptr};
    static constexpr uint64_t META_BYTES = 2ULL * 1024 * 1024;

    c10::Device NpuDevice() const
    {
        return c10::Device(c10::DeviceType::PrivateUse1, static_cast<c10::DeviceIndex>(deviceIndex_));
    }

    // Quant: expandx_ aliases combineX_ as int8; scales_ separate.
    at::Tensor numTokensPerExpert_;
    at::Tensor recvData_;
    at::Tensor combineX_;
    at::Tensor expandx_;
    at::Tensor scales_;

    at::Tensor sendTokenIdx_;
    at::Tensor putOffset_;
};

}  // namespace cam_zb

#endif  // CAM_PYBIND_ZB_BUFFER_H_
