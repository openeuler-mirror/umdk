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

// Session object for ZB normal layout / notify+dispatch / combine.
// Owns aclshmem init, meta GVA, and named SHMEM tensor slots.
class ZbBuffer {
public:
    ZbBuffer(int64_t rank, int64_t numRanks, int64_t localMemSize, const std::string &ipPort, int64_t hidden,
        int64_t numExperts, bool useQuant, int64_t globalBs);

    ~ZbBuffer() noexcept(false);

    ZbBuffer(const ZbBuffer &) = delete;
    ZbBuffer &operator=(const ZbBuffer &) = delete;

    bool is_initialized() const { return initialized_; }
    int64_t get_comm_meta_ptr() const { return reinterpret_cast<int64_t>(metaPtr_); }

    // Returns (num_tokens_per_expert, send_token_idx). num_tokens_per_expert is a SHMEM slot.
    std::tuple<at::Tensor, at::Tensor> get_dispatch_layout(const at::Tensor &topkIdx);

    // Fused notify + dispatch. Returns (recv_x, scales, handle=put_offset).
    // recv_x / scales are views into preallocated slots sliced to actual_recv.
    std::tuple<at::Tensor, at::Tensor, at::Tensor> dispatch(const at::Tensor &x, const at::Tensor &topkIdx,
        const at::Tensor &sendTokenIdx, const at::Tensor &numTokensPerExpert, int64_t quantMode);

    // Copies expert_out into SHMEM combine slot if needed, then combines.
    at::Tensor combine(const at::Tensor &expertOut, const at::Tensor &topkWeights, const at::Tensor &topkIdx,
        const at::Tensor &handle);

private:
    void InitShmem(int64_t localMemSize, const std::string &ipPort);
    void PreallocateSlots(c10::Device device);
    void FreeSlots();
    void FinalizeShmem();

    int64_t rank_{-1};
    int64_t numRanks_{-1};
    int64_t hidden_{0};
    int64_t numExperts_{0};
    int64_t globalBs_{0};
    bool useQuant_{false};
    bool initialized_{false};

    void *metaPtr_{nullptr};
    static constexpr uint64_t META_BYTES = 2ULL * 1024 * 1024;

    // Named SHMEM slots (owned; expandx_ aliases combine_x_ storage when quant).
    at::Tensor numTokensPerExpert_;
    at::Tensor recvData_;
    at::Tensor combineX_;
    at::Tensor expandx_;
    at::Tensor scales_;

    // Cached across layout → dispatch → combine within one forward.
    at::Tensor sendTokenIdx_;
    at::Tensor putOffset_;
};

}  // namespace cam_zb

#endif  // CAM_PYBIND_ZB_BUFFER_H_
