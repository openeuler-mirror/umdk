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
#include <vector>

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

    // ZB fused deep moe: runs the whole expert computation with SHMEM round buffers.
    // 与 cam_feature 保持一致：TensorList 参数用 std::vector<at::Tensor> 声明，
    // 实现内部再转 at::TensorList 传给 aclnnFusedDeepMoeZb。
    std::tuple<at::Tensor, at::Tensor, at::Tensor> zb_fused_deep_moe(
        const at::Tensor &x, const at::Tensor &expertIds, const std::vector<at::Tensor> &gmm1Weight,
        const std::vector<at::Tensor> &gmm1WeightScale, const std::vector<at::Tensor> &gmm2Weight,
        const std::vector<at::Tensor> &gmm2WeightScale, const at::Tensor &expertScales,
        const c10::optional<at::Tensor> &shareGmm1WeightOptional,
        const c10::optional<at::Tensor> &shareGmm1WeightScaleOptional,
        const c10::optional<at::Tensor> &shareGmm2WeightOptional,
        const c10::optional<at::Tensor> &shareGmm2WeightScaleOptional,
        const c10::optional<at::Tensor> &expertSmoothScalesOptional,
        const c10::optional<at::Tensor> &shareSmoothScalesOptional,
        const c10::optional<at::Tensor> &xActiveMaskOptional,
        const std::vector<at::Tensor> &gmm1BiasOptional, const std::vector<at::Tensor> &gmm2BiasOptional,
        const c10::optional<at::Tensor> &shareGmm1BiasOptional,
        const c10::optional<at::Tensor> &shareGmm2BiasOptional, c10::string_view groupEp,
        int64_t epRankSize, int64_t epRankId, int64_t moeExpertNum, int64_t quantMode, int64_t globalBs);

private:
    uint64_t EnsureShmemWorkspace();
    void InitShmem(int64_t localMemSize, const std::string &ipPort);
    // 固定预分配 dispatch/combine 路径的 layout/notify 槽位（numTokensPerExpert_/recvData_）。
    // zb_fused_deep_moe 的 EnsureShmemWorkspace 会从整个 SHMEM 池中减去这部分字节，
    // 避免重复 malloc 耗尽 SHMEM 池。
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

    // SHMEM workspace for the fused deep moe round buffers (extInfo = metaPtr_).
    // 与 cam_feature 一致：整个 SHMEM 池除去 meta 与已预分配的 layout/notify 槽位外，
    // 一次性分配给 fused，总大小传给 op_host，由 op_host 自己推导 roundRecvTokenNum。
    void *shmemWorkspacePtr_{nullptr};
    uint64_t shmemWorkspaceSize_{0};
    int64_t localMemSize_{0};         // whole SHMEM pool from ctor
    int64_t layoutNotifyBytes_{0};    // preallocated layout/notify slot bytes (numTokensPerExpert_ + recvData_)

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
