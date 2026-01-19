/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2026-2026. All rights reserved.
 * Description: add moe_combine_shmem pybind extention file
 * Create: 2026-01-06
 * Note:
 * History: 2026-01-06 create moe_combine_shmem pybind extention file
 */

#include <unistd.h>
#include <hccl/hccl.h>
#include <torch/extension.h>
#include <torch/csrc/autograd/custom_function.h>
#include "torch_npu/csrc/core/npu/NPUStream.h"
#include "pytorch_npu_helper.hpp"
#include <hccl/hccl.h>
#include <iostream>

using torch::autograd::AutogradContext;
using torch::autograd::Function;
using TensorVector = std::vector<at::Tensor>;
using namespace at;
using namespace std;

constexpr int KERNEL_PARAM_CNT = 3;

inline at::Tensor GenerateCombineOutputTensor(
    const at::Tensor &expandX, \
    const at::Tensor &expertIds, \
    bool isMeta)
{
    auto expandXShape = expandX.sizes();
    auto expertIdsShape = expertIds.sizes();
    int h = expandXShape[1];
    int bs = expertIdsShape[0];
    at::Tensor expandXOut;

    if (isMeta) {
        expandXOut = at::empty({bs, h}, expandX.options().device(at::kMeta));
    } else {
        expandXOut = at::empty({bs, h}, expandX.options());
    }

    return expandXOut;
}

at::Tensor MoeCombineShmemImplNpu(
    const at::Tensor &expandX, \
    const at::Tensor &expertIds, \
    const at::Tensor &expandIdx, \
    const at::Tensor &epSendCounts, \
    const at::Tensor &expertScales, \
    const c10::optional<at::Tensor> &tpSendCounts, \
    const c10::optional<at::Tensor> &xActiveMask, \
    const c10::optional<at::Tensor> &activationScale, \
    const c10::optional<at::Tensor> &weightScale, \
    const c10::optional<at::Tensor> &groupList, \
    const c10::optional<at::Tensor> &expandScales, \
    int64_t epWorldSize, \
    int64_t epRankId, \
    int64_t moeExpertNum, \
    int64_t tpWorldSize, \
    int64_t tpRankId, \
    int64_t expertShardType, \
    int64_t sharedExpertNum, \
    int64_t sharedExpertRankNum, \
    int64_t globalBS, \
    int64_t commQuantMode, \
    int64_t extInfo, \
    int64_t outDtype, \
    int64_t groupListType)
{
    at::Tensor expandXOut = GenerateCombineOutputTensor(expandX, expertIds, false);

    EXEC_NPU_CMD(aclnnMoeCombineShmem,
        // input
        expandX, expertIds, expandIdx, epSendCounts, expertScales, tpSendCounts, xActiveMask, activationScale, \
        weightScale, groupList, expandScales, \
        // attr
        epWorldSize, epRankId, moeExpertNum, tpWorldSize, tpRankId, expertShardType, sharedExpertNum, \
        sharedExpertRankNum, globalBS, commQuantMode, extInfo, outDtype, groupListType, \
        // output
        expandXOut);
    return expandXOut;
}

TensorVector MoeCombineShmemBackwardImplNpu(const at::Tensor &self)
{
    at::Tensor result = at::Tensor(self);
    return {result, result};
}

at::Tensor MoeCombineShmemImplMeta(
    const at::Tensor &expandX, \
    const at::Tensor &expertIds, \
    const at::Tensor &expandIdx, \
    const at::Tensor &epSendCounts, \
    const at::Tensor &expertScales, \
    const c10::optional<at::Tensor> &tpSendCounts, \
    const c10::optional<at::Tensor> &xActiveMask, \
    const c10::optional<at::Tensor> &activationScale, \
    const c10::optional<at::Tensor> &weightScale, \
    const c10::optional<at::Tensor> &groupList, \
    const c10::optional<at::Tensor> &expandScales, \
    int64_t epWorldSize, \
    int64_t epRankId, \
    int64_t moeExpertNum, \
    int64_t tpWorldSize, \
    int64_t tpRankId, \
    int64_t expertShardType, \
    int64_t sharedExpertNum, \
    int64_t sharedExpertRankNum, \
    int64_t globalBS, \
    int64_t commQuantMode, \
    int64_t extInfo, \
    int64_t outDtype, \
    int64_t groupListType)
{
    // reserved parameters
    (void) expandIdx;
    (void) epSendCounts;
    (void) expertScales;
    (void) tpSendCounts;
    (void) xActiveMask;
    (void) activationScale;
    (void) weightScale;
    (void) groupList;
    (void) expandScales;
    (void) epWorldSize;
    (void) epRankId;
    (void) moeExpertNum;
    (void) tpWorldSize;
    (void) tpRankId;
    (void) expertShardType;
    (void) sharedExpertNum;
    (void) sharedExpertRankNum;
    (void) globalBS;
    (void) commQuantMode;
    (void) extInfo;
    (void) outDtype;
    (void) groupListType;

    return GenerateCombineOutputTensor(expandX, expertIds, true);
}

at::Tensor MoeCombineShmemImpl(
    const at::Tensor &expandX, \
    const at::Tensor &expertIds, \
    const at::Tensor &expandIdx, \
    const at::Tensor &epSendCounts, \
    const at::Tensor &expertScales, \
    const c10::optional<at::Tensor> &tpSendCounts, \
    const c10::optional<at::Tensor> &xActiveMask, \
    const c10::optional<at::Tensor> &activationScale, \
    const c10::optional<at::Tensor> &weightScale, \
    const c10::optional<at::Tensor> &groupList, \
    const c10::optional<at::Tensor> &expandScales, \
    int64_t epWorldSize, \
    int64_t epRankId, \
    int64_t moeExpertNum, \
    int64_t tpWorldSize, \
    int64_t tpRankId, \
    int64_t expertShardType, \
    int64_t sharedExpertNum, \
    int64_t sharedExpertRankNum, \
    int64_t globalBS, \
    int64_t commQuantMode, \
    int64_t extInfo, \
    int64_t outDtype, \
    int64_t groupListType)
{
    static auto op = torch::Dispatcher::singleton()
                        .findSchemaOrThrow("umdk_cam_op_lib::moe_combine_shmem", "")
                        .typed<decltype(MoeCombineShmemImpl)>();
    return op.call(expandX, expertIds, expandIdx, epSendCounts, expertScales, tpSendCounts, xActiveMask,
        activationScale, weightScale, groupList, expandScales, epWorldSize, epRankId, moeExpertNum, tpWorldSize,
        tpRankId, expertShardType, sharedExpertNum, sharedExpertRankNum, globalBS, commQuantMode,
        extInfo, outDtype, groupListType);
}

// 通过继承torch::autograd::Function类实现前反向绑定
class MoeCombineShmem : public torch::autograd::Function<MoeCombineShmem> {
public:
    static at::Tensor forward(
        AutogradContext *ctx, \
        const at::Tensor &expandX, \
        const at::Tensor &expertIds, \
        const at::Tensor &expandIdx, \
        const at::Tensor &epSendCounts, \
        const at::Tensor &expertScales, \
        const c10::optional<at::Tensor> &tpSendCounts, \
        const c10::optional<at::Tensor> &xActiveMask, \
        const c10::optional<at::Tensor> &activationScale, \
        const c10::optional<at::Tensor> &weightScale, \
        const c10::optional<at::Tensor> &groupList, \
        const c10::optional<at::Tensor> &expandScales, \
        int64_t epWorldSize, \
        int64_t epRankId, \
        int64_t moeExpertNum, \
        int64_t tpWorldSize, \
        int64_t tpRankId, \
        int64_t expertShardType, \
        int64_t sharedExpertNum, \
        int64_t sharedExpertRankNum, \
        int64_t globalBS, \
        int64_t commQuantMode, \
        int64_t extInfo, \
        int64_t outDtype, \
        int64_t groupListType)
    {
        at::AutoDispatchBelowADInplaceOrView guard;
        auto result = MoeCombineShmemImpl(expandX, expertIds, expandIdx, epSendCounts, expertScales, tpSendCounts,
            xActiveMask, activationScale, weightScale, groupList, expandScales, epWorldSize, epRankId, moeExpertNum,
            tpWorldSize, tpRankId, expertShardType, sharedExpertNum, sharedExpertRankNum, globalBS, commQuantMode,
            extInfo, outDtype, groupListType);
        return result;
    }

    static TensorVector backward(
        AutogradContext *ctx, \
        TensorVector grad_outputs)
    {
        return {at::Tensor(), at::Tensor(), at::Tensor()};
    }
};

at::Tensor MoeCombineShmemImplAutograd(
    const at::Tensor &expandX, \
    const at::Tensor &expertIds, \
    const at::Tensor &expandIdx, \
    const at::Tensor &epSendCounts, \
    const at::Tensor &expertScales, \
    const c10::optional<at::Tensor> &tpSendCounts, \
    const c10::optional<at::Tensor> &xActiveMask, \
    const c10::optional<at::Tensor> &activationScale, \
    const c10::optional<at::Tensor> &weightScale, \
    const c10::optional<at::Tensor> &groupList, \
    const c10::optional<at::Tensor> &expandScales, \
    int64_t epWorldSize, \
    int64_t epRankId, \
    int64_t moeExpertNum, \
    int64_t tpWorldSize, \
    int64_t tpRankId, \
    int64_t expertShardType, \
    int64_t sharedExpertNum, \
    int64_t sharedExpertRankNum, \
    int64_t globalBS, \
    int64_t commQuantMode, \
    int64_t extInfo, \
    int64_t outDtype, \
    int64_t groupListType)
{
    auto result = MoeCombineShmem::apply(expandX, expertIds, expandIdx, epSendCounts, expertScales, tpSendCounts,
        xActiveMask, activationScale, weightScale, groupList, expandScales, epWorldSize, epRankId, moeExpertNum,
        tpWorldSize, tpRankId, expertShardType, sharedExpertNum, sharedExpertRankNum, globalBS, commQuantMode,
        extInfo, outDtype, groupListType);
    return result;
}

// moe_combine_shmem
TORCH_LIBRARY_IMPL(umdk_cam_op_lib, PrivateUse1, m)
{
    m.impl("moe_combine_shmem", &MoeCombineShmemImplNpu);
    m.impl("moe_combine_shmem_backward", &MoeCombineShmemBackwardImplNpu);
}

TORCH_LIBRARY_IMPL(umdk_cam_op_lib, AutogradPrivateUse1, m)
{
    m.impl("moe_combine_shmem", &MoeCombineShmemImplAutograd);
}

// 为Meta设备注册前反向实现
TORCH_LIBRARY_IMPL(umdk_cam_op_lib, Meta, m)
{
    m.impl("moe_combine_shmem", &MoeCombineShmemImplMeta);
}