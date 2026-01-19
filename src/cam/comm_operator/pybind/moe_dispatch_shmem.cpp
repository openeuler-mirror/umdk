/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2026-2026. All rights reserved.
 * Description: add moe_dispatch_shmem pybind extention file
 * Create: 2026-01-06
 * Note:
 * History: 2026-01-06 create moe_dispatch_shmem pybind extention file
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

constexpr uint32_t DYNAMIC_QUANT_MODE = 2;

inline TensorVector GenerateDispatchOutputTensor(
    const at::Tensor &x, \
    const at::Tensor &expertIds, \
    int64_t epWorldSize, \
    int64_t epRankId, \
    int64_t moeExpertNum, \
    int64_t tpWorldSize, \
    int64_t sharedExpertRankNum, \
    int64_t quantMode, \
    bool isMeta)
{
    bool isSharedExpert = epRankId < sharedExpertRankNum;
    if (epWorldSize == sharedExpertRankNum) {
        printf("Wrong parameters! Check the validation of sharedExpertRankNum");
        return {at::Tensor(),
                at::Tensor(),
                at::Tensor(),
                at::Tensor(),
                at::Tensor(),
                at::Tensor(),
                at::Tensor()};
    }

    auto expandXShape = x.sizes();
    int expertPerRank = moeExpertNum / (epWorldSize - sharedExpertRankNum);
    auto expertIdsShape = expertIds.sizes();

    int bs = expandXShape[0];
    int h = expandXShape[1];
    int k = expertIdsShape[1];
    int expandPara = epWorldSize * (expertPerRank <= k ? expertPerRank : k);

    int expandXOutNum = bs * expandPara;
    if (isSharedExpert) {
        expandXOutNum = bs * epWorldSize / sharedExpertRankNum;
    }

    // 申请输出Tensor资源
    at::Tensor expandXOut;
    at::Tensor dynamicScalesOut;
    at::Tensor expandIdxOut;
    at::Tensor expertTokenNumsOut;
    at::Tensor epSendCountOut;
    at::Tensor tpSendCountOut;

    if (isMeta) { // 每个输出变量都需要指定为mata设备类型
        at::TensorOptions options = at::TensorOptions(at::kMeta);
        // 当前只支持动态量化
        if (quantMode == DYNAMIC_QUANT_MODE) {
            expandXOut = at::empty({expandXOutNum, h}, x.options().dtype((at::kChar)).device(at::kMeta));
        } else {
            expandXOut = at::empty({expandXOutNum, h}, x.options().device(at::kMeta));
        }
        dynamicScalesOut = at::empty({expandXOutNum}, options.dtype(at::kFloat));
        expandIdxOut = at::empty({bs * k}, expertIds.options().device(at::kMeta));
        expertTokenNumsOut = at::empty({isSharedExpert ? 1 : expertPerRank},
            expertIds.options().dtype(at::kLong).device(at::kMeta));
        epSendCountOut = at::empty({isSharedExpert ? epWorldSize : epWorldSize * expertPerRank},
            expertIds.options().device(at::kMeta));
        tpSendCountOut = at::empty({tpWorldSize}, expertIds.options().device(at::kMeta));
    } else {
        at::TensorOptions options = at::TensorOptions(torch_npu::utils::get_npu_device_type());
        // 当前只支持动态量化
        if (quantMode == DYNAMIC_QUANT_MODE) {
            expandXOut = at::empty({expandXOutNum, h}, x.options().dtype((at::kChar)));
        } else {
            expandXOut = at::empty({expandXOutNum, h}, x.options());
        }
        dynamicScalesOut = at::empty({expandXOutNum}, options.dtype(at::kFloat));
        expandIdxOut = at::empty({bs * k}, expertIds.options());
        expertTokenNumsOut = at::empty({isSharedExpert ? 1 : expertPerRank},
            expertIds.options().dtype(at::kLong));
        epSendCountOut = at::empty({isSharedExpert ? epWorldSize : epWorldSize * expertPerRank},
            expertIds.options());
        tpSendCountOut = at::empty({tpWorldSize}, expertIds.options());
    }

    TensorVector ret = {
        expandXOut,
        dynamicScalesOut,
        expandIdxOut,
        expertTokenNumsOut,
        epSendCountOut,
        tpSendCountOut
    };

    return ret;
}

TensorVector MoeDispatchShmemImplNpu(
    const at::Tensor &x, \
    const at::Tensor &expertIds, \
    const c10::optional<at::Tensor> &scales, \
    const c10::optional<at::Tensor> &xActiveMask, \
    int64_t epWorldSize, \
    int64_t epRankId, \
    int64_t moeExpertNum, \
    int64_t tpWorldSize, \
    int64_t tpRankId, \
    int64_t expertShardType, \
    int64_t sharedExpertNum, \
    int64_t sharedExpertRankNum, \
    int64_t quantMode, \
    int64_t globalBS, \
    int64_t expertTokenNumsType, \
    int64_t extInfo)
{
    TensorVector outList = GenerateDispatchOutputTensor(x, expertIds, epWorldSize, epRankId, moeExpertNum,
                                                            tpWorldSize, sharedExpertRankNum, quantMode, false);
    at::Tensor expandXOut = outList[0];
    at::Tensor dynamicScalesOut = outList[1];
    at::Tensor expandIdxOut = outList[2];
    at::Tensor expertTokenNumsOut = outList[3];
    at::Tensor epSendCountOut = outList[4];
    at::Tensor tpSendCountOut = outList[5];
    
    EXEC_NPU_CMD(aclnnMoeDispatchShmem,
        // input
        x, expertIds, scales, xActiveMask, \
        // attr
        epWorldSize, epRankId, moeExpertNum, tpWorldSize, tpRankId, expertShardType, \
        sharedExpertNum, sharedExpertRankNum, quantMode, globalBS, expertTokenNumsType, extInfo, \
        // output
        expandXOut, dynamicScalesOut, expandIdxOut, expertTokenNumsOut, epSendCountOut, tpSendCountOut);

    return outList;
}

TensorVector MoeDispatchShmemBackwardImplNpu(const at::Tensor &self)
{
    at::Tensor result = at::Tensor(self); // 创建输出内存
    return {result, result, result};
}

TensorVector MoeDispatchShmemImplMeta(
    const at::Tensor &x, \
    const at::Tensor &expertIds, \
    const c10::optional<at::Tensor> &scales, \
    const c10::optional<at::Tensor> &xActiveMask, \
    int64_t epWorldSize, \
    int64_t epRankId, \
    int64_t moeExpertNum, \
    int64_t tpWorldSize, \
    int64_t tpRankId, \
    int64_t expertShardType, \
    int64_t sharedExpertNum, \
    int64_t sharedExpertRankNum, \
    int64_t quantMode, \
    int64_t globalBS, \
    int64_t expertTokenNumsType, \
    int64_t extInfo)
{
    // reserved parameters
    (void) xActiveMask;
    (void) tpRankId;
    (void) expertShardType;
    (void) sharedExpertNum;
    (void) globalBS;
    (void) expertTokenNumsType;
    (void) extInfo;

    return GenerateDispatchOutputTensor(x, expertIds, epWorldSize, epRankId, moeExpertNum,
        tpWorldSize, sharedExpertRankNum, quantMode, true);
}

TensorVector MoeDispatchShmemImpl(
    const at::Tensor &x, \
    const at::Tensor &expertIds, \
    const c10::optional<at::Tensor> &scales, \
    const c10::optional<at::Tensor> &xActiveMask, \
    int64_t epWorldSize, \
    int64_t epRankId, \
    int64_t moeExpertNum, \
    int64_t tpWorldSize, \
    int64_t tpRankId, \
    int64_t expertShardType, \
    int64_t sharedExpertNum, \
    int64_t sharedExpertRankNum, \
    int64_t quantMode, \
    int64_t globalBS, \
    int64_t expertTokenNumsType, \
    int64_t extInfo)
{
    static auto op = torch::Dispatcher::singleton()
                        .findSchemaOrThrow("umdk_cam_op_lib::moe_dispatch_shmem", "")
                        .typed<decltype(MoeDispatchShmemImpl)>();
    return op.call(x, expertIds, scales, xActiveMask, \
        epWorldSize, epRankId, moeExpertNum, tpWorldSize, tpRankId, expertShardType, \
        sharedExpertNum, sharedExpertRankNum, quantMode, globalBS, expertTokenNumsType, extInfo);
}

// 通过继承torch::autograd::Function类实现前反向绑定
class MoeDispatchShmem : public torch::autograd::Function<MoeDispatchShmem> {
public:
    static TensorVector forward(
        AutogradContext *ctx, \
        const at::Tensor &x, \
        const at::Tensor &expertIds, \
        const c10::optional<at::Tensor> &scales, \
        const c10::optional<at::Tensor> &xActiveMask, \
        int64_t epWorldSize, \
        int64_t epRankId, \
        int64_t moeExpertNum, \
        int64_t tpWorldSize, \
        int64_t tpRankId, \
        int64_t expertShardType, \
        int64_t sharedExpertNum, \
        int64_t sharedExpertRankNum, \
        int64_t quantMode, \
        int64_t globalBS, \
        int64_t expertTokenNumsType, \
        int64_t extInfo)
    {
        at::AutoDispatchBelowADInplaceOrView guard;
        auto result = MoeDispatchShmemImpl(x, expertIds, scales, xActiveMask, \
            epWorldSize, epRankId, moeExpertNum, tpWorldSize, tpRankId, expertShardType, \
            sharedExpertNum, sharedExpertRankNum, quantMode, globalBS, expertTokenNumsType, extInfo);

        return result;
    }

    static TensorVector backward(
        AutogradContext *ctx, \
        TensorVector grad_outputs)
    {
        return {at::Tensor(), at::Tensor(), at::Tensor()};
    }
};

TensorVector MoeDispatchShmemImplAutograd(
    const at::Tensor &x, \
    const at::Tensor &expertIds, \
    const c10::optional<at::Tensor> &scales, \
    const c10::optional<at::Tensor> &xActiveMask, \
    int64_t epWorldSize, \
    int64_t epRankId, \
    int64_t moeExpertNum, \
    int64_t tpWorldSize, \
    int64_t tpRankId, \
    int64_t expertShardType, \
    int64_t sharedExpertNum, \
    int64_t sharedExpertRankNum, \
    int64_t quantMode, \
    int64_t globalBS, \
    int64_t expertTokenNumsType, \
    int64_t extInfo)
{
    auto result = MoeDispatchShmem::apply(x, expertIds, scales, xActiveMask, \
            epWorldSize, epRankId, moeExpertNum, tpWorldSize, tpRankId, expertShardType, \
            sharedExpertNum, sharedExpertRankNum, quantMode, globalBS, expertTokenNumsType, extInfo);
    return result;
}

// moe_dispatch_shmem
TORCH_LIBRARY_IMPL(umdk_cam_op_lib, PrivateUse1, m)
{
    m.impl("moe_dispatch_shmem", &MoeDispatchShmemImplNpu);
    m.impl("moe_dispatch_shmem_backward", &MoeDispatchShmemBackwardImplNpu);
}

TORCH_LIBRARY_IMPL(umdk_cam_op_lib, AutogradPrivateUse1, m)
{
    m.impl("moe_dispatch_shmem", &MoeDispatchShmemImplAutograd);
}

// 为Meta设备注册前反向实现
TORCH_LIBRARY_IMPL(umdk_cam_op_lib, Meta, m)
{
    m.impl("moe_dispatch_shmem", &MoeDispatchShmemImplMeta);
}