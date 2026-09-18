/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2026-2026. All rights reserved.
 * Description: add moe_dispatch_send_async pybind extention file
 * Create: 2026-09-17
 * Note:
 * History: 2026-09-17 port from cam_async repository
 */

#include <unistd.h>
#include <hccl/hccl.h>
#include <torch/extension.h>
#include <torch/csrc/autograd/custom_function.h>
#include <iostream>
#include "pytorch_npu_helper.hpp"

using torch::autograd::AutogradContext;
using torch::autograd::Function;
using tensor_list = std::vector<at::Tensor>;
using namespace at;
using namespace std;

at::Tensor cam_dispatch_send_async_impl_npu(
    const at::Tensor &x,
    const at::Tensor &expertIds,
    const at::Tensor &commArgs,
    const int64_t commId,
    const int64_t maxSeqLen,
    const int64_t batchSize,
    const int64_t hiddenSize,
    const int64_t topk,
    const int64_t moeRankNum,
    const int64_t attnRankNum,
    const int64_t routeExpertNumPerMoe,
    const int64_t attnRankId,
    const int64_t worldSize,
    const int64_t layerIndex,
    const int64_t tpSize,
    const int64_t dynamicQuant,
    c10::string_view groupName)
{
    const std::string groupNameStr(groupName.data(), groupName.size());
    const char* groupNamePtr = groupNameStr.c_str();
    at::Tensor expandXOut = at::empty({1}, x.options().dtype(at::kChar));
    int magic = 0;

    EXEC_NPU_CMD(aclnnCamMoeDistributeDispatchSend,
        // input
        x, expertIds, commArgs,
        // attr
        magic, maxSeqLen, batchSize, hiddenSize, topk, moeRankNum, attnRankNum, routeExpertNumPerMoe,
        attnRankId, worldSize, layerIndex, tpSize, dynamicQuant, groupNamePtr,
        // output
        expandXOut);
    return expandXOut;
}

std::tuple<at::Tensor, at::Tensor> cam_dispatch_send_async_backward_impl_npu(const at::Tensor &self)
{
    at::Tensor result = at::Tensor(self);  // create output memory
    return {result, result};
}

at::Tensor cam_dispatch_send_async_impl_meta(
    const at::Tensor &x,
    const at::Tensor &expertIds,
    const at::Tensor &commArgs,
    const int64_t commId,
    const int64_t maxSeqLen,
    const int64_t batchSize,
    const int64_t hiddenSize,
    const int64_t topk,
    const int64_t moeRankNum,
    const int64_t attnRankNum,
    const int64_t routeExpertNumPerMoe,
    const int64_t attnRankId,
    const int64_t worldSize,
    const int64_t layerIndex,
    const int64_t tpSize,
    const int64_t dynamicQuant,
    c10::string_view groupName)
{
    at::Tensor ret = at::empty({1}, x.options().dtype(at::kChar));
    return ret;
}

at::Tensor cam_dispatch_send_async_impl(
    const at::Tensor &x,
    const at::Tensor &expertIds,
    const at::Tensor &commArgs,
    const int64_t commId,
    const int64_t maxSeqLen,
    const int64_t batchSize,
    const int64_t hiddenSize,
    const int64_t topk,
    const int64_t moeRankNum,
    const int64_t attnRankNum,
    const int64_t routeExpertNumPerMoe,
    const int64_t attnRankId,
    const int64_t worldSize,
    const int64_t layerIndex,
    const int64_t tpSize,
    const int64_t dynamicQuant,
    c10::string_view groupName)
{
    static auto op = torch::Dispatcher::singleton()
                         .findSchemaOrThrow("umdk_cam_op_lib::moe_dispatch_send_async", "")
                         .typed<decltype(cam_dispatch_send_async_impl)>();
    return op.call(x, expertIds, commArgs, commId, maxSeqLen, batchSize,
        hiddenSize, topk, moeRankNum, attnRankNum, routeExpertNumPerMoe, attnRankId,
        worldSize, layerIndex, tpSize, dynamicQuant, groupName);
}

// bind forward/backward via torch::autograd::Function subclass
class ExtCamDispatchSendAsync : public torch::autograd::Function<ExtCamDispatchSendAsync> {
public:
    static at::Tensor forward(AutogradContext *ctx,
                                const at::Tensor &x,
                                const at::Tensor &expertIds,
                                const at::Tensor &commArgs,
                                const int64_t commId,
                                const int64_t maxSeqLen,
                                const int64_t batchSize,
                                const int64_t hiddenSize,
                                const int64_t topk,
                                const int64_t moeRankNum,
                                const int64_t attnRankNum,
                                const int64_t routeExpertNumPerMoe,
                                const int64_t attnRankId,
                                const int64_t worldSize,
                                const int64_t layerIndex,
                                const int64_t tpSize,
                                const int64_t dynamicQuant,
                                c10::string_view groupName)
{
        at::AutoDispatchBelowADInplaceOrView guard;

        auto result = cam_dispatch_send_async_impl(x, expertIds, commArgs, commId, maxSeqLen, batchSize,
            hiddenSize, topk, moeRankNum, attnRankNum, routeExpertNumPerMoe, attnRankId,
            worldSize, layerIndex, tpSize, dynamicQuant, groupName);
        return result;
    }

    static tensor_list backward(AutogradContext *ctx, tensor_list grad_outputs)
    {
        return {at::Tensor(),
                at::Tensor(),
                at::Tensor(),
                at::Tensor(),
                at::Tensor(),
                at::Tensor()};
    }
};

at::Tensor cam_dispatch_send_async_impl_autograd(
    const at::Tensor &x,
    const at::Tensor &expertIds,
    const at::Tensor &commArgs,
    const int64_t commId,
    const int64_t maxSeqLen,
    const int64_t batchSize,
    const int64_t hiddenSize,
    const int64_t topk,
    const int64_t moeRankNum,
    const int64_t attnRankNum,
    const int64_t routeExpertNumPerMoe,
    const int64_t attnRankId,
    const int64_t worldSize,
    const int64_t layerIndex,
    const int64_t tpSize,
    const int64_t dynamicQuant,
    c10::string_view groupName)
{
    auto result = ExtCamDispatchSendAsync::apply(x, expertIds, commArgs, commId, maxSeqLen, batchSize,
        hiddenSize, topk, moeRankNum, attnRankNum, routeExpertNumPerMoe, attnRankId,
        worldSize, layerIndex, tpSize, dynamicQuant, groupName);
    return result;
}

// cam_dispatch_send
TORCH_LIBRARY_IMPL(umdk_cam_op_lib, PrivateUse1, m)
{
    m.impl("moe_dispatch_send_async", &cam_dispatch_send_async_impl_npu);
}

TORCH_LIBRARY_IMPL(umdk_cam_op_lib, AutogradPrivateUse1, m)
{
    m.impl("moe_dispatch_send_async", &cam_dispatch_send_async_impl_autograd);
}

// register forward/backward impl for Meta device
TORCH_LIBRARY_IMPL(umdk_cam_op_lib, Meta, m)
{
    m.impl("moe_dispatch_send_async", &cam_dispatch_send_async_impl_meta);
}