/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2026-2026. All rights reserved.
 * Description: add moe_combine_recv_async pybind extention file
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

at::Tensor cam_combine_recv_async_impl_npu(
    const at::Tensor &expandX,
    const at::Tensor &expertIds,
    const at::Tensor &expertScales,
    const at::Tensor &commArgs,
    const int64_t commId,
    const int64_t batchSize,
    const int64_t hiddenSize,
    const int64_t topk,
    const int64_t moeRankNum,
    const int64_t attnRankNum,
    const int64_t routeExpertNumPerMoe,
    const int64_t attnRankId,
    const int64_t worldSize,
    c10::string_view groupName)
{
    const std::string groupNameStr(groupName.data(), groupName.size());
    const char* groupNamePtr = groupNameStr.c_str();
    at::Tensor xOut = at::empty({batchSize == 0 ? 1 : batchSize, hiddenSize == 0 ? 1 : hiddenSize}, expandX.options());
    int magic = 0;

    EXEC_NPU_CMD(aclnnCamMoeDistributeCombineRecv,
        // input
        expandX, expertIds, expertScales, commArgs,
        // attr
        magic, batchSize, hiddenSize, topk, moeRankNum, attnRankNum, routeExpertNumPerMoe,
        attnRankId, worldSize, groupNamePtr,
        // output
        xOut);
    return xOut;
}

std::tuple<at::Tensor, at::Tensor> cam_combine_recv_async_backward_impl_npu(const at::Tensor &self)
{
    at::Tensor result = at::Tensor(self);  // create output memory
    return {result, result};
}

at::Tensor cam_combine_recv_async_impl_meta(
    const at::Tensor &expandX,
    const at::Tensor &expertIds,
    const at::Tensor &expertScales,
    const at::Tensor &commArgs,
    const int64_t commId,
    const int64_t batchSize,
    const int64_t hiddenSize,
    const int64_t topk,
    const int64_t moeRankNum,
    const int64_t attnRankNum,
    const int64_t routeExpertNumPerMoe,
    const int64_t attnRankId,
    const int64_t worldSize,
    c10::string_view groupName)
{
    at::Tensor xOut = at::empty({batchSize, hiddenSize}, expandX.options());
    return xOut;
}

at::Tensor cam_combine_recv_async_impl(
    const at::Tensor &expandX,
    const at::Tensor &expertIds,
    const at::Tensor &expertScales,
    const at::Tensor &commArgs,
    const int64_t commId,
    const int64_t batchSize,
    const int64_t hiddenSize,
    const int64_t topk,
    const int64_t moeRankNum,
    const int64_t attnRankNum,
    const int64_t routeExpertNumPerMoe,
    const int64_t attnRankId,
    const int64_t worldSize,
    c10::string_view groupName)
{
    static auto op = torch::Dispatcher::singleton()
                         .findSchemaOrThrow("umdk_cam_op_lib::moe_combine_recv_async", "")
                         .typed<decltype(cam_combine_recv_async_impl)>();
    return op.call(expandX, expertIds, expertScales, commArgs, commId, batchSize,
        hiddenSize, topk, moeRankNum, attnRankNum, routeExpertNumPerMoe, attnRankId, worldSize, groupName);
}

// bind forward/backward via torch::autograd::Function subclass
class ExtCamCombineRecvAsync : public torch::autograd::Function<ExtCamCombineRecvAsync> {
public:
    static at::Tensor forward(AutogradContext *ctx, \
                                const at::Tensor &expandX,
                                const at::Tensor &expertIds,
                                const at::Tensor &expertScales,
                                const at::Tensor &commArgs,
                                const int64_t commId,
                                const int64_t batchSize,
                                const int64_t hiddenSize,
                                const int64_t topk,
                                const int64_t moeRankNum,
                                const int64_t attnRankNum,
                                const int64_t routeExpertNumPerMoe,
                                const int64_t attnRankId,
                                const int64_t worldSize,
                                c10::string_view groupName)
    {
        at::AutoDispatchBelowADInplaceOrView guard;

        auto result = cam_combine_recv_async_impl(expandX, expertIds, expertScales, commArgs,
            commId, batchSize, hiddenSize, topk, moeRankNum, attnRankNum, routeExpertNumPerMoe,
            attnRankId, worldSize, groupName);
        return result;
    }

    static tensor_list backward(AutogradContext *ctx, tensor_list grad_outputs)
    {
        return {at::Tensor(),
                at::Tensor(),
                at::Tensor(),
                at::Tensor(),
                at::Tensor(),
                at::Tensor(),
                at::Tensor(),
                at::Tensor(),
                at::Tensor(),
                at::Tensor(),
                at::Tensor()};
    }
};

at::Tensor cam_combine_recv_async_impl_autograd(
    const at::Tensor &expandX,
    const at::Tensor &expertIds,
    const at::Tensor &expertScales,
    const at::Tensor &commArgs,
    const int64_t commId,
    const int64_t batchSize,
    const int64_t hiddenSize,
    const int64_t topk,
    const int64_t moeRankNum,
    const int64_t attnRankNum,
    const int64_t routeExpertNumPerMoe,
    const int64_t attnRankId,
    const int64_t worldSize,
    c10::string_view groupName)
{
    auto result = ExtCamCombineRecvAsync::apply(expandX, expertIds, expertScales, commArgs,
        commId, batchSize, hiddenSize, topk, moeRankNum, attnRankNum, routeExpertNumPerMoe,
        attnRankId, worldSize, groupName);
    return result;
}

TORCH_LIBRARY_IMPL(umdk_cam_op_lib, PrivateUse1, m)
{
    m.impl("moe_combine_recv_async", &cam_combine_recv_async_impl_npu);
}

TORCH_LIBRARY_IMPL(umdk_cam_op_lib, AutogradPrivateUse1, m)
{
    m.impl("moe_combine_recv_async", &cam_combine_recv_async_impl_autograd);
}

// register forward/backward impl for Meta device
TORCH_LIBRARY_IMPL(umdk_cam_op_lib, Meta, m)
{
    m.impl("moe_combine_recv_async", &cam_combine_recv_async_impl_meta);
}