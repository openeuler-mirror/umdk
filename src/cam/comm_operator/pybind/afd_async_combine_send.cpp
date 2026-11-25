/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2026-2026. All rights reserved.
 * Description: add afd_async_combine_send pybind extention file
 * Create: 2026-09-17
 * Note:
 * History: 2026-09-17 initial CAM port
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

constexpr int KERNEL_PARAM_CNT = 3;

at::Tensor afd_async_combine_send_impl_npu(
    const at::Tensor &expandX,
    const at::Tensor &commArgs,
    const at::Tensor &batchInfo,
    const int64_t commId,
    const int64_t maxSeqLen,
    const int64_t hiddenSize,
    const int64_t topk,
    const int64_t moeRankNum,
    const int64_t attnRankNum,
    const int64_t routeExpertNumPerMoe,
    const int64_t moeRankId,
    const int64_t worldSize,
    const int64_t tpSize,
    c10::string_view groupName)
{
    const std::string groupNameStr(groupName.data(), groupName.size());
    const char* groupNamePtr = groupNameStr.c_str();
    at::Tensor expandXOut = at::empty({1}, expandX.options().dtype(at::kChar));
    int magic = 0;

    // inputs first, then attrs, then output
    EXEC_NPU_CMD(aclnnAfdAsyncCombineSend,
        // input
        expandX, commArgs, batchInfo,
        // attr
        magic, maxSeqLen, hiddenSize, topk, moeRankNum, attnRankNum, routeExpertNumPerMoe,
        moeRankId, worldSize, tpSize, groupNamePtr,
        // output
        expandXOut);
    return expandXOut;
}

std::tuple<at::Tensor, at::Tensor> afd_async_combine_send_backward_impl_npu(const at::Tensor &self)
{
    at::Tensor result = at::Tensor(self);  // create output memory
    return {result, result};
}

at::Tensor afd_async_combine_send_impl_meta(
    const at::Tensor &expandX,
    const at::Tensor &commArgs,
    const at::Tensor &batchInfo,
    const int64_t commId,
    const int64_t maxSeqLen,
    const int64_t hiddenSize,
    const int64_t topk,
    const int64_t moeRankNum,
    const int64_t attnRankNum,
    const int64_t routeExpertNumPerMoe,
    const int64_t moeRankId,
    const int64_t worldSize,
    const int64_t tpSize,
    c10::string_view groupName)
{
    at::Tensor result = at::empty({1}, expandX.options().dtype(at::kChar));
    return result;
}

at::Tensor afd_async_combine_send_impl(
    const at::Tensor &expandX,
    const at::Tensor &commArgs,
    const at::Tensor &batchInfo,
    const int64_t commId,
    const int64_t maxSeqLen,
    const int64_t hiddenSize,
    const int64_t topk,
    const int64_t moeRankNum,
    const int64_t attnRankNum,
    const int64_t routeExpertNumPerMoe,
    const int64_t moeRankId,
    const int64_t worldSize,
    const int64_t tpSize,
    c10::string_view groupName)
{
    static auto op = torch::Dispatcher::singleton()
                         .findSchemaOrThrow("umdk_cam_op_lib::afd_async_combine_send", "")
                         .typed<decltype(afd_async_combine_send_impl)>();
    return op.call(expandX, commArgs, batchInfo, commId, maxSeqLen,
        hiddenSize, topk, moeRankNum, attnRankNum, routeExpertNumPerMoe, moeRankId, worldSize, tpSize, groupName);
}

// bind forward/backward via torch::autograd::Function subclass
class ExtCamCombineSendAsync : public torch::autograd::Function<ExtCamCombineSendAsync> {
public:
    static at::Tensor forward(AutogradContext *ctx,
                              const at::Tensor &expandX,
                              const at::Tensor &commArgs,
                              const at::Tensor &batchInfo,
                              const int64_t commId,
                              const int64_t maxSeqLen,
                              const int64_t hiddenSize,
                              const int64_t topk,
                              const int64_t moeRankNum,
                              const int64_t attnRankNum,
                              const int64_t routeExpertNumPerMoe,
                              const int64_t moeRankId,
                              const int64_t worldSize,
                              const int64_t tpSize,
                              c10::string_view groupName)
    {
        at::AutoDispatchBelowADInplaceOrView guard;

        auto result = afd_async_combine_send_impl(expandX, commArgs, batchInfo, commId, maxSeqLen,
            hiddenSize, topk, moeRankNum, attnRankNum, routeExpertNumPerMoe, moeRankId, worldSize, tpSize, groupName);
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
                at::Tensor(),
                at::Tensor(),
                at::Tensor(),
                at::Tensor()};
    }
};

at::Tensor afd_async_combine_send_impl_autograd(
    const at::Tensor &expandX,
    const at::Tensor &commArgs,
    const at::Tensor &batchInfo,
    const int64_t commId,
    const int64_t maxSeqLen,
    const int64_t hiddenSize,
    const int64_t topk,
    const int64_t moeRankNum,
    const int64_t attnRankNum,
    const int64_t routeExpertNumPerMoe,
    const int64_t moeRankId,
    const int64_t worldSize,
    const int64_t tpSize,
    c10::string_view groupName)
{
    auto result = ExtCamCombineSendAsync::apply(expandX, commArgs, batchInfo, commId, maxSeqLen,
        hiddenSize, topk, moeRankNum, attnRankNum, routeExpertNumPerMoe, moeRankId, worldSize, tpSize, groupName);
    return result;
}

// cam_combine_send
TORCH_LIBRARY_IMPL(umdk_cam_op_lib, PrivateUse1, m)
{
    m.impl("afd_async_combine_send", &afd_async_combine_send_impl_npu);
}

TORCH_LIBRARY_IMPL(umdk_cam_op_lib, AutogradPrivateUse1, m)
{
    m.impl("afd_async_combine_send", &afd_async_combine_send_impl_autograd);
}

// register forward/backward impl for Meta device
TORCH_LIBRARY_IMPL(umdk_cam_op_lib, Meta, m)
{
    m.impl("afd_async_combine_send", &afd_async_combine_send_impl_meta);
}
