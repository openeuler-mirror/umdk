/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2026-2026. All rights reserved.
 * Description: add moe_dispatch_recv_async pybind extention file
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

constexpr int64_t MAX_BATCH_SIZE = 1024 * 256;
constexpr int64_t INFO_NUM = 5; // number of valid batch-info fields
constexpr char BATCH_SIZE_FACTOR[] = "BATCH_SIZE_FACTOR";
constexpr float DEFAULT_BATCH_SIZE_FACTOR = 1.0;

static inline float get_batch_size_factor()
{
    float factor = DEFAULT_BATCH_SIZE_FACTOR;
    auto env = std::getenv(BATCH_SIZE_FACTOR);
    if (env != nullptr) {
        try {
            std::string envStr(env);
            factor = std::stof(envStr);
        } catch (...) {
            cerr << "Unknown Exception encountered when parser env BATCH_SIZE_FACTOR" << endl;
        }
    }
    return factor;
}

tensor_list cam_dispatch_recv_async_impl_npu(
    const at::Tensor &x,
    const at::Tensor &commArgs,
    const int64_t commId,
    const int64_t batchSize,
    const int64_t hiddenSize,
    const int64_t topk,
    const int64_t moeRankNum,
    const int64_t attnRankNum,
    const int64_t routeExpertNumPerMoe,
    const int64_t moeRankId,
    const int64_t worldSize,
    const int64_t tpSize,
    const int64_t dynamicQuant,
    c10::string_view groupName)
{
    const std::string groupNameStr(groupName.data(), groupName.size());
    const char* groupNamePtr = groupNameStr.c_str();
    float batchSizeFactor = get_batch_size_factor();
    int64_t maxTokenNum = (int64_t)(MAX_BATCH_SIZE * batchSizeFactor);
    int64_t maxTokenNumShared = MAX_BATCH_SIZE / moeRankNum;
    at::Tensor expandXOut;
    at::Tensor expandXOutShared;
    at::Tensor dynamicScalesOut;
    at::Tensor dynamicScalesOutShared;
    if (dynamicQuant != 0) {
        expandXOut = at::empty({maxTokenNum, hiddenSize}, x.options().dtype(at::kChar));
        dynamicScalesOut = at::empty({maxTokenNum}, x.options().dtype(at::kFloat));
        expandXOutShared = at::empty({maxTokenNumShared, hiddenSize}, x.options().dtype(at::kChar));
        dynamicScalesOutShared = at::empty({maxTokenNumShared}, x.options().dtype(at::kFloat));
    } else {
        expandXOut = at::empty({maxTokenNum, hiddenSize}, x.options());
        dynamicScalesOut = at::empty({1}, x.options().dtype(at::kFloat));
        expandXOutShared = at::empty({maxTokenNumShared, hiddenSize}, x.options());
        dynamicScalesOutShared = at::empty({1}, x.options().dtype(at::kFloat));
    }

    int64_t batchInfoNum = INFO_NUM + tpSize + (routeExpertNumPerMoe + 1) * tpSize;
    at::Tensor batchInfoOut = at::empty({batchInfoNum}, x.options().dtype(at::kLong));
    at::Tensor epRecvCountRouted = at::empty({routeExpertNumPerMoe}, x.options().dtype(at::kLong));
    at::Tensor epRecvCountShared = at::empty({1}, x.options().dtype(at::kLong));
    int magic = 0;

    tensor_list ret = {
        expandXOut,
        expandXOutShared,
        dynamicScalesOut,
        dynamicScalesOutShared,
        batchInfoOut,
        epRecvCountRouted,
        epRecvCountShared
    };

    EXEC_NPU_CMD(aclnnCamMoeDistributeDispatchRecv,
        // input
        x, commArgs,
        // attr
        magic, batchSize, hiddenSize, topk, moeRankNum, attnRankNum,
        routeExpertNumPerMoe, moeRankId, worldSize, tpSize, dynamicQuant, groupNamePtr,
        // output
        expandXOut, expandXOutShared, dynamicScalesOut, dynamicScalesOutShared,
        batchInfoOut, epRecvCountRouted, epRecvCountShared);

    return ret;
}

std::tuple<at::Tensor, at::Tensor> cam_dispatch_recv_async_backward_impl_npu(const at::Tensor &self)
{
    at::Tensor result = at::Tensor(self);  // create output memory
    return {result, result};
}

tensor_list cam_dispatch_recv_async_impl_meta(
    const at::Tensor &x,
    const at::Tensor &commArgs,
    const int64_t commId,
    const int64_t batchSize,
    const int64_t hiddenSize,
    const int64_t topk,
    const int64_t moeRankNum,
    const int64_t attnRankNum,
    const int64_t routeExpertNumPerMoe,
    const int64_t moeRankId,
    const int64_t worldSize,
    const int64_t tpSize,
    const int64_t dynamicQuant,
    c10::string_view groupName)
{
    float batchSizeFactor = get_batch_size_factor();
    int64_t maxTokenNum = (int64_t)(MAX_BATCH_SIZE * batchSizeFactor);
    int64_t maxTokenNumShared = MAX_BATCH_SIZE / moeRankNum;
    at::Tensor expandXOut;
    at::Tensor expandXOutShared;
    at::Tensor dynamicScalesOut;
    at::Tensor dynamicScalesOutShared;
    if (dynamicQuant != 0) {
        expandXOut = at::empty({maxTokenNum, hiddenSize}, x.options().dtype(at::kChar));
        dynamicScalesOut = at::empty({maxTokenNum}, x.options().dtype(at::kFloat));
        expandXOutShared = at::empty({maxTokenNumShared, hiddenSize}, x.options().dtype(at::kChar));
        dynamicScalesOutShared = at::empty({maxTokenNumShared}, x.options().dtype(at::kFloat));
    } else {
        expandXOut = at::empty({maxTokenNum, hiddenSize}, x.options());
        dynamicScalesOut = at::empty({1}, x.options().dtype(at::kFloat));
        expandXOutShared = at::empty({maxTokenNumShared, hiddenSize}, x.options());
        dynamicScalesOutShared = at::empty({1}, x.options().dtype(at::kFloat));
    }

    int64_t batchInfoNum = INFO_NUM + tpSize + (routeExpertNumPerMoe + 1) * tpSize;
    at::Tensor batchInfoOut = at::empty({batchInfoNum}, x.options().dtype(at::kLong));
    at::Tensor epRecvCountRouted = at::empty({routeExpertNumPerMoe}, x.options().dtype(at::kLong));
    at::Tensor epRecvCountShared = at::empty({1}, x.options().dtype(at::kLong));

    tensor_list ret = {
        expandXOut,
        expandXOutShared,
        dynamicScalesOut,
        dynamicScalesOutShared,
        batchInfoOut,
        epRecvCountRouted,
        epRecvCountShared
    };

    return ret;
}

tensor_list cam_dispatch_recv_async_impl(
    const at::Tensor &x,
    const at::Tensor &commArgs,
    const int64_t commId,
    const int64_t batchSize,
    const int64_t hiddenSize,
    const int64_t topk,
    const int64_t moeRankNum,
    const int64_t attnRankNum,
    const int64_t routeExpertNumPerMoe,
    const int64_t moeRankId,
    const int64_t worldSize,
    const int64_t tpSize,
    const int64_t dynamicQuant,
    c10::string_view groupName)
{
    static auto op = torch::Dispatcher::singleton()
                         .findSchemaOrThrow("umdk_cam_op_lib::moe_dispatch_recv_async", "")
                         .typed<decltype(cam_dispatch_recv_async_impl)>();
    return op.call(x, commArgs, commId, batchSize, hiddenSize, topk, moeRankNum,
        attnRankNum, routeExpertNumPerMoe, moeRankId, worldSize, tpSize, dynamicQuant, groupName);
}

// bind forward/backward via torch::autograd::Function subclass
class ExtCamDispatchRecvAsync : public torch::autograd::Function<ExtCamDispatchRecvAsync> {
public:
    static tensor_list forward(AutogradContext *ctx,
                                const at::Tensor &x,
                                const at::Tensor &commArgs,
                                const int64_t commId,
                                const int64_t batchSize,
                                const int64_t hiddenSize,
                                const int64_t topk,
                                const int64_t moeRankNum,
                                const int64_t attnRankNum,
                                const int64_t routeExpertNumPerMoe,
                                const int64_t moeRankId,
                                const int64_t worldSize,
                                const int64_t tpSize,
                                const int64_t dynamicQuant,
                                c10::string_view groupName)
{
        at::AutoDispatchBelowADInplaceOrView guard;

        auto result = cam_dispatch_recv_async_impl(x, commArgs, commId, batchSize, hiddenSize, topk, moeRankNum,
            attnRankNum, routeExpertNumPerMoe, moeRankId, worldSize, tpSize, dynamicQuant, groupName);
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

tensor_list cam_dispatch_recv_async_impl_autograd(
    const at::Tensor &x,
    const at::Tensor &commArgs,
    const int64_t commId,
    const int64_t batchSize,
    const int64_t hiddenSize,
    const int64_t topk,
    const int64_t moeRankNum,
    const int64_t attnRankNum,
    const int64_t routeExpertNumPerMoe,
    const int64_t moeRankId,
    const int64_t worldSize,
    const int64_t tpSize,
    const int64_t dynamicQuant,
    c10::string_view groupName)
{
    auto result = ExtCamDispatchRecvAsync::apply(x, commArgs, commId, batchSize, hiddenSize, topk, moeRankNum,
        attnRankNum, routeExpertNumPerMoe, moeRankId, worldSize, tpSize, dynamicQuant, groupName);
    return result;
}

// cam_dispatch_recv
TORCH_LIBRARY_IMPL(umdk_cam_op_lib, PrivateUse1, m)
{
    m.impl("moe_dispatch_recv_async", &cam_dispatch_recv_async_impl_npu);
}

TORCH_LIBRARY_IMPL(umdk_cam_op_lib, AutogradPrivateUse1, m)
{
    m.impl("moe_dispatch_recv_async", &cam_dispatch_recv_async_impl_autograd);
}

// register forward/backward impl for Meta device
TORCH_LIBRARY_IMPL(umdk_cam_op_lib, Meta, m)
{
    m.impl("moe_dispatch_recv_async", &cam_dispatch_recv_async_impl_meta);
}
