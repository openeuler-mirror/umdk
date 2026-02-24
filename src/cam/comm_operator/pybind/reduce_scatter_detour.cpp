/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2025-2025. All rights reserved.
 * Description: add reduceScatter detour file
 * Create: 2026-01-22
 * Note:
 * History: 2026-01-22 reduceScatter detour file
 */

#include <unistd.h>
#include <hccl/hccl.h>
#include <torch/extension.h>
#include <torch/csrc/autograd/custom_function.h>
#include "torch_npu/csrc/core/npu/NPUStream.h"
#include "pytorch_npu_helper.hpp"
#include <hccl/hccl.h>
#include "cam_api.h"
#include "cam_comm.h"
#include <iostream>
#include "ext_utils.h"

using torch::autograd::AutogradContext;
using torch::autograd::Function;
using tensor_list = std::vector<at::Tensor>;
using namespace at;
using namespace std;

at::Tensor reduce_scatter_detour_impl_npu(
    const at::Tensor &sendData, \
    const at::Tensor &commRankIds, \
    const at::Tensor &commArgs, \
    const int64_t commId, \
    const int64_t op)
{
    int32_t rankSize = cam_get_rank_size(commId);
    int64_t groupSize = commRankIds.numel();
    auto shape = sendData.sizes();
    std::vector<int64_t> shapeVec(shape.vec());
    shapeVec[0] = shapeVec[0] / groupSize;
    at::IntArrayRef modifiedShape(shapeVec);
    at::Tensor recvData = at::empty(modifiedShape, sendData.options());
    uint32_t magic = cam_get_and_increase_magic(commId);
    EXEC_NPU_CMD(aclnnReduceScatterDetour, sendData, commRankIds, commArgs, magic, rankSize, op, recvData);

    return recvData;
}

std::tuple<at::Tensor, at::Tensor> reduce_scatter_detour_backward_impl_npu(const at::Tensor &self)
{
    at::Tensor result = at::Tensor(self);
    return {result, result};
}

at::Tensor reduce_scatter_detour_impl_meta(
    const at::Tensor &sendData, \
    const at::Tensor &commRankIds, \
    const at::Tensor &commArgs, \
    const int64_t commId, \
    const int64_t op)
{
    int32_t rankSize = cam_get_rank_size(commId);
    int64_t groupSize = commRankIds.numel();
    auto shape = sendData.sizes();
    std::vector<int64_t> shapeVec(shape.vec());
    shapeVec[0] = shapeVec[0] / groupSize;
    at::IntArrayRef modifiedShape(shapeVec);
    at::Tensor recvData = at::empty(modifiedShape, sendData.options());
    return recvData;
}

at::Tensor reduce_scatter_detour_impl(
    const at::Tensor &sendData, \
    const at::Tensor &commRankIds, \
    const at::Tensor &commArgs, \
    const int64_t commId,
    const int64_t op)
{
    static auto rsOp = torch::Dispatcher::singleton()
                        .findSchemaOrThrow("umdk_cam_op_lib::reduce_scatter_detour", "")
                        .typed<decltype(reduce_scatter_detour_impl)>();
    return rsOp.call(sendData, commRankIds, commArgs, commId, op);
}

class ExtReduceScatterDetour : public torch::autograd::Function<ExtReduceScatterDetour> {
public:
    static at::Tensor forward(AutogradContext *ctx, \
                            const at::Tensor &sendData, \
                            const at::Tensor &commRankIds, \
                            const at::Tensor &commArgs, \
                            const int64_t commId, \
                            const int64_t op)
    {
        at::AutoDispatchBelowADInplaceOrView guard;

        auto result = reduce_scatter_detour_impl(sendData, commRankIds, commArgs, commId, op);
        return result;
    }
    
    static tensor_list backward(AutogradContext *ctx, tensor_list grad_outputs)
    {
        return {at::Tensor(),
                at::Tensor()};
    }
};

at::Tensor reduce_scatter_detour_impl_autograd(
    const at::Tensor &sendData, \
    const at::Tensor &commRankIds, \
    const at::Tensor &commArgs, \
    const int64_t commId, \
    const int64_t op)
{
    auto result = ExtReduceScatterDetour::apply(sendData, commRankIds, commArgs, commId, op);
    return result;
}

TORCH_LIBRARY_IMPL(umdk_cam_op_lib, PrivateUse1, m)
{
    m.impl("reduce_scatter_detour", &reduce_scatter_detour_impl_npu);
    m.impl("reduce_scatter_detour_backward", &reduce_scatter_detour_backward_impl_npu);
}

TORCH_LIBRARY_IMPL(umdk_cam_op_lib, AutogradPrivateUse1, m)
{
    m.impl("reduce_scatter_detour", &reduce_scatter_detour_impl_autograd);
}

TORCH_LIBRARY_IMPL(umdk_cam_op_lib, Meta, m)
{
    m.impl("reduce_scatter_detour", &reduce_scatter_detour_impl_meta);
}


