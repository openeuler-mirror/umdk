/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2025-2025. All rights reserved.
 * Description: add all2all detour file
 * Create: 2026-01-22
 * Note:
 * History: 2026-01-22 all2all detour file
 */

#include <unistd.h>
#include <hccl/hccl.h>
#include <torch/extension.h>
#include <torch/csrc/autograd/custom_function.h>
#include "torch_npu/csrc/core/npu/NPUStream.h"
#include "pytorch_npu_helper.hpp"
#include <iostream>
#include "cam_api.h"
#include "cam_comm.h"
#include "ext_utils.h"

using torch::autograd::AutogradContext;
using torch::autograd::Function;
using tensor_list = std::vector<at::Tensor>;
using namespace at;
using namespace std;

constexpr int KERNEL_PARAM_CNT = 3;

at::Tensor all2_all_detour_impl_npu(
    const at::Tensor &sendData, \
    const at::Tensor &commRankIds, \
    const at::Tensor &commArgs, \
    const int64_t commId)
{
    auto shape = sendData.sizes();
    at::IntArrayRef modified_shape(shape.data(), shape.size());
    at::Tensor recvData = at::empty(modified_shape, sendData.options());
    uint32_t magic = cam_get_and_increase_magic(commId);
    EXEC_NPU_CMD(aclnnAll2AllDetour,
                    sendData, commRankIds, commArgs, \
                    magic, recvData);
    return recvData;
}

std::tuple<at::Tensor, at::Tensor> all2_all_detour_backward_impl_npu(const at::Tensor &self)
{
    at::Tensor result = at::Tensor(self);
    return {result, result};
}

at::Tensor all2_all_detour_impl_meta(
    const at::Tensor &sendData, \
    const at::Tensor &commRankIds, \
    const at::Tensor &commArgs, \
    const int64_t commId)
{
    auto shape = sendData.sizes();
    std::vector<int64_t> recv_data_shape(shape.size());
    for (int i = 0; i < shape.size(); i++) {
        recv_data_shape[i] = shape[i];
    }
    at::IntArrayRef modified_shape(recv_data_shape.data(), recv_data_shape.size());
    at::Tensor recvData = at::empty(modified_shape, sendData.options());
    return recvData;
}

at::Tensor all2_all_detour_impl(
    const at::Tensor &sendData, \
    const at::Tensor &commRankIds, \
    const at::Tensor &commArgs, \
    const int64_t commId)
{
    static auto op = torch::Dispatcher::singleton()
                        .findSchemaOrThrow("umdk_cam_op_lib::all2_all_detour", "")
                        .typed<decltype(all2_all_detour_impl)>();
    return op.call(sendData, commRankIds, commArgs, commId);
}

class ExtAll2AllDetour : public torch::autograd::Function<ExtAll2AllDetour> {
public:
    static at::Tensor forward(AutogradContext *ctx, \
                            const at::Tensor &sendData, \
                            const at::Tensor &commRankIds, \
                            const at::Tensor &commArgs, \
                            const int64_t commId)
    {
        at::AutoDispatchBelowADInplaceOrView guard;

        auto result = all2_all_detour_impl(sendData, commRankIds, commArgs, commId);
        return result;
    }
    
    static tensor_list backward(AutogradContext *ctx, tensor_list grad_outputs)
    {
        return {at::Tensor(),
                at::Tensor(),
                at::Tensor(),
                at::Tensor()};
    }
};

at::Tensor all2_all_detour_impl_autograd(
    const at::Tensor &sendData, \
    const at::Tensor &commRankIds, \
    const at::Tensor &commArgs, \
    const int64_t commId)
{
    auto result = ExtAll2AllDetour::apply(sendData, commRankIds, commArgs, commId);
    return result;
}

TORCH_LIBRARY_IMPL(umdk_cam_op_lib, PrivateUse1, m)
{
    m.impl("all2_all_detour", &all2_all_detour_impl_npu);
    m.impl("all2_all_detour_backward", &all2_all_detour_backward_impl_npu);
}

TORCH_LIBRARY_IMPL(umdk_cam_op_lib, AutogradPrivateUse1, m)
{
    m.impl("all2_all_detour", &all2_all_detour_impl_autograd);
}

TORCH_LIBRARY_IMPL(umdk_cam_op_lib, Meta, m)
{
    m.impl("all2_all_detour", &all2_all_detour_impl_meta);
}


