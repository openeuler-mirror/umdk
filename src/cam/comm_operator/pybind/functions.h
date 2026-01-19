/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2025-2025. All rights reserved.
 * Description: add functions
 * Create: 2025-12-10
 * Note:
 * History: 2025-12-10 add functions
 */

#ifndef COMMON_OPS_CSRC_FUNCTIONS_H_
#define COMMON_OPS_CSRC_FUNCTIONS_H_

#include <ATen/ATen.h>
#include <torch/script.h>
#include <torch/extension.h>
#include <torch/csrc/autograd/custom_function.h>
#include "torch_npu/csrc/core/npu/NPUStream.h"

std::vector<at::Tensor> fused_deep_moe_impl_autograd(
    const at::Tensor &x, \
    const at::Tensor &expertIds, \
    const at::TensorList &gmm1PermutedWeight, \
    const at::TensorList &gmm1PermutedWeightScale, \
    const at::TensorList &gmm2Weight, \
    const at::TensorList &gmm2WeightScale, \
    const c10::optional<at::Tensor> &expertSmoothScalesOptional, \
    const c10::optional<at::Tensor> &expertScalesOptional, \
    c10::string_view groupEp, \
    int64_t epRankSize, \
    int64_t epRankId, \
    int64_t moeExpertNum, \
    int64_t sharedExpertNum, \
    int64_t sharedExpertRankNum, \
    int64_t quantMode, \
    int64_t globalBs);

std::tuple<at::Tensor, at::Tensor, at::Tensor>
moe_dispatch_normal_impl_autograd(
    const at::Tensor &x, \
    const at::Tensor &topkIdx, \
    const at::Tensor &sendOffset, \
    const at::Tensor &sendTokenIdx, \
    const at::Tensor &recvOffset, \
    const at::Tensor &recvCount, \
    c10::string_view groupEp, \
    int64_t epWorldSize, \
    int64_t epRankId, \
    c10::string_view groupTp, \
    int64_t tpWorldSize, \
    int64_t tpRankId, \
    int64_t moeExpertNum, \
    int64_t quantMode, \
    int64_t globalBs);

at::Tensor
moe_combine_normal_impl_autograd(
    const at::Tensor &recvX, \
    const at::Tensor &tokenSrcInfo, \
    const at::Tensor &epRecvCounts, \
    const at::Tensor &recvTopkWeights, \
    const c10::optional<at::Tensor> &tpRecvCounts, \
    c10::string_view epGroupName, \
    int64_t epWorldSize, \
    int64_t epRankId, \
    c10::string_view tpGroupName, \
    int64_t tpWorldSize, \
    int64_t tpRankId, \
    int64_t moeExpertNum, \
    int64_t globalBs);

std::vector<at::Tensor> moe_dispatch_shmem_impl_autograd( \
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
    int64_t extInfo);

at::Tensor moe_combine_shmem_impl_autograd( \
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
    int64_t groupListType);

at::Tensor all2_all_detour_impl_autograd( \
    const at::Tensor &sendData, \
    const at::Tensor &commArgs1, \
    const at::Tensor &commRankIds, \
    const int64_t commId);

at::Tensor reduce_scatter_detour_impl_autograd( \
    const at::Tensor &sendData, \
    const at::Tensor &commArgs1, \
    const at::Tensor &commRankIds, \
    const int64_t commId, \
    const int64_t op);
#endif // COMMON_OPS_CSRC_FUNCTIONS_H_