/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2025-2025. All rights reserved.
 * Description: pybind functions header file
 * Create: 2025-12-10
 * Note:
 * History: 2025-12-10 add pybind functions header file
 */

#ifndef COMMON_OPS_CSRC_FUNCTIONS_H_
#define COMMON_OPS_CSRC_FUNCTIONS_H_

#include "torch_npu/csrc/core/npu/NPUStream.h"
#include <ATen/ATen.h>
#include <torch/csrc/autograd/custom_function.h>
#include <torch/extension.h>
#include <torch/script.h>

std::vector<at::Tensor> FusedDeepMoeImplAutograd(
    const at::Tensor &x, \
    const at::Tensor &expertIds, \
    const at::TensorList &gmm1Weight, \
    const at::TensorList &gmm1WeightScale, \
    const at::TensorList &gmm2Weight, \
    const at::TensorList &gmm2WeightScale, \
    const at::Tensor &expertScales, \
    const c10::optional<at::Tensor> &shareGmm1WeightOptional, \
    const c10::optional<at::Tensor> &shareGmm1WeightScaleOptional, \
    const c10::optional<at::Tensor> &shareGmm2WeightOptional, \
    const c10::optional<at::Tensor> &shareGmm2WeightScaleOptional, \
    const c10::optional<at::Tensor> &expertSmoothScales, \
    const c10::optional<at::Tensor> &shareSmoothScales, \
    const c10::optional<at::Tensor> &xActiveMask, \
    c10::string_view groupEp, \
    int64_t epRankSize, \
    int64_t epRankId, \
    int64_t moeExpertNum, \
    int64_t quantMode, \
    int64_t globalBs);

std::tuple<at::Tensor, at::Tensor> GetDispatchLayoutImplAutograd(
    const at::Tensor &topIdx,
    int64_t numExperts,
    int64_t numRanks);

std::tuple<at::Tensor, at::Tensor, at::Tensor, at::Tensor, at::Tensor>MoeDispatchPrefillImplAutograd(
    const at::Tensor &x,
    const at::Tensor &topkIdx,
    const at::Tensor &topkWeights,
    const at::Tensor &numTokensPerExpert,
    const at::Tensor &sendTokenIdxSmall,
    c10::string_view groupEp,
    int64_t rank,
    int64_t numRanks,
    bool useQuant);

at::Tensor MoeCombinePrefillImplAutograd(
    const at::Tensor &x,
    const at::Tensor &topkIdx,
    const at::Tensor &topkWeights,
    const at::Tensor &srcIdx,
    const at::Tensor &sendHead,
    c10::string_view groupEp,
    int64_t rank,
    int64_t numRanks);

std::tuple<at::Tensor, at::Tensor> GetDispatchLayoutZbImplAutograd(const at::Tensor &topkIdx, int64_t numExperts,
    int64_t numRanks);

// Fused notify + dispatch (aligned with moe_dispatch_prefill).
// Returns: recv_x, scales, put_offset, total_recv_tokens, recv_tokens_per_expert
std::tuple<at::Tensor, at::Tensor, at::Tensor, at::Tensor, at::Tensor> MoeDispatchPrefillZbImplAutograd(
    const at::Tensor &x, const at::Tensor &topkIdx, const at::Tensor &sendTokenIdx,
    const at::Tensor &numTokensPerExpert, int64_t epWorldSize, int64_t epRankId, int64_t moeExpertNum,
    int64_t quantMode, int64_t globalBs, int64_t commMetaPtr);

at::Tensor MoeCombinePrefillZbImplAutograd(const at::Tensor &recvX, const at::Tensor &epRecvCounts,
    const at::Tensor &recvTopkWeights, const at::Tensor &topkIdx, const c10::optional<at::Tensor> &sendTokenIdx,
    int64_t commMetaPtr, int64_t epWorldSize, int64_t epRankId, int64_t tpWorldSize, int64_t tpRankId,
    int64_t moeExpertNum, int64_t globalBs);

#endif // COMMON_OPS_CSRC_FUNCTIONS_H_
