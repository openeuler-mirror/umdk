/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2026-2026. All rights reserved.
 * Description: cam_deepep_combine_recv pybind extension file.
 * Create: 2026-11-03
 * Note: combined_x / combined_topk_idx / topk_weights / recv_status /
 *       return_progress are caller-owned so the scheduler and the accuracy
 *       checker can hold the same storage across rounds.
 * History: 2026-11-03 create
 */

#include <unistd.h>
#include <torch/extension.h>
#include <torch/csrc/autograd/custom_function.h>
#include "torch_npu/csrc/core/npu/NPUStream.h"
#include "pytorch_npu_helper.hpp"

using torch::autograd::AutogradContext;
using torch::autograd::Function;
using tensor_list = std::vector<at::Tensor>;
using namespace at;
using namespace std;

namespace {
// Five caller-owned buffers are written in place and returned as a fixed-size
// aliased tuple, so the Meta kernel validates and then hands back the inputs.
using CombineRecvOut = std::tuple<at::Tensor, at::Tensor, at::Tensor, at::Tensor, at::Tensor>;

// Attribute domain mirrored from TilingFunc.
constexpr int64_t kMaxNumExperts = 2048;
constexpr int64_t kMaxNumRanks = 256;
constexpr int64_t kMaxNumTopk = 32;
constexpr int64_t kMaxNumHidden = 8192;
constexpr int64_t kHiddenAlignment = 128;
constexpr int64_t kMaxTokenCapacity = 32768;
constexpr int64_t kMaxRecvStatusWords = 4096;
constexpr int64_t kMaxReturnProgressBytes = 65536;
constexpr int64_t kTiledRank = 2;

// One gradient slot per forward argument, and the fixed output positions.
constexpr size_t kForwardArgCount = 24;
constexpr size_t kOutCombinedX = 0;
constexpr size_t kOutTopkIdx = 1;
constexpr size_t kOutTopkWeights = 2;
constexpr size_t kOutRecvStatus = 3;
constexpr size_t kOutReturnProgress = 4;

void CheckDtype(const at::Tensor &t, at::ScalarType want, const char *name)
{
    TORCH_CHECK(t.scalar_type() == want, "cam_deepep_combine_recv: ", name,
        " must have dtype ", want, ", got ", t.scalar_type());
}

void CheckDim(const at::Tensor &t, int64_t dim, const char *name)
{
    TORCH_CHECK(t.dim() == dim, "cam_deepep_combine_recv: ", name, " must be ",
        dim, "-D, got ", t.dim(), "-D");
}

void CheckByteBlob(const at::Tensor &t, const char *name)
{
    CheckDtype(t, at::kByte, name);
    CheckDim(t, 1, name);
}
}  // namespace

CombineRecvOut CamDeepepCombineRecvImplNpu(
    const at::Tensor &payload,
    const at::Tensor &taskInfo,
    const at::Tensor &context,
    const at::Tensor &controlBuffer,
    const at::Tensor &roundLedger,
    const at::Tensor &afdWorkspace,
    const at::Tensor &tokenMask,
    at::Tensor &combinedX,
    at::Tensor &combinedTopkIdx,
    at::Tensor &topkWeights,
    at::Tensor &recvStatus,
    at::Tensor &returnProgress,
    c10::string_view groupEp,
    const int64_t numExperts,
    const int64_t numRanks,
    const int64_t numTopk,
    const int64_t roundStep,
    const int64_t start,
    const int64_t numHidden,
    const int64_t numTokenCapacity,
    const int64_t recvStatusWords,
    const int64_t returnProgressBytes,
    const int64_t timeoutCycles,
    const int64_t numVecCores)
{
    vector<char> groupEpChars(groupEp.begin(), groupEp.end());
    groupEpChars.push_back('\0');
    char *groupEpPtr = &groupEpChars[0];

    EXEC_NPU_CMD(aclnnCamDeepepCombineRecv,
        // input
        payload, taskInfo, context, controlBuffer, roundLedger, afdWorkspace,
        tokenMask,
        // attr
        groupEpPtr, numExperts, numRanks, numTopk, roundStep, start, numHidden,
        numTokenCapacity, recvStatusWords, returnProgressBytes, timeoutCycles, numVecCores,
        // output
        combinedX, combinedTopkIdx, topkWeights, recvStatus, returnProgress);
    return std::make_tuple(combinedX, combinedTopkIdx, topkWeights, recvStatus, returnProgress);
}

CombineRecvOut CamDeepepCombineRecvImplMeta(
    const at::Tensor &payload,
    const at::Tensor &taskInfo,
    const at::Tensor &context,
    const at::Tensor &controlBuffer,
    const at::Tensor &roundLedger,
    const at::Tensor &afdWorkspace,
    const at::Tensor &tokenMask,
    at::Tensor &combinedX,
    at::Tensor &combinedTopkIdx,
    at::Tensor &topkWeights,
    at::Tensor &recvStatus,
    at::Tensor &returnProgress,
    c10::string_view groupEp,
    const int64_t numExperts,
    const int64_t numRanks,
    const int64_t numTopk,
    const int64_t roundStep,
    const int64_t start,
    const int64_t numHidden,
    const int64_t numTokenCapacity,
    const int64_t recvStatusWords,
    const int64_t returnProgressBytes,
    const int64_t timeoutCycles,
    const int64_t numVecCores)
{
    // Attribute domain mirrors TilingFunc so an out-of-domain call fails here,
    // before any kernel launch, on every dispatch key.
    TORCH_CHECK(numExperts > 0 && numExperts <= kMaxNumExperts,
        "combine_recv: num_experts out of range: ", numExperts);
    TORCH_CHECK(numRanks > 0 && numRanks <= kMaxNumRanks,
        "combine_recv: num_ranks out of range: ", numRanks);
    TORCH_CHECK(numTopk > 0 && numTopk <= kMaxNumTopk,
        "combine_recv: num_topk out of range: ", numTopk);
    TORCH_CHECK(roundStep == 0 || roundStep == 1, "combine_recv: round_step must be 0 or 1");
    TORCH_CHECK(start == 0 || start == 1, "combine_recv: start must be 0 or 1");
    TORCH_CHECK(numHidden > 0 && numHidden <= kMaxNumHidden,
        "combine_recv: num_hidden out of range: ", numHidden);
    TORCH_CHECK(numHidden % kHiddenAlignment == 0,
        "combine_recv: num_hidden must be a multiple of 128");
    TORCH_CHECK(numTokenCapacity > 0 && numTokenCapacity <= kMaxTokenCapacity,
        "combine_recv: num_token_capacity out of range: ", numTokenCapacity);
    TORCH_CHECK(recvStatusWords > 0 && recvStatusWords <= kMaxRecvStatusWords,
        "combine_recv: recv_status_words out of range: ", recvStatusWords);
    TORCH_CHECK(returnProgressBytes >= 0 && returnProgressBytes <= kMaxReturnProgressBytes,
        "combine_recv: return_progress_bytes out of range: ", returnProgressBytes);
    TORCH_CHECK(timeoutCycles > 0, "combine_recv: timeout_cycles must be positive");
    TORCH_CHECK(numVecCores >= 0, "combine_recv: num_vec_cores must be nonnegative");

    // AFD control plane: opaque byte blobs owned by the caller.
    CheckByteBlob(payload, "payload");
    CheckByteBlob(taskInfo, "task_info");
    CheckByteBlob(context, "context");
    CheckByteBlob(controlBuffer, "control_buffer");
    CheckByteBlob(roundLedger, "round_ledger");
    CheckByteBlob(afdWorkspace, "afd_workspace");
    CheckDtype(tokenMask, at::kBool, "token_mask");
    CheckDim(tokenMask, 1, "token_mask");
    TORCH_CHECK(tokenMask.size(0) == numTokenCapacity,
        "combine_recv: token_mask must be [num_token_capacity]");

    // Outputs are preallocated by the caller; their shape follows the attrs.
    CheckDtype(combinedX, at::kBFloat16, "combined_x");
    CheckDim(combinedX, kTiledRank, "combined_x");
    TORCH_CHECK(combinedX.size(0) == numTokenCapacity && combinedX.size(1) == numHidden,
        "combine_recv: combined_x must be [num_token_capacity, num_hidden]");
    CheckDtype(combinedTopkIdx, at::kLong, "combined_topk_idx");
    CheckDim(combinedTopkIdx, kTiledRank, "combined_topk_idx");
    TORCH_CHECK(combinedTopkIdx.size(0) == numTokenCapacity && combinedTopkIdx.size(1) == numTopk,
        "combine_recv: combined_topk_idx must be [num_token_capacity, num_topk]");
    CheckDtype(topkWeights, at::kFloat, "topk_weights");
    CheckDim(topkWeights, kTiledRank, "topk_weights");
    TORCH_CHECK(topkWeights.size(0) == numTokenCapacity && topkWeights.size(1) == numTopk,
        "combine_recv: topk_weights must be [num_token_capacity, num_topk]");
    CheckDtype(recvStatus, at::kInt, "recv_status");
    CheckDim(recvStatus, 1, "recv_status");
    TORCH_CHECK(recvStatus.size(0) == recvStatusWords,
        "combine_recv: recv_status must be [recv_status_words]");
    CheckDtype(returnProgress, at::kByte, "return_progress");
    CheckDim(returnProgress, 1, "return_progress");
    TORCH_CHECK(returnProgress.numel() == returnProgressBytes,
        "combine_recv: return_progress must carry return_progress_bytes bytes");

    // The kernel writes all five buffers in place; the tuple aliases the inputs.
    return std::make_tuple(combinedX, combinedTopkIdx, topkWeights, recvStatus, returnProgress);
}

CombineRecvOut CamDeepepCombineRecvImpl(
    const at::Tensor &payload,
    const at::Tensor &taskInfo,
    const at::Tensor &context,
    const at::Tensor &controlBuffer,
    const at::Tensor &roundLedger,
    const at::Tensor &afdWorkspace,
    const at::Tensor &tokenMask,
    at::Tensor &combinedX,
    at::Tensor &combinedTopkIdx,
    at::Tensor &topkWeights,
    at::Tensor &recvStatus,
    at::Tensor &returnProgress,
    c10::string_view groupEp,
    const int64_t numExperts,
    const int64_t numRanks,
    const int64_t numTopk,
    const int64_t roundStep,
    const int64_t start,
    const int64_t numHidden,
    const int64_t numTokenCapacity,
    const int64_t recvStatusWords,
    const int64_t returnProgressBytes,
    const int64_t timeoutCycles,
    const int64_t numVecCores)
{
    static auto op = torch::Dispatcher::singleton()
                         .findSchemaOrThrow("umdk_cam_op_lib::cam_deepep_combine_recv", "")
                         .typed<decltype(CamDeepepCombineRecvImpl)>();
    return op.call(payload, taskInfo, context, controlBuffer, roundLedger,
        afdWorkspace, tokenMask, combinedX, combinedTopkIdx, topkWeights,
        recvStatus, returnProgress, groupEp, numExperts, numRanks, numTopk,
        roundStep, start, numHidden, numTokenCapacity, recvStatusWords,
        returnProgressBytes, timeoutCycles, numVecCores);
}

class ExtCamDeepepCombineRecv : public torch::autograd::Function<ExtCamDeepepCombineRecv> {
public:
    // torch::autograd::Function::apply only accepts a Tensor or a tensor_list
    // as the forward result (to_optional has no tuple overload), so the fixed
    // five-output contract is carried as a list here and re-packed below.
    static tensor_list forward(
        AutogradContext *ctx,
        const at::Tensor &payload,
        const at::Tensor &taskInfo,
        const at::Tensor &context,
        const at::Tensor &controlBuffer,
        const at::Tensor &roundLedger,
        const at::Tensor &afdWorkspace,
        const at::Tensor &tokenMask,
        at::Tensor &combinedX,
        at::Tensor &combinedTopkIdx,
        at::Tensor &topkWeights,
        at::Tensor &recvStatus,
        at::Tensor &returnProgress,
        c10::string_view groupEp,
        const int64_t numExperts,
        const int64_t numRanks,
        const int64_t numTopk,
        const int64_t roundStep,
        const int64_t start,
        const int64_t numHidden,
        const int64_t numTokenCapacity,
        const int64_t recvStatusWords,
        const int64_t returnProgressBytes,
        const int64_t timeoutCycles,
        const int64_t numVecCores)
    {
        at::AutoDispatchBelowADInplaceOrView guard;
        const auto outs = CamDeepepCombineRecvImpl(payload, taskInfo, context,
            controlBuffer, roundLedger, afdWorkspace, tokenMask, combinedX,
            combinedTopkIdx, topkWeights, recvStatus, returnProgress, groupEp,
            numExperts, numRanks, numTopk, roundStep, start, numHidden,
            numTokenCapacity, recvStatusWords, returnProgressBytes, timeoutCycles,
            numVecCores);
        return tensor_list{std::get<0>(outs), std::get<1>(outs), std::get<2>(outs),
            std::get<3>(outs), std::get<4>(outs)};
    }

    static tensor_list backward(AutogradContext *ctx, tensor_list gradOutputs)
    {
        // Communication operators are not differentiable; one empty gradient per
        // forward argument keeps the autograd contract well-formed.
        return tensor_list(kForwardArgCount);
    }
};

CombineRecvOut CamDeepepCombineRecvImplAutograd(
    const at::Tensor &payload,
    const at::Tensor &taskInfo,
    const at::Tensor &context,
    const at::Tensor &controlBuffer,
    const at::Tensor &roundLedger,
    const at::Tensor &afdWorkspace,
    const at::Tensor &tokenMask,
    at::Tensor &combinedX,
    at::Tensor &combinedTopkIdx,
    at::Tensor &topkWeights,
    at::Tensor &recvStatus,
    at::Tensor &returnProgress,
    c10::string_view groupEp,
    const int64_t numExperts,
    const int64_t numRanks,
    const int64_t numTopk,
    const int64_t roundStep,
    const int64_t start,
    const int64_t numHidden,
    const int64_t numTokenCapacity,
    const int64_t recvStatusWords,
    const int64_t returnProgressBytes,
    const int64_t timeoutCycles,
    const int64_t numVecCores)
{
    const auto outs = ExtCamDeepepCombineRecv::apply(payload, taskInfo, context,
        controlBuffer, roundLedger, afdWorkspace, tokenMask, combinedX,
        combinedTopkIdx, topkWeights, recvStatus, returnProgress, groupEp,
        numExperts, numRanks, numTopk, roundStep, start, numHidden,
        numTokenCapacity, recvStatusWords, returnProgressBytes, timeoutCycles,
        numVecCores);
    return std::make_tuple(outs[kOutCombinedX], outs[kOutTopkIdx], outs[kOutTopkWeights],
        outs[kOutRecvStatus], outs[kOutReturnProgress]);
}

TORCH_LIBRARY_IMPL(umdk_cam_op_lib, PrivateUse1, m)
{
    m.impl("cam_deepep_combine_recv", &CamDeepepCombineRecvImplNpu);
}

TORCH_LIBRARY_IMPL(umdk_cam_op_lib, AutogradPrivateUse1, m)
{
    m.impl("cam_deepep_combine_recv", &CamDeepepCombineRecvImplAutograd);
}

TORCH_LIBRARY_IMPL(umdk_cam_op_lib, Meta, m)
{
    m.impl("cam_deepep_combine_recv", &CamDeepepCombineRecvImplMeta);
}
