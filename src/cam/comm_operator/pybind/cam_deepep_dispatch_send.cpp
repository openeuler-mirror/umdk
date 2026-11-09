/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2026-2026. All rights reserved.
 * Description: cam_deepep_dispatch_send pybind extension file.
 * Create: 2026-11-03
 * Note: AFD control-plane buffers are caller-owned tensors; the output status
 *       buffer is passed in and returned so the scheduler can hold the same
 *       storage across rounds.
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
// Strides are stored in the tiling record as int32, so the domain is capped
// there as well: an int64 value past INT32_MAX would wrap after validation.
constexpr int64_t kMaxStride = 2147483647;

// Attribute domain mirrored from TilingFunc.
constexpr int64_t kMaxNumRanks = 256;
constexpr int64_t kMaxNumExperts = 2048;
constexpr int64_t kMaxNumTopk = 32;
constexpr int64_t kMaxTokensPerTile = 32768;
constexpr int64_t kMaxNumSFPacks = 2048;
constexpr int64_t kMaxSendStatusWords = 4096;
constexpr int64_t kMaxNumHidden = 8192;
constexpr int64_t kTiledRank = 2;

// One gradient slot per forward argument.
constexpr size_t kForwardArgCount = 23;

// The Meta kernel must reject the same dtype/shape/attr domain the OpDef and
// TilingFunc declare instead of echoing the caller's buffer, and it must
// return that buffer itself because the schema marks it mutable.
void CheckDtype(const at::Tensor &t, at::ScalarType want, const char *name)
{
    TORCH_CHECK(t.scalar_type() == want, "cam_deepep_dispatch_send: ", name,
        " must have dtype ", want, ", got ", t.scalar_type());
}

void CheckDim(const at::Tensor &t, int64_t dim, const char *name)
{
    TORCH_CHECK(t.dim() == dim, "cam_deepep_dispatch_send: ", name, " must be ",
        dim, "-D, got ", t.dim(), "-D");
}

void CheckByteBlob(const at::Tensor &t, const char *name)
{
    CheckDtype(t, at::kByte, name);
    CheckDim(t, 1, name);
}
}  // namespace

at::Tensor CamDeepepDispatchSendImplNpu(
    const at::Tensor &x,
    const at::Tensor &sf,
    const at::Tensor &topkIdx,
    const at::Tensor &topkWeights,
    const at::Tensor &tokenMask,
    const at::Tensor &taskInfo,
    const at::Tensor &context,
    const at::Tensor &controlBuffer,
    const at::Tensor &roundLedger,
    const at::Tensor &afdWorkspace,
    const at::Tensor &jettyPtrs,
    at::Tensor &sendStatus,
    c10::string_view groupEp,
    const int64_t numRanks,
    const int64_t numExperts,
    const int64_t numTopk,
    const int64_t numTokensPerTile,
    const int64_t sfTokenStride,
    const int64_t sfHiddenStride,
    const int64_t numSfPacks,
    const int64_t timeoutCycles,
    const int64_t sendStatusWords,
    const int64_t numVecCores)
{
    vector<char> groupEpChars(groupEp.begin(), groupEp.end());
    groupEpChars.push_back('\0');
    char *groupEpPtr = &groupEpChars[0];

    EXEC_NPU_CMD(aclnnCamDeepepDispatchSend,
        // input
        x, sf, topkIdx, topkWeights, tokenMask, taskInfo, context, controlBuffer,
        roundLedger, afdWorkspace, jettyPtrs,
        // attr
        groupEpPtr, numRanks, numExperts, numTopk, numTokensPerTile, sfTokenStride,
        sfHiddenStride, numSfPacks, timeoutCycles, sendStatusWords, numVecCores,
        // output
        sendStatus);
    return sendStatus;
}

at::Tensor CamDeepepDispatchSendImplMeta(
    const at::Tensor &x,
    const at::Tensor &sf,
    const at::Tensor &topkIdx,
    const at::Tensor &topkWeights,
    const at::Tensor &tokenMask,
    const at::Tensor &taskInfo,
    const at::Tensor &context,
    const at::Tensor &controlBuffer,
    const at::Tensor &roundLedger,
    const at::Tensor &afdWorkspace,
    const at::Tensor &jettyPtrs,
    at::Tensor &sendStatus,
    c10::string_view groupEp,
    const int64_t numRanks,
    const int64_t numExperts,
    const int64_t numTopk,
    const int64_t numTokensPerTile,
    const int64_t sfTokenStride,
    const int64_t sfHiddenStride,
    const int64_t numSfPacks,
    const int64_t timeoutCycles,
    const int64_t sendStatusWords,
    const int64_t numVecCores)
{
    // Attribute domain mirrors TilingFunc: an out-of-domain call fails here,
    // before any kernel launch, on every dispatch key.
    TORCH_CHECK(numRanks > 0 && numRanks <= kMaxNumRanks,
        "dispatch_send: num_ranks out of range: ", numRanks);
    TORCH_CHECK(numExperts > 0 && numExperts <= kMaxNumExperts,
        "dispatch_send: num_experts out of range: ", numExperts);
    TORCH_CHECK(numExperts % numRanks == 0,
        "dispatch_send: num_experts must divide by num_ranks");
    TORCH_CHECK(numTopk > 0 && numTopk <= kMaxNumTopk,
        "dispatch_send: num_topk out of range: ", numTopk);
    TORCH_CHECK(numTokensPerTile > 0 && numTokensPerTile <= kMaxTokensPerTile,
        "dispatch_send: num_tokens_per_tile out of range: ", numTokensPerTile);
    TORCH_CHECK(sfTokenStride >= 0 && sfTokenStride <= kMaxStride &&
        sfHiddenStride >= 0 && sfHiddenStride <= kMaxStride,
        "dispatch_send: sf strides must be nonnegative");
    TORCH_CHECK(numSfPacks >= 0 && numSfPacks <= kMaxNumSFPacks,
        "dispatch_send: num_sf_packs out of range: ", numSfPacks);
    TORCH_CHECK(timeoutCycles > 0, "dispatch_send: timeout_cycles must be positive");
    TORCH_CHECK(sendStatusWords > 0 && sendStatusWords <= kMaxSendStatusWords,
        "dispatch_send: send_status_words out of range: ", sendStatusWords);
    TORCH_CHECK(numVecCores >= 0, "dispatch_send: num_vec_cores must be nonnegative");

    CheckDtype(x, at::kBFloat16, "x");
    TORCH_CHECK(x.dim() >= 1, "dispatch_send: x must have at least one dimension");
    const int64_t numHidden = x.size(-1);
    TORCH_CHECK(numHidden > 0 && numHidden <= kMaxNumHidden,
        "dispatch_send: hidden out of range: ", numHidden);
    const int64_t tokens = x.numel() / numHidden;

    // Scale factors are a dummy tensor while num_sf_packs is zero, so only the
    // packed layout is checked when the call actually carries them.
    CheckDtype(sf, at::kShort, "sf");
    if (numSfPacks > 0) {
        CheckDim(sf, kTiledRank, "sf");
        TORCH_CHECK(sf.size(0) == tokens && sf.size(1) == numSfPacks,
            "dispatch_send: sf must be [tokens, num_sf_packs] when num_sf_packs > 0");
    }

    CheckDtype(topkIdx, at::kLong, "topk_idx");
    CheckDim(topkIdx, kTiledRank, "topk_idx");
    TORCH_CHECK(topkIdx.size(0) == tokens && topkIdx.size(1) == numTopk,
        "dispatch_send: topk_idx must be [tokens, num_topk]");
    CheckDtype(topkWeights, at::kFloat, "topk_weights");
    CheckDim(topkWeights, kTiledRank, "topk_weights");
    TORCH_CHECK(topkWeights.size(0) == tokens && topkWeights.size(1) == numTopk,
        "dispatch_send: topk_weights must be [tokens, num_topk]");
    CheckDtype(tokenMask, at::kBool, "token_mask");
    CheckDim(tokenMask, 1, "token_mask");
    TORCH_CHECK(tokenMask.size(0) == tokens, "dispatch_send: token_mask must be [tokens]");

    // AFD control plane: opaque byte blobs owned by the caller.
    CheckByteBlob(taskInfo, "task_info");
    CheckByteBlob(context, "context");
    CheckByteBlob(controlBuffer, "control_buffer");
    CheckByteBlob(roundLedger, "round_ledger");
    CheckByteBlob(afdWorkspace, "afd_workspace");
    CheckDtype(jettyPtrs, at::kLong, "jetty_ptrs");
    CheckDim(jettyPtrs, 1, "jetty_ptrs");

    CheckDtype(sendStatus, at::kInt, "send_status");
    CheckDim(sendStatus, 1, "send_status");
    TORCH_CHECK(sendStatus.size(0) == sendStatusWords,
        "dispatch_send: send_status must be [send_status_words]");

    // The kernel fills the caller's status buffer in place and the schema marks
    // it mutable, so the returned tensor is that same storage.
    return sendStatus;
}

at::Tensor CamDeepepDispatchSendImpl(
    const at::Tensor &x,
    const at::Tensor &sf,
    const at::Tensor &topkIdx,
    const at::Tensor &topkWeights,
    const at::Tensor &tokenMask,
    const at::Tensor &taskInfo,
    const at::Tensor &context,
    const at::Tensor &controlBuffer,
    const at::Tensor &roundLedger,
    const at::Tensor &afdWorkspace,
    const at::Tensor &jettyPtrs,
    at::Tensor &sendStatus,
    c10::string_view groupEp,
    const int64_t numRanks,
    const int64_t numExperts,
    const int64_t numTopk,
    const int64_t numTokensPerTile,
    const int64_t sfTokenStride,
    const int64_t sfHiddenStride,
    const int64_t numSfPacks,
    const int64_t timeoutCycles,
    const int64_t sendStatusWords,
    const int64_t numVecCores)
{
    static auto op = torch::Dispatcher::singleton()
                         .findSchemaOrThrow("umdk_cam_op_lib::cam_deepep_dispatch_send", "")
                         .typed<decltype(CamDeepepDispatchSendImpl)>();
    return op.call(x, sf, topkIdx, topkWeights, tokenMask, taskInfo, context,
        controlBuffer, roundLedger, afdWorkspace, jettyPtrs, sendStatus, groupEp,
        numRanks, numExperts, numTopk, numTokensPerTile, sfTokenStride,
        sfHiddenStride, numSfPacks, timeoutCycles, sendStatusWords, numVecCores);
}

class ExtCamDeepepDispatchSend : public torch::autograd::Function<ExtCamDeepepDispatchSend> {
public:
    static at::Tensor forward(
        AutogradContext *ctx,
        const at::Tensor &x,
        const at::Tensor &sf,
        const at::Tensor &topkIdx,
        const at::Tensor &topkWeights,
        const at::Tensor &tokenMask,
        const at::Tensor &taskInfo,
        const at::Tensor &context,
        const at::Tensor &controlBuffer,
        const at::Tensor &roundLedger,
        const at::Tensor &afdWorkspace,
        const at::Tensor &jettyPtrs,
        at::Tensor &sendStatus,
        c10::string_view groupEp,
        const int64_t numRanks,
        const int64_t numExperts,
        const int64_t numTopk,
        const int64_t numTokensPerTile,
        const int64_t sfTokenStride,
        const int64_t sfHiddenStride,
        const int64_t numSfPacks,
        const int64_t timeoutCycles,
        const int64_t sendStatusWords,
        const int64_t numVecCores)
    {
        at::AutoDispatchBelowADInplaceOrView guard;
        return CamDeepepDispatchSendImpl(x, sf, topkIdx, topkWeights, tokenMask,
            taskInfo, context, controlBuffer, roundLedger, afdWorkspace, jettyPtrs,
            sendStatus, groupEp, numRanks, numExperts, numTopk, numTokensPerTile,
            sfTokenStride, sfHiddenStride, numSfPacks, timeoutCycles, sendStatusWords,
            numVecCores);
    }

    static tensor_list backward(AutogradContext *ctx, tensor_list gradOutputs)
    {
        // Communication operators are not differentiable; one empty gradient per
        // forward argument keeps the autograd contract well-formed.
        return tensor_list(kForwardArgCount);
    }
};

at::Tensor CamDeepepDispatchSendImplAutograd(
    const at::Tensor &x,
    const at::Tensor &sf,
    const at::Tensor &topkIdx,
    const at::Tensor &topkWeights,
    const at::Tensor &tokenMask,
    const at::Tensor &taskInfo,
    const at::Tensor &context,
    const at::Tensor &controlBuffer,
    const at::Tensor &roundLedger,
    const at::Tensor &afdWorkspace,
    const at::Tensor &jettyPtrs,
    at::Tensor &sendStatus,
    c10::string_view groupEp,
    const int64_t numRanks,
    const int64_t numExperts,
    const int64_t numTopk,
    const int64_t numTokensPerTile,
    const int64_t sfTokenStride,
    const int64_t sfHiddenStride,
    const int64_t numSfPacks,
    const int64_t timeoutCycles,
    const int64_t sendStatusWords,
    const int64_t numVecCores)
{
    return ExtCamDeepepDispatchSend::apply(x, sf, topkIdx, topkWeights, tokenMask,
        taskInfo, context, controlBuffer, roundLedger, afdWorkspace, jettyPtrs,
        sendStatus, groupEp, numRanks, numExperts, numTopk, numTokensPerTile,
        sfTokenStride, sfHiddenStride, numSfPacks, timeoutCycles, sendStatusWords,
        numVecCores);
}

TORCH_LIBRARY_IMPL(umdk_cam_op_lib, PrivateUse1, m)
{
    m.impl("cam_deepep_dispatch_send", &CamDeepepDispatchSendImplNpu);
}

TORCH_LIBRARY_IMPL(umdk_cam_op_lib, AutogradPrivateUse1, m)
{
    m.impl("cam_deepep_dispatch_send", &CamDeepepDispatchSendImplAutograd);
}

TORCH_LIBRARY_IMPL(umdk_cam_op_lib, Meta, m)
{
    m.impl("cam_deepep_dispatch_send", &CamDeepepDispatchSendImplMeta);
}
