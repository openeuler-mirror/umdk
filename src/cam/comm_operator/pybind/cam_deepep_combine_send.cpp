/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2026-2026. All rights reserved.
 * Description: cam_deepep_combine_send pybind extension file.
 * Create: 2026-11-03
 * Note: the completion buffer is scheduler-owned, so it is passed in and
 *       returned instead of being allocated per call.
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
// Attribute domain mirrored from TilingFunc.
constexpr int64_t kMaxNumSrcRanks = 256;
constexpr int64_t kMaxNumRanks = 256;
constexpr int64_t kMaxNumExperts = 2048;
constexpr int64_t kMaxExpertsPerRank = 512;
constexpr int64_t kMaxNumTopk = 32;
constexpr int64_t kMaxNumSourceLanes = 256;
constexpr int64_t kMaxNumLayers = 64;
constexpr int64_t kMaxPaddedTokens = 32768;
constexpr int64_t kMaxTokensPerTile = 128;
constexpr int64_t kMaxCompletionBytes = 65536;
constexpr int64_t kMaxNumHidden = 8192;
constexpr int64_t kMetadataWords = 4;
constexpr int64_t kTiledRank = 2;
// One gradient slot per forward argument.
constexpr size_t kForwardArgCount = 22;

// The Meta kernel must reject the same dtype/shape/attr domain the OpDef and
// TilingFunc declare instead of echoing the caller's buffer, and it must
// return that buffer itself because the schema marks it mutable.
void CheckDtype(const at::Tensor &t, at::ScalarType want, const char *name)
{
    TORCH_CHECK(t.scalar_type() == want, "cam_deepep_combine_send: ", name,
        " must have dtype ", want, ", got ", t.scalar_type());
}

void CheckDim(const at::Tensor &t, int64_t dim, const char *name)
{
    TORCH_CHECK(t.dim() == dim, "cam_deepep_combine_send: ", name, " must be ",
        dim, "-D, got ", t.dim(), "-D");
}

void CheckByteBlob(const at::Tensor &t, const char *name)
{
    CheckDtype(t, at::kByte, name);
    CheckDim(t, 1, name);
}
}  // namespace

at::Tensor CamDeepepCombineSendImplNpu(
    const at::Tensor &x,
    const at::Tensor &srcMetadata,
    const at::Tensor &context,
    const at::Tensor &active,
    const at::Tensor &controlBuffer,
    const at::Tensor &executionState,
    const at::Tensor &afdWorkspace,
    const at::Tensor &jettyPtrs,
    at::Tensor &completion,
    c10::string_view groupEp,
    const int64_t numSrcRanks,
    const int64_t numRanks,
    const int64_t numExperts,
    const int64_t numTopk,
    const int64_t numSourceLanes,
    const int64_t numLayers,
    const int64_t maxPaddedTokens,
    const int64_t numTokensPerTile,
    const int64_t rankIdx,
    const int64_t timeoutCycles,
    const int64_t completionBytes,
    const int64_t numVecCores)
{
    vector<char> groupEpChars(groupEp.begin(), groupEp.end());
    groupEpChars.push_back('\0');
    char *groupEpPtr = &groupEpChars[0];

    // The output-side executor skips tiling and the kernel when the only
    // output tensor is empty, so an invalid completion attribute would
    // otherwise succeed as a no-op. Mirror the Meta/TilingFunc contract here
    // and in the public aclnn entry, before the executor is built.
    TORCH_CHECK(completionBytes > 0 && completionBytes <= kMaxCompletionBytes,
        "combine_send: completion_bytes out of range: ", completionBytes);
    CheckDtype(completion, at::kByte, "completion");
    CheckDim(completion, 1, "completion");
    TORCH_CHECK(completion.size(0) == completionBytes,
        "combine_send: completion must be [completion_bytes]");

    EXEC_NPU_CMD(aclnnCamDeepepCombineSend,
        // input
        x, srcMetadata, context, active, controlBuffer, executionState,
        afdWorkspace, jettyPtrs,
        // attr
        groupEpPtr, numSrcRanks, numRanks, numExperts, numTopk, numSourceLanes,
        numLayers, maxPaddedTokens, numTokensPerTile, rankIdx, timeoutCycles,
        completionBytes, numVecCores,
        // output
        completion);
    return completion;
}

at::Tensor CamDeepepCombineSendImplMeta(
    const at::Tensor &x,
    const at::Tensor &srcMetadata,
    const at::Tensor &context,
    const at::Tensor &active,
    const at::Tensor &controlBuffer,
    const at::Tensor &executionState,
    const at::Tensor &afdWorkspace,
    const at::Tensor &jettyPtrs,
    at::Tensor &completion,
    c10::string_view groupEp,
    const int64_t numSrcRanks,
    const int64_t numRanks,
    const int64_t numExperts,
    const int64_t numTopk,
    const int64_t numSourceLanes,
    const int64_t numLayers,
    const int64_t maxPaddedTokens,
    const int64_t numTokensPerTile,
    const int64_t rankIdx,
    const int64_t timeoutCycles,
    const int64_t completionBytes,
    const int64_t numVecCores)
{
    // Attribute domain mirrors TilingFunc: an out-of-domain call fails here,
    // before any kernel launch, on every dispatch key.
    TORCH_CHECK(numSrcRanks > 0 && numSrcRanks <= kMaxNumSrcRanks,
        "combine_send: num_src_ranks out of range: ", numSrcRanks);
    TORCH_CHECK(numRanks > 0 && numRanks <= kMaxNumRanks,
        "combine_send: num_ranks out of range: ", numRanks);
    TORCH_CHECK(numExperts > 0 && numExperts <= kMaxNumExperts,
        "combine_send: num_experts out of range: ", numExperts);
    TORCH_CHECK(numExperts % numRanks == 0 && numExperts / numRanks <= kMaxExpertsPerRank,
        "combine_send: num_experts must divide into at most 512 per rank");
    TORCH_CHECK(numTopk > 0 && numTopk <= kMaxNumTopk,
        "combine_send: num_topk out of range: ", numTopk);
    TORCH_CHECK(numSourceLanes > 0 && numSourceLanes <= kMaxNumSourceLanes,
        "combine_send: num_source_lanes out of range: ", numSourceLanes);
    TORCH_CHECK(numLayers > 0 && numLayers <= kMaxNumLayers,
        "combine_send: num_layers out of range: ", numLayers);
    TORCH_CHECK(maxPaddedTokens > 0 && maxPaddedTokens <= kMaxPaddedTokens,
        "combine_send: max_padded_tokens out of range: ", maxPaddedTokens);
    TORCH_CHECK(numTokensPerTile > 0 && numTokensPerTile <= kMaxTokensPerTile,
        "combine_send: num_tokens_per_tile out of range: ", numTokensPerTile);
    TORCH_CHECK(rankIdx >= 0 && rankIdx < numRanks, "combine_send: rank_idx out of range: ", rankIdx);
    TORCH_CHECK(timeoutCycles > 0, "combine_send: timeout_cycles must be positive");
    TORCH_CHECK(completionBytes > 0 && completionBytes <= kMaxCompletionBytes,
        "combine_send: completion_bytes out of range: ", completionBytes);
    TORCH_CHECK(numVecCores >= 0, "combine_send: num_vec_cores must be nonnegative");

    CheckDtype(x, at::kBFloat16, "x");
    CheckDim(x, kTiledRank, "x");
    TORCH_CHECK(x.size(0) >= maxPaddedTokens, "combine_send: x rows must cover max_padded_tokens");
    TORCH_CHECK(x.size(1) > 0 && x.size(1) <= kMaxNumHidden,
        "combine_send: hidden out of range: ", x.size(1));

    // src_metadata is the [row, 4] int32 dispatch record the send path reads.
    CheckDtype(srcMetadata, at::kInt, "src_metadata");
    CheckDim(srcMetadata, kTiledRank, "src_metadata");
    TORCH_CHECK(srcMetadata.size(0) >= maxPaddedTokens && srcMetadata.size(1) == kMetadataWords,
        "combine_send: src_metadata must be [max_padded_tokens, 4]");

    CheckByteBlob(context, "context");
    CheckByteBlob(active, "active");
    CheckByteBlob(controlBuffer, "control_buffer");
    CheckByteBlob(executionState, "execution_state");
    CheckByteBlob(afdWorkspace, "afd_workspace");
    CheckDtype(jettyPtrs, at::kLong, "jetty_ptrs");
    CheckDim(jettyPtrs, 1, "jetty_ptrs");

    CheckDtype(completion, at::kByte, "completion");
    CheckDim(completion, 1, "completion");
    TORCH_CHECK(completion.size(0) == completionBytes,
        "combine_send: completion must be [completion_bytes]");

    // The kernel fills the caller's completion buffer in place and the schema
    // marks it mutable, so the returned tensor is that same storage.
    return completion;
}

at::Tensor CamDeepepCombineSendImpl(
    const at::Tensor &x,
    const at::Tensor &srcMetadata,
    const at::Tensor &context,
    const at::Tensor &active,
    const at::Tensor &controlBuffer,
    const at::Tensor &executionState,
    const at::Tensor &afdWorkspace,
    const at::Tensor &jettyPtrs,
    at::Tensor &completion,
    c10::string_view groupEp,
    const int64_t numSrcRanks,
    const int64_t numRanks,
    const int64_t numExperts,
    const int64_t numTopk,
    const int64_t numSourceLanes,
    const int64_t numLayers,
    const int64_t maxPaddedTokens,
    const int64_t numTokensPerTile,
    const int64_t rankIdx,
    const int64_t timeoutCycles,
    const int64_t completionBytes,
    const int64_t numVecCores)
{
    static auto op = torch::Dispatcher::singleton()
                         .findSchemaOrThrow("umdk_cam_op_lib::cam_deepep_combine_send", "")
                         .typed<decltype(CamDeepepCombineSendImpl)>();
    return op.call(x, srcMetadata, context, active, controlBuffer, executionState,
        afdWorkspace, jettyPtrs, completion, groupEp, numSrcRanks, numRanks,
        numExperts, numTopk, numSourceLanes, numLayers, maxPaddedTokens,
        numTokensPerTile, rankIdx, timeoutCycles, completionBytes, numVecCores);
}

class ExtCamDeepepCombineSend : public torch::autograd::Function<ExtCamDeepepCombineSend> {
public:
    static at::Tensor forward(
        AutogradContext *ctx,
        const at::Tensor &x,
        const at::Tensor &srcMetadata,
        const at::Tensor &context,
        const at::Tensor &active,
        const at::Tensor &controlBuffer,
        const at::Tensor &executionState,
        const at::Tensor &afdWorkspace,
        const at::Tensor &jettyPtrs,
        at::Tensor &completion,
        c10::string_view groupEp,
        const int64_t numSrcRanks,
        const int64_t numRanks,
        const int64_t numExperts,
        const int64_t numTopk,
        const int64_t numSourceLanes,
        const int64_t numLayers,
        const int64_t maxPaddedTokens,
        const int64_t numTokensPerTile,
        const int64_t rankIdx,
        const int64_t timeoutCycles,
        const int64_t completionBytes,
        const int64_t numVecCores)
    {
        at::AutoDispatchBelowADInplaceOrView guard;
        return CamDeepepCombineSendImpl(x, srcMetadata, context, active,
            controlBuffer, executionState, afdWorkspace, jettyPtrs, completion,
            groupEp, numSrcRanks, numRanks, numExperts, numTopk, numSourceLanes,
            numLayers, maxPaddedTokens, numTokensPerTile, rankIdx, timeoutCycles,
            completionBytes, numVecCores);
    }

    static tensor_list backward(AutogradContext *ctx, tensor_list gradOutputs)
    {
        // Communication operators are not differentiable; one empty gradient per
        // forward argument keeps the autograd contract well-formed.
        return tensor_list(kForwardArgCount);
    }
};

at::Tensor CamDeepepCombineSendImplAutograd(
    const at::Tensor &x,
    const at::Tensor &srcMetadata,
    const at::Tensor &context,
    const at::Tensor &active,
    const at::Tensor &controlBuffer,
    const at::Tensor &executionState,
    const at::Tensor &afdWorkspace,
    const at::Tensor &jettyPtrs,
    at::Tensor &completion,
    c10::string_view groupEp,
    const int64_t numSrcRanks,
    const int64_t numRanks,
    const int64_t numExperts,
    const int64_t numTopk,
    const int64_t numSourceLanes,
    const int64_t numLayers,
    const int64_t maxPaddedTokens,
    const int64_t numTokensPerTile,
    const int64_t rankIdx,
    const int64_t timeoutCycles,
    const int64_t completionBytes,
    const int64_t numVecCores)
{
    return ExtCamDeepepCombineSend::apply(x, srcMetadata, context, active,
        controlBuffer, executionState, afdWorkspace, jettyPtrs, completion,
        groupEp, numSrcRanks, numRanks, numExperts, numTopk, numSourceLanes,
        numLayers, maxPaddedTokens, numTokensPerTile, rankIdx, timeoutCycles,
        completionBytes, numVecCores);
}

TORCH_LIBRARY_IMPL(umdk_cam_op_lib, PrivateUse1, m)
{
    m.impl("cam_deepep_combine_send", &CamDeepepCombineSendImplNpu);
}

TORCH_LIBRARY_IMPL(umdk_cam_op_lib, AutogradPrivateUse1, m)
{
    m.impl("cam_deepep_combine_send", &CamDeepepCombineSendImplAutograd);
}

TORCH_LIBRARY_IMPL(umdk_cam_op_lib, Meta, m)
{
    m.impl("cam_deepep_combine_send", &CamDeepepCombineSendImplMeta);
}
