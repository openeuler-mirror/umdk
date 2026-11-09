/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2026-2026. All rights reserved.
 * Description: cam_deepep_dispatch_recv pybind extension file.
 * Create: 2026-11-03
 * Note: the three receive buffers are caller-owned so the same storage can be
 *       replayed across rounds; they are passed in and returned.
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
constexpr int64_t kMaxNumSourceLanes = 256;
constexpr int64_t kMaxNumLayers = 64;
constexpr int64_t kMaxLaneTokens = 32768;
constexpr int64_t kMaxNumHidden = 8192;
constexpr int64_t kMaxNumSFPacks = 512;
constexpr int64_t kMinNumTokensPerStage = 1;
constexpr int64_t kMaxNumTokensPerStage = 16;
constexpr int64_t kMetadataWords = 4;
constexpr int64_t kTiledRank = 2;

// One gradient slot per forward argument, and the fixed output positions.
constexpr size_t kForwardArgCount = 28;
constexpr size_t kOutRecvX = 0;
constexpr size_t kOutRecvSf = 1;
constexpr size_t kOutSrcMetadata = 2;

// The Meta kernel must reject the same dtype/shape/attr domain the op_host
// declares instead of echoing the caller's buffers, and it must return the
// caller-owned buffers themselves because the schema marks them mutable.
void CheckDtype(const at::Tensor &t, at::ScalarType want, const char *name)
{
    TORCH_CHECK(t.scalar_type() == want, "cam_deepep_dispatch_recv: ", name,
        " must have dtype ", want, ", got ", t.scalar_type());
}

void CheckDim(const at::Tensor &t, int64_t dim, const char *name)
{
    TORCH_CHECK(t.dim() == dim, "cam_deepep_dispatch_recv: ", name, " must be ",
        dim, "-D, got ", t.dim(), "-D");
}

void CheckByteBlob(const at::Tensor &t, const char *name)
{
    CheckDtype(t, at::kByte, name);
    CheckDim(t, 1, name);
}
}  // namespace

std::tuple<at::Tensor, at::Tensor, at::Tensor> CamDeepepDispatchRecvImplNpu(
    const at::Tensor &payload,
    const at::Tensor &context,
    const at::Tensor &active,
    const at::Tensor &executionState,
    const at::Tensor &afdWorkspace,
    const at::Tensor &controlBuffer,
    at::Tensor &recvX,
    at::Tensor &recvSf,
    at::Tensor &recvSrcMetadata,
    c10::string_view groupEp,
    const int64_t numRanks,
    const int64_t numExperts,
    const int64_t numTopk,
    const int64_t numSourceLanes,
    const int64_t numLayers,
    const int64_t maxExpandedTokens,
    const int64_t maxPaddedTokens,
    const int64_t expertAlignment,
    const int64_t numTokensPerStage,
    const int64_t rankIdx,
    const int64_t recvSfTokenStride,
    const int64_t recvSfHiddenStride,
    const int64_t payloadBytes,
    const int64_t controlBytes,
    const int64_t contextBytes,
    const int64_t numHidden,
    const int64_t numSfPacks,
    const int64_t numVecCores)
{
    vector<char> groupEpChars(groupEp.begin(), groupEp.end());
    groupEpChars.push_back('\0');
    char *groupEpPtr = &groupEpChars[0];

    EXEC_NPU_CMD(aclnnCamDeepepDispatchRecv,
        // input
        payload, context, active, executionState, afdWorkspace, controlBuffer,
        // attr
        groupEpPtr, numRanks, numExperts, numTopk, numSourceLanes, numLayers,
        maxExpandedTokens, maxPaddedTokens, expertAlignment, numTokensPerStage,
        rankIdx, recvSfTokenStride, recvSfHiddenStride, payloadBytes, controlBytes,
        contextBytes, numHidden, numSfPacks, numVecCores,
        // output
        recvX, recvSf, recvSrcMetadata);
    return std::make_tuple(recvX, recvSf, recvSrcMetadata);
}

std::tuple<at::Tensor, at::Tensor, at::Tensor> CamDeepepDispatchRecvImplMeta(
    const at::Tensor &payload,
    const at::Tensor &context,
    const at::Tensor &active,
    const at::Tensor &executionState,
    const at::Tensor &afdWorkspace,
    const at::Tensor &controlBuffer,
    at::Tensor &recvX,
    at::Tensor &recvSf,
    at::Tensor &recvSrcMetadata,
    c10::string_view groupEp,
    const int64_t numRanks,
    const int64_t numExperts,
    const int64_t numTopk,
    const int64_t numSourceLanes,
    const int64_t numLayers,
    const int64_t maxExpandedTokens,
    const int64_t maxPaddedTokens,
    const int64_t expertAlignment,
    const int64_t numTokensPerStage,
    const int64_t rankIdx,
    const int64_t recvSfTokenStride,
    const int64_t recvSfHiddenStride,
    const int64_t payloadBytes,
    const int64_t controlBytes,
    const int64_t contextBytes,
    const int64_t numHidden,
    const int64_t numSfPacks,
    const int64_t numVecCores)
{
    // Opaque AFD control plane: uint8 byte blobs owned by the caller.
    CheckByteBlob(payload, "payload");
    CheckByteBlob(context, "context");
    CheckByteBlob(active, "active");
    CheckByteBlob(executionState, "execution_state");
    CheckByteBlob(afdWorkspace, "afd_workspace");
    CheckByteBlob(controlBuffer, "control_buffer");

    // Attribute domain mirrors TilingFunc so a bad call fails here too.
    TORCH_CHECK(numRanks > 0 && numRanks <= kMaxNumRanks,
        "dispatch_recv: num_ranks out of range: ", numRanks);
    TORCH_CHECK(numExperts > 0 && numExperts <= kMaxNumExperts,
        "dispatch_recv: num_experts out of range: ", numExperts);
    TORCH_CHECK(numExperts % numRanks == 0,
        "dispatch_recv: num_experts must divide by num_ranks");
    TORCH_CHECK(numTopk > 0 && numTopk <= kMaxNumTopk,
        "dispatch_recv: num_topk out of range: ", numTopk);
    TORCH_CHECK(numSourceLanes > 0 && numSourceLanes <= kMaxNumSourceLanes,
        "dispatch_recv: num_source_lanes out of range: ", numSourceLanes);
    TORCH_CHECK(numLayers > 0 && numLayers <= kMaxNumLayers,
        "dispatch_recv: num_layers out of range: ", numLayers);
    TORCH_CHECK(maxExpandedTokens > 0 && maxExpandedTokens <= kMaxLaneTokens,
        "dispatch_recv: max_expanded_tokens out of range: ", maxExpandedTokens);
    TORCH_CHECK(maxPaddedTokens > 0 && maxPaddedTokens <= kMaxLaneTokens,
        "dispatch_recv: max_padded_tokens out of range: ", maxPaddedTokens);
    TORCH_CHECK(maxExpandedTokens <= maxPaddedTokens,
        "dispatch_recv: max_expanded_tokens must not exceed max_padded_tokens");
    TORCH_CHECK(expertAlignment > 0 && (expertAlignment & (expertAlignment - 1)) == 0,
        "dispatch_recv: expert_alignment must be a power of two");
    TORCH_CHECK(maxPaddedTokens >= expertAlignment,
        "dispatch_recv: max_padded_tokens must cover one expert_alignment");
    TORCH_CHECK(numTokensPerStage >= kMinNumTokensPerStage &&
        numTokensPerStage <= kMaxNumTokensPerStage &&
        (numTokensPerStage & (numTokensPerStage - 1)) == 0,
        "dispatch_recv: num_tokens_per_stage out of range: ", numTokensPerStage);
    TORCH_CHECK(rankIdx >= 0 && rankIdx < numRanks, "dispatch_recv: rank_idx out of range: ", rankIdx);
    TORCH_CHECK(recvSfTokenStride >= 0 && recvSfTokenStride <= kMaxStride &&
        recvSfHiddenStride >= 0 && recvSfHiddenStride <= kMaxStride,
        "dispatch_recv: recv_sf strides must be nonnegative");
    TORCH_CHECK(payloadBytes > 0 && contextBytes > 0,
        "dispatch_recv: payload_bytes and context_bytes must be positive");
    TORCH_CHECK(numHidden > 0 && numHidden <= kMaxNumHidden,
        "dispatch_recv: num_hidden out of range: ", numHidden);
    TORCH_CHECK(numSfPacks >= 0 && numSfPacks <= kMaxNumSFPacks,
        "dispatch_recv: num_sf_packs out of range: ", numSfPacks);
    TORCH_CHECK(numVecCores >= 0, "dispatch_recv: num_vec_cores must be nonnegative");

    // Output buffers are preallocated by the caller; their shape follows attrs.
    CheckDtype(recvX, at::kBFloat16, "recv_x");
    CheckDim(recvX, kTiledRank, "recv_x");
    TORCH_CHECK(recvX.size(0) == maxPaddedTokens && recvX.size(1) == numHidden,
        "dispatch_recv: recv_x must be [max_padded_tokens, num_hidden]");
    CheckDtype(recvSf, at::kShort, "recv_sf");
    CheckDim(recvSf, kTiledRank, "recv_sf");
    TORCH_CHECK(recvSf.size(0) == maxPaddedTokens && recvSf.size(1) == numSfPacks,
        "dispatch_recv: recv_sf must be [max_padded_tokens, num_sf_packs] int16");
    CheckDtype(recvSrcMetadata, at::kInt, "recv_src_metadata");
    CheckDim(recvSrcMetadata, kTiledRank, "recv_src_metadata");
    TORCH_CHECK(recvSrcMetadata.size(0) == maxPaddedTokens && recvSrcMetadata.size(1) == kMetadataWords,
        "dispatch_recv: recv_src_metadata must be [max_padded_tokens, 4] int32");

    // Read-path side effect: the kernel advances execution_state in place and
    // uses afd_workspace as scratch, so the returned tuple aliases the inputs.
    return std::make_tuple(recvX, recvSf, recvSrcMetadata);
}

std::tuple<at::Tensor, at::Tensor, at::Tensor> CamDeepepDispatchRecvImpl(
    const at::Tensor &payload,
    const at::Tensor &context,
    const at::Tensor &active,
    const at::Tensor &executionState,
    const at::Tensor &afdWorkspace,
    const at::Tensor &controlBuffer,
    at::Tensor &recvX,
    at::Tensor &recvSf,
    at::Tensor &recvSrcMetadata,
    c10::string_view groupEp,
    const int64_t numRanks,
    const int64_t numExperts,
    const int64_t numTopk,
    const int64_t numSourceLanes,
    const int64_t numLayers,
    const int64_t maxExpandedTokens,
    const int64_t maxPaddedTokens,
    const int64_t expertAlignment,
    const int64_t numTokensPerStage,
    const int64_t rankIdx,
    const int64_t recvSfTokenStride,
    const int64_t recvSfHiddenStride,
    const int64_t payloadBytes,
    const int64_t controlBytes,
    const int64_t contextBytes,
    const int64_t numHidden,
    const int64_t numSfPacks,
    const int64_t numVecCores)
{
    static auto op = torch::Dispatcher::singleton()
                         .findSchemaOrThrow("umdk_cam_op_lib::cam_deepep_dispatch_recv", "")
                         .typed<decltype(CamDeepepDispatchRecvImpl)>();
    return op.call(payload, context, active, executionState, afdWorkspace,
        controlBuffer, recvX, recvSf, recvSrcMetadata, groupEp, numRanks,
        numExperts, numTopk, numSourceLanes, numLayers, maxExpandedTokens,
        maxPaddedTokens, expertAlignment, numTokensPerStage, rankIdx,
        recvSfTokenStride, recvSfHiddenStride, payloadBytes, controlBytes,
        contextBytes, numHidden, numSfPacks, numVecCores);
}

class ExtCamDeepepDispatchRecv : public torch::autograd::Function<ExtCamDeepepDispatchRecv> {
public:
    // torch::autograd::Function::apply only accepts a Tensor or a tensor_list
    // as the forward result (to_optional has no tuple overload), so the fixed
    // three-output contract is carried as a list here and re-packed below.
    static tensor_list forward(
        AutogradContext *ctx,
        const at::Tensor &payload,
        const at::Tensor &context,
        const at::Tensor &active,
        const at::Tensor &executionState,
        const at::Tensor &afdWorkspace,
        const at::Tensor &controlBuffer,
        at::Tensor &recvX,
        at::Tensor &recvSf,
        at::Tensor &recvSrcMetadata,
        c10::string_view groupEp,
        const int64_t numRanks,
        const int64_t numExperts,
        const int64_t numTopk,
        const int64_t numSourceLanes,
        const int64_t numLayers,
        const int64_t maxExpandedTokens,
        const int64_t maxPaddedTokens,
        const int64_t expertAlignment,
        const int64_t numTokensPerStage,
        const int64_t rankIdx,
        const int64_t recvSfTokenStride,
        const int64_t recvSfHiddenStride,
        const int64_t payloadBytes,
        const int64_t controlBytes,
        const int64_t contextBytes,
        const int64_t numHidden,
        const int64_t numSfPacks,
        const int64_t numVecCores)
    {
        at::AutoDispatchBelowADInplaceOrView guard;
        const auto outs = CamDeepepDispatchRecvImpl(payload, context, active,
            executionState, afdWorkspace, controlBuffer, recvX, recvSf,
            recvSrcMetadata, groupEp, numRanks, numExperts, numTopk, numSourceLanes,
            numLayers, maxExpandedTokens, maxPaddedTokens, expertAlignment,
            numTokensPerStage, rankIdx, recvSfTokenStride, recvSfHiddenStride,
            payloadBytes, controlBytes, contextBytes, numHidden, numSfPacks,
            numVecCores);
        return tensor_list{std::get<kOutRecvX>(outs), std::get<kOutRecvSf>(outs),
            std::get<kOutSrcMetadata>(outs)};
    }

    static tensor_list backward(AutogradContext *ctx, tensor_list gradOutputs)
    {
        // Communication operators are not differentiable; one empty gradient per
        // forward argument keeps the autograd contract well-formed.
        return tensor_list(kForwardArgCount);
    }
};

std::tuple<at::Tensor, at::Tensor, at::Tensor> CamDeepepDispatchRecvImplAutograd(
    const at::Tensor &payload,
    const at::Tensor &context,
    const at::Tensor &active,
    const at::Tensor &executionState,
    const at::Tensor &afdWorkspace,
    const at::Tensor &controlBuffer,
    at::Tensor &recvX,
    at::Tensor &recvSf,
    at::Tensor &recvSrcMetadata,
    c10::string_view groupEp,
    const int64_t numRanks,
    const int64_t numExperts,
    const int64_t numTopk,
    const int64_t numSourceLanes,
    const int64_t numLayers,
    const int64_t maxExpandedTokens,
    const int64_t maxPaddedTokens,
    const int64_t expertAlignment,
    const int64_t numTokensPerStage,
    const int64_t rankIdx,
    const int64_t recvSfTokenStride,
    const int64_t recvSfHiddenStride,
    const int64_t payloadBytes,
    const int64_t controlBytes,
    const int64_t contextBytes,
    const int64_t numHidden,
    const int64_t numSfPacks,
    const int64_t numVecCores)
{
    const auto outs = ExtCamDeepepDispatchRecv::apply(payload, context, active,
        executionState, afdWorkspace, controlBuffer, recvX, recvSf, recvSrcMetadata,
        groupEp, numRanks, numExperts, numTopk, numSourceLanes, numLayers,
        maxExpandedTokens, maxPaddedTokens, expertAlignment, numTokensPerStage,
        rankIdx, recvSfTokenStride, recvSfHiddenStride, payloadBytes, controlBytes,
        contextBytes, numHidden, numSfPacks, numVecCores);
    return std::make_tuple(outs[kOutRecvX], outs[kOutRecvSf], outs[kOutSrcMetadata]);
}

TORCH_LIBRARY_IMPL(umdk_cam_op_lib, PrivateUse1, m)
{
    m.impl("cam_deepep_dispatch_recv", &CamDeepepDispatchRecvImplNpu);
}

TORCH_LIBRARY_IMPL(umdk_cam_op_lib, AutogradPrivateUse1, m)
{
    m.impl("cam_deepep_dispatch_recv", &CamDeepepDispatchRecvImplAutograd);
}

TORCH_LIBRARY_IMPL(umdk_cam_op_lib, Meta, m)
{
    m.impl("cam_deepep_dispatch_recv", &CamDeepepDispatchRecvImplMeta);
}
