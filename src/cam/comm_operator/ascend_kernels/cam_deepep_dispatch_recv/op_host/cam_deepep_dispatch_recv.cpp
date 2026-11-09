/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2026-2026. All rights reserved.
 * Description: cam_deepep_dispatch_recv operator definition and tiling
 * Create: 2026-11-03
 * Note: model-dependent sizes are read at tiling time and passed as runtime
 *       fields; the tiling key stays constant. The tiling-time UB budget
 *       re-derives the kernel's own pool layout, so a tiling the body cannot fit
 *       is rejected on the host instead of aborting on device.
 *       max_expanded_tokens is the second-layer split capacity q: the most
 *       expanded rows (one (token, local expert) route each) a scheduler slice
 *       may hold. max_padded_tokens is the physical row budget (>= q, a multiple
 *       of expert_alignment) that sizes the receive buffers and the F-side
 *       split. Size q for the balanced per-rank row count of one round,
 *       ceil(factor * num_sources * window * topk / num_receivers) with factor
 *       around 1.2, and cap it at 32768; batches above the cap simply split into
 *       more slices. Both values must stay fixed for a prepared receive buffer.
 * History: 2026-11-03 create runtime parameter port;
 *          2026-11-03 real tensor interface (payload/active/state tensors);
 *          2026-11-04 reject max_padded_tokens < expert_alignment on the host
 */

#include "../op_kernel/cam_deepep_dispatch_recv_tiling.h"
#include "register/op_def_registry.h"
#include "tiling/platform/platform_ascendc.h"
#include "error_log.h"

namespace {
constexpr uint32_t kDefaultNumRanks = 2;
constexpr uint32_t kDefaultNumExperts = 16;
constexpr uint32_t kDefaultNumTopk = 8;
constexpr uint32_t kDefaultNumSourceLanes = 4;
constexpr uint32_t kDefaultNumLayers = 1;
constexpr uint32_t kDefaultMaxExpandedTokens = 4096;
constexpr uint32_t kDefaultMaxPaddedTokens = 4096;
constexpr uint32_t kDefaultExpertAlignment = 128;
constexpr uint32_t kDefaultNumTokensPerStage = 16;
constexpr uint32_t kDefaultNumHidden = 3584;
constexpr uint32_t kMaxNumRanks = 256;
constexpr uint32_t kMaxNumExperts = 2048;
constexpr uint32_t kMaxNumTopk = 32;
constexpr uint32_t kMaxNumSourceLanes = 256;
constexpr uint32_t kMaxNumLayers = 64;
constexpr uint32_t kMaxLaneTokens = 32768;
constexpr uint32_t kMaxNumHidden = 8192;
constexpr uint32_t kMaxNumSFPacks = 512;
constexpr int64_t kMaxInt32 = 2147483647;
constexpr uint64_t kMaxPhysicalUbBytes = 253952;
// recv_src_metadata rows: [global slot, local slot, source rank, weight index].
constexpr int64_t kMetadataWords = 4;
// Stage counts the kernel accepts: powers of two from 1 to 16.
constexpr int64_t kMinNumTokensPerStage = 1;
constexpr int64_t kMaxNumTokensPerStage = 16;
// Rank of the tiled outputs and their positions in the OpDef output list.
constexpr size_t kOutputRank = 2;
constexpr size_t kOutputRecvX = 0;
constexpr size_t kOutputRecvSf = 1;
constexpr size_t kOutputSrcMetadata = 2;

uint64_t Align32(uint64_t v)
{
    return (v + 31uLL) & ~31uLL;
}

uint64_t Align512(uint64_t v)
{
    return (v + 511uLL) & ~511uLL;
}

// Mirrors deep_ep::afd::TokenLayout so host and device agree byte-for-byte.
uint64_t RecordStride(uint64_t hiddenBytes, uint64_t sfBytes, uint64_t numTopk)
{
    const uint64_t topkIdxOffset = hiddenBytes + Align32(sfBytes);
    const uint64_t topkWeightsOffset = topkIdxOffset + Align32(8uLL * numTopk);
    const uint64_t srcTokenIdxOffset = topkWeightsOffset + 4uLL * numTopk;
    const uint64_t validMaskOffset = srcTokenIdxOffset + 4uLL;
    return Align512(validMaskOffset + 4uLL);
}

uint64_t MetadataStride(uint64_t hiddenBytes, uint64_t sfBytes, uint64_t numTopk)
{
    const uint64_t topkIdxOffset = hiddenBytes + Align32(sfBytes);
    const uint64_t topkWeightsOffset = topkIdxOffset + Align32(8uLL * numTopk);
    const uint64_t srcTokenIdxOffset = topkWeightsOffset + 4uLL * numTopk;
    const uint64_t validMaskOffset = srcTokenIdxOffset + 4uLL;
    return Align32(validMaskOffset + 4uLL - hiddenBytes);
}

// Attributes reach tiling as int64. Read the full value and let the caller
// check the domain before narrowing: narrowing first turned a negative or
// > UINT32_MAX value into a plausible small number that reached the kernel.
int64_t ReadIntAttr(const gert::TilingContext* context, size_t idx, int64_t fallback)
{
    auto attrs = context->GetAttrs();
    if (attrs == nullptr) {
        return fallback;
    }
    const int64_t* value = attrs->GetInt(idx);
    if (value == nullptr) {
        return fallback;
    }
    return *value;
}

bool IsStageCount(int64_t t)
{
    return t >= kMinNumTokensPerStage && t <= kMaxNumTokensPerStage &&
        (t & (t - 1)) == 0;
}
}  // namespace

namespace optiling {
static ge::graphStatus TilingFunc(gert::TilingContext* context)
{
    Cam::CamDeepepDispatchRecvTilingData* tiling = context->GetTilingData<Cam::CamDeepepDispatchRecvTilingData>();
    OP_TILING_CHECK(tiling == nullptr, OP_LOGE(context->GetNodeName(), "tiling data is null"),
        return ge::GRAPH_FAILED);

    // Attr order follows the OpDef below: group_ep, num_ranks, num_experts,
    // num_topk, num_source_lanes, num_layers, max_expanded_tokens,
    // max_padded_tokens, expert_alignment, num_tokens_per_stage, rank_idx,
    // recv_sf_token_stride, recv_sf_hidden_stride, payload_bytes, control_bytes,
    // context_bytes, num_hidden, num_sf_packs, num_vec_cores.
    const int64_t numRanksValue = ReadIntAttr(context, 1U, kDefaultNumRanks);
    const int64_t numExpertsValue = ReadIntAttr(context, 2U, kDefaultNumExperts);
    const int64_t numTopkValue = ReadIntAttr(context, 3U, kDefaultNumTopk);
    const int64_t numSourceLanesValue = ReadIntAttr(context, 4U, kDefaultNumSourceLanes);
    const int64_t numLayersValue = ReadIntAttr(context, 5U, kDefaultNumLayers);
    const int64_t maxExpandedTokensValue = ReadIntAttr(context, 6U, kDefaultMaxExpandedTokens);
    const int64_t maxPaddedTokensValue = ReadIntAttr(context, 7U, kDefaultMaxPaddedTokens);
    const int64_t expertAlignmentValue = ReadIntAttr(context, 8U, kDefaultExpertAlignment);
    const int64_t numTokensPerStageValue = ReadIntAttr(context, 9U, kDefaultNumTokensPerStage);
    const int64_t rankIdxValue = ReadIntAttr(context, 10U, 0);
    const int64_t sfTokenStrideValue = ReadIntAttr(context, 11U, 0);
    const int64_t sfHiddenStrideValue = ReadIntAttr(context, 12U, 1);
    const int64_t payloadBytesValue = ReadIntAttr(context, 13U, 0);
    const int64_t controlBytesValue = ReadIntAttr(context, 14U, 0);
    const int64_t contextBytesValue = ReadIntAttr(context, 15U, 0);
    // bf16 payload: hidden elements -> bytes. The fp8 body variant keeps the
    // same element axis so the metadata layout stays comparable.
    const int64_t numHiddenValue = ReadIntAttr(context, 16U, kDefaultNumHidden);
    const int64_t numSFPacksValue = ReadIntAttr(context, 17U, 0);

    // Domain check on the int64 values, before any narrowing. The divisibility
    // test is safe because the rank bounds are evaluated first.
    OP_TILING_CHECK(numRanksValue <= 0 || numRanksValue > static_cast<int64_t>(kMaxNumRanks) ||
        numExpertsValue <= 0 || numExpertsValue > static_cast<int64_t>(kMaxNumExperts) ||
        numExpertsValue % numRanksValue != 0 ||
        numTopkValue <= 0 || numTopkValue > static_cast<int64_t>(kMaxNumTopk) ||
        numSourceLanesValue <= 0 ||
        numSourceLanesValue > static_cast<int64_t>(kMaxNumSourceLanes) ||
        numLayersValue <= 0 || numLayersValue > static_cast<int64_t>(kMaxNumLayers) ||
        maxExpandedTokensValue <= 0 || maxExpandedTokensValue > static_cast<int64_t>(kMaxLaneTokens) ||
        maxPaddedTokensValue <= 0 || maxPaddedTokensValue > static_cast<int64_t>(kMaxLaneTokens) ||
        maxExpandedTokensValue > maxPaddedTokensValue ||
        expertAlignmentValue <= 0 ||
        (expertAlignmentValue & (expertAlignmentValue - 1)) != 0 ||
        !IsStageCount(numTokensPerStageValue) ||
        numHiddenValue <= 0 || numHiddenValue > static_cast<int64_t>(kMaxNumHidden) ||
        numSFPacksValue < 0 || numSFPacksValue > static_cast<int64_t>(kMaxNumSFPacks) ||
        rankIdxValue < 0 || rankIdxValue >= numRanksValue ||
        sfTokenStrideValue < 0 || sfTokenStrideValue > kMaxInt32 ||
        sfHiddenStrideValue < 0 || sfHiddenStrideValue > kMaxInt32 ||
        payloadBytesValue <= 0 || contextBytesValue <= 0 || controlBytesValue < 0,
        OP_LOGE(context->GetNodeName(), "dispatch_recv shape out of support domain"),
        return ge::GRAPH_FAILED);

    // The second layer slices by expert with num_padded_rows as the physical row
    // budget. A padded capacity below one alignment leaves no padding headroom,
    // so a slice can make no progress on its current expert and the round never
    // terminates on device. Reject the combination on the host instead.
    OP_TILING_CHECK(maxPaddedTokensValue < expertAlignmentValue,
        OP_LOGE(context->GetNodeName(),
            "dispatch_recv max_padded_tokens (%lld) must be >= expert_alignment (%lld)",
            static_cast<long long>(maxPaddedTokensValue),
            static_cast<long long>(expertAlignmentValue)),
        return ge::GRAPH_FAILED);

    const uint32_t numRanks = static_cast<uint32_t>(numRanksValue);
    const uint32_t numExperts = static_cast<uint32_t>(numExpertsValue);
    const uint32_t numTopk = static_cast<uint32_t>(numTopkValue);
    const uint32_t numSourceLanes = static_cast<uint32_t>(numSourceLanesValue);
    const uint32_t numLayers = static_cast<uint32_t>(numLayersValue);
    const uint32_t maxExpandedTokens = static_cast<uint32_t>(maxExpandedTokensValue);
    const uint32_t maxPaddedTokens = static_cast<uint32_t>(maxPaddedTokensValue);
    const uint32_t expertAlignment = static_cast<uint32_t>(expertAlignmentValue);
    const uint32_t numTokensPerStage = static_cast<uint32_t>(numTokensPerStageValue);
    const uint32_t numHidden = static_cast<uint32_t>(numHiddenValue);
    const uint32_t numSFPacks = static_cast<uint32_t>(numSFPacksValue);
    const uint32_t numHiddenBytes = numHidden * 2U;

    auto ascendcPlatform = platform_ascendc::PlatformAscendC(context->GetPlatformInfo());
    const uint32_t aivNum = ascendcPlatform.GetCoreNumAiv();
    OP_TILING_CHECK(aivNum == 0, OP_LOGE(context->GetNodeName(), "no AIV core available"),
        return ge::GRAPH_FAILED);

    // num_vec_cores == 0 keeps the platform AIV count; see dispatch_send.
    const int64_t numVecCoresValue = ReadIntAttr(context, 18U, 0);
    OP_TILING_CHECK(numVecCoresValue < 0 ||
        numVecCoresValue > static_cast<int64_t>(aivNum),
        OP_LOGE(context->GetNodeName(), "dispatch_recv num_vec_cores exceeds the AIV count"),
        return ge::GRAPH_FAILED);
    const uint32_t numVecCores = numVecCoresValue == 0 ?
        aivNum : static_cast<uint32_t>(numVecCoresValue);

    uint64_t ubSize = 0;
    ascendcPlatform.GetCoreMemSize(platform_ascendc::CoreMemType::UB, ubSize);
    OP_TILING_CHECK(ubSize == 0 || ubSize > kMaxPhysicalUbBytes,
        OP_LOGE(context->GetNodeName(), "reported UB size is outside the 950/3510 domain"),
        return ge::GRAPH_FAILED);

    // Re-derive the kernel pool: production DispatchCopyEpilogueUBLayout with
    // runtime strides. token[2], metadata[2], refs[2], segment[2][32],
    // zero[512], control[256].
    const uint64_t tokenBytes = RecordStride(numHiddenBytes, uint64_t(numSFPacks) * 2u, numTopk);
    const uint64_t metadataBytes = MetadataStride(numHiddenBytes, uint64_t(numSFPacks) * 2u, numTopk);
    const uint64_t tokenStage = Align32(tokenBytes * numTokensPerStage);
    const uint64_t metadataStage = Align32(16uLL * numTokensPerStage);
    const uint64_t refsStage = Align32(4uLL * numTokensPerStage);
    const uint64_t ubTotal = 2uLL * tokenStage + 2uLL * metadataStage + 2uLL * refsStage +
        64uLL + 512uLL + 256uLL;
    OP_TILING_CHECK(ubTotal > ubSize,
        OP_LOGE(context->GetNodeName(), "dispatch_recv UB pool exceeds available UB"),
        return ge::GRAPH_FAILED);

    tiling->blockDim = numVecCores;
    tiling->numRanks = numRanks;
    tiling->numExperts = numExperts;
    tiling->expertsPerRank = numExperts / numRanks;
    tiling->numTopk = numTopk;
    tiling->numVecCores = numVecCores;
    tiling->numHiddenBytes = numHiddenBytes;
    tiling->numSFPacks = numSFPacks;
    tiling->numSourceLanes = numSourceLanes;
    tiling->numLayers = numLayers;
    tiling->maxExpandedTokens = maxExpandedTokens;
    tiling->maxPaddedTokens = maxPaddedTokens;
    tiling->expertAlignment = expertAlignment;
    tiling->numTokensPerStage = numTokensPerStage;
    // The SIMT vector functions address UB through the launch-time dynamic UB
    // window: with the attribute unset only a few KiB are visible, so a VF
    // that touches a routing array past it traps as aivec 341 no matter
    // the layout. Request all but 32 KiB of the vector buffer; the rest
    // covers the static shared-memory reserve the launcher adds on top.
    const uint32_t dynUbSize = ubSize > 32768U ?
        static_cast<uint32_t>(ubSize) - 32768U : static_cast<uint32_t>(ubSize);
    (void)context->SetDynUBufSize(dynUbSize);
    tiling->numUbBytes = static_cast<uint32_t>(ubSize);
    tiling->rankIdx = static_cast<uint32_t>(rankIdxValue);
    tiling->recvSfTokenStride = static_cast<int32_t>(sfTokenStrideValue);
    tiling->recvSfHiddenStride = static_cast<int32_t>(sfHiddenStrideValue);
    tiling->payloadBytes = static_cast<uint64_t>(payloadBytesValue);
    tiling->controlBytes = static_cast<uint64_t>(controlBytesValue);
    tiling->contextBytes = static_cast<uint64_t>(contextBytesValue);
    tiling->reserved[0] = 0U;
    tiling->reserved[1] = 0U;

    context->SetBlockDim(numVecCores);
    return ge::GRAPH_SUCCESS;
}
}  // namespace optiling

namespace ge {
static ge::graphStatus InferShape(gert::InferShapeContext* context)
{
    auto attrs = context->GetAttrs();
    int64_t maxPaddedTokens = kDefaultMaxPaddedTokens;
    int64_t numHidden = kDefaultNumHidden;
    int64_t numSFPacks = 0;
    if (attrs != nullptr) {
        const int64_t* padded = attrs->GetInt(7U);
        const int64_t* hidden = attrs->GetInt(16U);
        const int64_t* packs = attrs->GetInt(17U);
        if (padded != nullptr && *padded > 0) {
            maxPaddedTokens = *padded;
        }
        if (hidden != nullptr && *hidden > 0) {
            numHidden = *hidden;
        }
        if (packs != nullptr && *packs > 0) {
            numSFPacks = *packs;
        }
    }

    gert::Shape* xShape = context->GetOutputShape(kOutputRecvX);
    xShape->SetDimNum(kOutputRank);
    xShape->SetDim(0, maxPaddedTokens);
    xShape->SetDim(1, numHidden);

    gert::Shape* sfShape = context->GetOutputShape(kOutputRecvSf);
    sfShape->SetDimNum(kOutputRank);
    sfShape->SetDim(0, maxPaddedTokens);
    sfShape->SetDim(1, numSFPacks);

    gert::Shape* metadataShape = context->GetOutputShape(kOutputSrcMetadata);
    metadataShape->SetDimNum(kOutputRank);
    metadataShape->SetDim(0, maxPaddedTokens);
    metadataShape->SetDim(1, kMetadataWords);
    return GRAPH_SUCCESS;
}

static ge::graphStatus InferDataType(gert::InferDataTypeContext* context)
{
    context->SetOutputDataType(kOutputRecvX, ge::DT_BF16);
    context->SetOutputDataType(kOutputRecvSf, ge::DT_INT16);
    context->SetOutputDataType(kOutputSrcMetadata, ge::DT_INT32);
    return GRAPH_SUCCESS;
}
}  // namespace ge

namespace ops {
class CamDeepepDispatchRecv : public OpDef {
public:
    explicit CamDeepepDispatchRecv(const char* name) : OpDef(name)
    {
        // Inbound payload plus the AFD control plane. control_buffer is
        // mutated in place, mirroring the production AFD contract.
        this->Input("payload")
            .ParamType(REQUIRED)
            .DataType({ge::DT_UINT8})
            .Format({ge::FORMAT_ND})
            .UnknownShapeFormat({ge::FORMAT_ND});
        this->Input("context")
            .ParamType(REQUIRED)
            .DataType({ge::DT_UINT8})
            .Format({ge::FORMAT_ND})
            .UnknownShapeFormat({ge::FORMAT_ND});
        this->Input("active")
            .ParamType(REQUIRED)
            .DataType({ge::DT_UINT8})
            .Format({ge::FORMAT_ND})
            .UnknownShapeFormat({ge::FORMAT_ND});
        this->Input("execution_state")
            .ParamType(REQUIRED)
            .DataType({ge::DT_UINT8})
            .Format({ge::FORMAT_ND})
            .UnknownShapeFormat({ge::FORMAT_ND});
        this->Input("workspace")
            .ParamType(REQUIRED)
            .DataType({ge::DT_UINT8})
            .Format({ge::FORMAT_ND})
            .UnknownShapeFormat({ge::FORMAT_ND});
        this->Input("control_buffer")
            .ParamType(REQUIRED)
            .DataType({ge::DT_UINT8})
            .Format({ge::FORMAT_ND})
            .UnknownShapeFormat({ge::FORMAT_ND});

        this->Output("recv_x")
            .ParamType(REQUIRED)
            .DataType({ge::DT_BF16})
            .Format({ge::FORMAT_ND})
            .UnknownShapeFormat({ge::FORMAT_ND});
        this->Output("recv_sf")
            .ParamType(REQUIRED)
            .DataType({ge::DT_INT16})
            .Format({ge::FORMAT_ND})
            .UnknownShapeFormat({ge::FORMAT_ND});
        this->Output("recv_src_metadata")
            .ParamType(REQUIRED)
            .DataType({ge::DT_INT32})
            .Format({ge::FORMAT_ND})
            .UnknownShapeFormat({ge::FORMAT_ND});

        this->Attr("group_ep").String();
        this->Attr("num_ranks").Int();
        this->Attr("num_experts").Int();
        this->Attr("num_topk").Int();
        this->Attr("num_source_lanes").Int();
        this->Attr("num_layers").Int();
        this->Attr("max_expanded_tokens").Int();
        this->Attr("max_padded_tokens").Int();
        this->Attr("expert_alignment").Int();
        this->Attr("num_tokens_per_stage").Int();
        this->Attr("rank_idx").Int();
        this->Attr("recv_sf_token_stride").Int();
        this->Attr("recv_sf_hidden_stride").Int();
        this->Attr("payload_bytes").Int();
        this->Attr("control_bytes").Int();
        this->Attr("context_bytes").Int();
        this->Attr("num_hidden").Int();
        this->Attr("num_sf_packs").Int();
        this->Attr("num_vec_cores").Int();
        this->SetInferShape(ge::InferShape).SetInferDataType(ge::InferDataType);

        OpAICoreConfig aicoreConfig;
        aicoreConfig.DynamicCompileStaticFlag(true)
            .DynamicFormatFlag(true)
            .DynamicRankSupportFlag(true)
            .DynamicShapeSupportFlag(true)
            .NeedCheckSupportFlag(false)
            .PrecisionReduceFlag(true)
            .ExtendCfgInfo("aclnnSupport.value", "support_aclnn")
            .ExtendCfgInfo("jitCompile.flag", "static_true")
            .ExtendCfgInfo("multiKernelSupportDynamicGraph.value", "multi_kernel");

        this->AICore().SetTiling(optiling::TilingFunc);
        this->AICore().AddConfig("ascend950", aicoreConfig);
    }
};
OP_ADD(CamDeepepDispatchRecv);
}  // namespace ops
