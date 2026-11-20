/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2026-2026. All rights reserved.
 * Description: afd_async_dispatch_recv operator definition and tiling
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

#include "../op_kernel/afd_async_dispatch_recv_tiling.h"
#include "afd_async_opdef.h"
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
// recv_src_metadata rows: [source lane, round-local token, TopK slot, entry].
constexpr int64_t kMetadataWords = 4;
constexpr int64_t kActiveHeaderBytes = 64;
constexpr size_t kInputActive = 2;
constexpr size_t kInputExecutionState = 3;
constexpr size_t kInputAfdWorkspace = 4;
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

// Mirrors afd_async::afd::TokenLayout so host and device agree byte-for-byte.
uint64_t RecordStride(uint64_t hiddenBytes, uint64_t sfBytes, uint64_t numTopk)
{
    const uint64_t topkIdxOffset = hiddenBytes + Align32(sfBytes);
    const uint64_t topkWeightsOffset = topkIdxOffset + Align32(8uLL * numTopk);
    const uint64_t srcTokenIdxOffset = topkWeightsOffset + 4uLL * numTopk;
    const uint64_t validMaskOffset = srcTokenIdxOffset + 4uLL;
    return Align512(validMaskOffset + 4uLL);
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

int64_t ByteVectorSize(const gert::TilingContext* context, size_t input)
{
    const gert::StorageShape* shape = context->GetInputShape(input);
    if (shape == nullptr || shape->GetStorageShape().GetDimNum() != 1) {
        return 0;
    }
    return shape->GetStorageShape().GetDim(0);
}
}  // namespace

namespace optiling {
using DispatchRecvTiling = Cam::AfdAsyncDispatchRecvTilingData;

static ge::graphStatus ReadDispatchRecvGeometry(gert::TilingContext* context, DispatchRecvTiling* tiling)
{
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
    // Domain check on the int64 values, before any narrowing. The divisibility
    // test is safe because the rank bounds are evaluated first.
    OP_TILING_CHECK(numRanksValue <= 0 || numRanksValue > static_cast<int64_t>(kMaxNumRanks) ||
        numExpertsValue <= 0 || numExpertsValue > static_cast<int64_t>(kMaxNumExperts) ||
        numExpertsValue % numRanksValue != 0 ||
        numTopkValue <= 0 || numTopkValue > static_cast<int64_t>(kMaxNumTopk) ||
        numSourceLanesValue <= 0 ||
        numSourceLanesValue > static_cast<int64_t>(kMaxNumSourceLanes) ||
        numLayersValue <= 0 || numLayersValue > static_cast<int64_t>(kMaxNumLayers) ||
        maxExpandedTokensValue <= 0 || maxExpandedTokensValue > kMaxInt32 ||
        maxPaddedTokensValue <= 0 || maxPaddedTokensValue > kMaxInt32 ||
        maxExpandedTokensValue > maxPaddedTokensValue ||
        expertAlignmentValue <= 0 ||
        (expertAlignmentValue & (expertAlignmentValue - 1)) != 0 ||
        !IsStageCount(numTokensPerStageValue) ||
        rankIdxValue < 0 || rankIdxValue >= numRanksValue,
        OP_LOGE(context->GetNodeName(), "dispatch_recv shape out of support domain"),
        return ge::GRAPH_FAILED);

    tiling->numRanks = static_cast<uint32_t>(numRanksValue);
    tiling->numExperts = static_cast<uint32_t>(numExpertsValue);
    tiling->expertsPerRank = tiling->numExperts / tiling->numRanks;
    tiling->numTopk = static_cast<uint32_t>(numTopkValue);
    tiling->numSourceLanes = static_cast<uint32_t>(numSourceLanesValue);
    tiling->numLayers = static_cast<uint32_t>(numLayersValue);
    tiling->maxExpandedTokens = static_cast<uint32_t>(maxExpandedTokensValue);
    tiling->maxPaddedTokens = static_cast<uint32_t>(maxPaddedTokensValue);
    tiling->expertAlignment = static_cast<uint32_t>(expertAlignmentValue);
    tiling->numTokensPerStage = static_cast<uint32_t>(numTokensPerStageValue);
    tiling->rankIdx = static_cast<uint32_t>(rankIdxValue);
    return ge::GRAPH_SUCCESS;
}

static ge::graphStatus ReadDispatchRecvTransferAttrs(gert::TilingContext* context, DispatchRecvTiling* tiling)
{
    const int64_t sfTokenStrideValue = ReadIntAttr(context, 11U, 0);
    const int64_t sfHiddenStrideValue = ReadIntAttr(context, 12U, 1);
    const int64_t payloadBytesValue = ReadIntAttr(context, 13U, 0);
    const int64_t controlBytesValue = ReadIntAttr(context, 14U, 0);
    const int64_t contextBytesValue = ReadIntAttr(context, 15U, 0);
    // bf16 payload: hidden elements -> bytes. The fp8 body variant keeps the
    // same element axis so the metadata layout stays comparable.
    const int64_t numHiddenValue = ReadIntAttr(context, 16U, kDefaultNumHidden);
    const int64_t numSFPacksValue = ReadIntAttr(context, 17U, 0);
    OP_TILING_CHECK(numHiddenValue <= 0 || numHiddenValue > static_cast<int64_t>(kMaxNumHidden) ||
        numSFPacksValue < 0 || numSFPacksValue > static_cast<int64_t>(kMaxNumSFPacks) ||
        sfTokenStrideValue < 0 || sfTokenStrideValue > kMaxInt32 ||
        sfHiddenStrideValue < 0 || sfHiddenStrideValue > kMaxInt32 ||
        payloadBytesValue <= 0 || contextBytesValue <= 0 || controlBytesValue < 0,
        OP_LOGE(context->GetNodeName(), "dispatch_recv shape out of support domain"),
        return ge::GRAPH_FAILED);
    // The second layer slices by expert with num_padded_rows as the physical row
    // budget. A padded capacity below one alignment leaves no padding headroom,
    // so a slice can make no progress on its current expert and the round never
    // terminates on device. Reject the combination on the host instead.
    OP_TILING_CHECK(tiling->maxPaddedTokens < tiling->expertAlignment,
        OP_LOGE(context->GetNodeName(),
            "dispatch_recv max_padded_tokens (%lld) must be >= expert_alignment (%lld)",
            static_cast<long long>(tiling->maxPaddedTokens),
            static_cast<long long>(tiling->expertAlignment)),
        return ge::GRAPH_FAILED);

    tiling->numHiddenBytes = static_cast<uint32_t>(numHiddenValue) * 2U;
    tiling->numSFPacks = static_cast<uint32_t>(numSFPacksValue);
    tiling->recvSfTokenStride = static_cast<int32_t>(sfTokenStrideValue);
    tiling->recvSfHiddenStride = static_cast<int32_t>(sfHiddenStrideValue);
    tiling->payloadBytes = static_cast<uint64_t>(payloadBytesValue);
    tiling->controlBytes = static_cast<uint64_t>(controlBytesValue);
    tiling->contextBytes = static_cast<uint64_t>(contextBytesValue);
    return ge::GRAPH_SUCCESS;
}

static ge::graphStatus CheckDispatchRecvStorage(
    gert::TilingContext* context, DispatchRecvTiling* tiling, uint32_t numVecCores)
{
    const int64_t activeSize = ByteVectorSize(context, kInputActive);
    OP_TILING_CHECK(activeSize < kActiveHeaderBytes,
        OP_LOGE(context->GetNodeName(), "dispatch_recv active must be a byte vector covering its header"),
        return ge::GRAPH_FAILED);
    const uint64_t activeBytes = static_cast<uint64_t>(activeSize);
    const uint64_t legacyActiveBytes = kActiveHeaderBytes + 64uLL * tiling->numSourceLanes +
        32uLL * tiling->numSourceLanes * tiling->expertsPerRank;
    OP_TILING_CHECK(tiling->maxPaddedTokens > kMaxLaneTokens && activeBytes <= legacyActiveBytes,
        OP_LOGE(context->GetNodeName(), "dispatch_recv rows above the legacy limit require transaction storage"),
        return ge::GRAPH_FAILED);

    if (activeBytes > legacyActiveBytes) {
        const uint64_t segmentCapacity =
            static_cast<uint64_t>(tiling->numSourceLanes) * tiling->expertsPerRank;
        const uint64_t indexCapacity =
            segmentCapacity < tiling->maxExpandedTokens ? segmentCapacity : tiling->maxExpandedTokens;
        const uint64_t executionBytes = 32uLL + Align32(4uLL * tiling->numSourceLanes);
        const uint64_t workspaceBytes = 32uLL * numVecCores + 256uLL + 2uLL * Align32(4uLL * indexCapacity);
        OP_TILING_CHECK(
            ByteVectorSize(context, kInputExecutionState) < static_cast<int64_t>(executionBytes) ||
            ByteVectorSize(context, kInputAfdWorkspace) < static_cast<int64_t>(workspaceBytes),
            OP_LOGE(context->GetNodeName(), "dispatch_recv transaction execution state or scratch is undersized"),
            return ge::GRAPH_FAILED);
    }
    tiling->activeBytes = activeBytes;
    return ge::GRAPH_SUCCESS;
}

static ge::graphStatus SetDispatchRecvResources(gert::TilingContext* context, DispatchRecvTiling* tiling)
{
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
    if (CheckDispatchRecvStorage(context, tiling, numVecCores) != ge::GRAPH_SUCCESS) {
        return ge::GRAPH_FAILED;
    }
    uint64_t ubSize = 0;
    ascendcPlatform.GetCoreMemSize(platform_ascendc::CoreMemType::UB, ubSize);
    OP_TILING_CHECK(ubSize == 0 || ubSize > kMaxPhysicalUbBytes,
        OP_LOGE(context->GetNodeName(), "reported UB size is outside the 950/3510 domain"),
        return ge::GRAPH_FAILED);

    // Re-derive the kernel pool: production DispatchCopyEpilogueUBLayout with
    // runtime strides. token[2], metadata[2], refs[2], segment[2][32],
    // zero[512], control[256].
    const uint64_t tokenBytes =
        RecordStride(tiling->numHiddenBytes, uint64_t(tiling->numSFPacks) * 2u, tiling->numTopk);
    const uint64_t tokenStage = Align32(tokenBytes * tiling->numTokensPerStage);
    const uint64_t metadataStage = Align32(16uLL * tiling->numTokensPerStage);
    const uint64_t refsStage = Align32(4uLL * tiling->numTokensPerStage);
    const uint64_t ubTotal = 2uLL * tokenStage + 2uLL * metadataStage + 2uLL * refsStage +
        64uLL + 512uLL + 256uLL;
    OP_TILING_CHECK(ubTotal > ubSize,
        OP_LOGE(context->GetNodeName(), "dispatch_recv UB pool exceeds available UB"),
        return ge::GRAPH_FAILED);
    tiling->blockDim = numVecCores;
    tiling->numVecCores = numVecCores;
    // The SIMT vector functions address UB through the launch-time dynamic UB
    // window: with the attribute unset only a few KiB are visible, so a VF
    // that touches a routing array past it traps as aivec 341 no matter
    // the layout. Request all but 32 KiB of the vector buffer; the rest
    // covers the static shared-memory reserve the launcher adds on top.
    const uint32_t dynUbSize = ubSize > 32768U ?
        static_cast<uint32_t>(ubSize) - 32768U : static_cast<uint32_t>(ubSize);
    (void)context->SetDynUBufSize(dynUbSize);
    tiling->numUbBytes = static_cast<uint32_t>(ubSize);
    return ge::GRAPH_SUCCESS;
}

static ge::graphStatus TilingFunc(gert::TilingContext* context)
{
    auto* tiling = context->GetTilingData<DispatchRecvTiling>();
    OP_TILING_CHECK(tiling == nullptr, OP_LOGE(context->GetNodeName(), "tiling data is null"),
        return ge::GRAPH_FAILED);
    DispatchRecvTiling pending{};
    if (ReadDispatchRecvGeometry(context, &pending) != ge::GRAPH_SUCCESS ||
        ReadDispatchRecvTransferAttrs(context, &pending) != ge::GRAPH_SUCCESS ||
        SetDispatchRecvResources(context, &pending) != ge::GRAPH_SUCCESS) {
        return ge::GRAPH_FAILED;
    }
    *tiling = pending;
    context->SetBlockDim(pending.blockDim);
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
class AfdAsyncDispatchRecv : public OpDef {
public:
    explicit AfdAsyncDispatchRecv(const char* name) : OpDef(name)
    {
        // Inbound payload plus the AFD control plane. control_buffer is
        // mutated in place, mirroring the production AFD contract.
        RequiredAfdNdTensor(this->Input("payload"), ge::DT_UINT8);
        RequiredAfdNdTensor(this->Input("context"), ge::DT_UINT8);
        RequiredAfdNdTensor(this->Input("active"), ge::DT_UINT8);
        RequiredAfdNdTensor(this->Input("execution_state"), ge::DT_UINT8);
        RequiredAfdNdTensor(this->Input("workspace"), ge::DT_UINT8);
        RequiredAfdNdTensor(this->Input("control_buffer"), ge::DT_UINT8);

        RequiredAfdNdTensor(this->Output("recv_x"), ge::DT_BF16);
        RequiredAfdNdTensor(this->Output("recv_sf"), ge::DT_INT16);
        RequiredAfdNdTensor(this->Output("recv_src_metadata"), ge::DT_INT32);

        DefineAttributes();
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

private:
    void DefineAttributes()
    {
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
    }
};
OP_ADD(AfdAsyncDispatchRecv);
}  // namespace ops
