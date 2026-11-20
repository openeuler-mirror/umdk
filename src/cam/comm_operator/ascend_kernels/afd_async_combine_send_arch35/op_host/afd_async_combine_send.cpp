/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2026-2026. All rights reserved.
 * Description: afd_async_combine_send operator definition and tiling
 * Create: 2026-11-03
 * Note: model-dependent sizes are read at tiling time and passed as runtime
 *       fields; the tiling key stays constant. max_padded_tokens is the physical
 *       row budget (q_alloc) of the matching dispatch_recv receive buffer and
 *       must be the same value for the whole transaction.
 * History: 2026-11-03 create runtime parameter port;
 *          2026-11-03 real tensor interface (completion output, rank/limits);
 *          2026-11-04 document the max_padded_tokens contract
 */

#include <cstdlib>
#include <limits>

#include "../op_kernel/afd_async_combine_send_tiling.h"
#include "afd_async_opdef.h"
#include "tiling/platform/platform_ascendc.h"
#include "error_log.h"

namespace {
constexpr uint32_t kDefaultNumSrcRanks = 2;
constexpr uint32_t kDefaultNumRanks = 2;
constexpr uint32_t kDefaultNumExperts = 16;
constexpr uint32_t kDefaultNumTopk = 8;
constexpr uint32_t kDefaultNumSourceLanes = 4;
constexpr uint32_t kDefaultNumLayers = 1;
constexpr uint32_t kDefaultMaxPaddedTokens = 4096;
constexpr uint32_t kDefaultNumTokensPerTile = 16;
constexpr uint32_t kDefaultNumHidden = 3584;
constexpr uint32_t kDefaultCompletionBytes = 4096;
constexpr uint32_t kMaxNumRanks = 256;
constexpr uint32_t kMaxNumExperts = 2048;
constexpr uint32_t kMaxExpertsPerRank = 512;
constexpr uint32_t kMaxNumTopk = 32;
constexpr uint32_t kMaxNumSourceLanes = 256;
constexpr uint32_t kMaxNumLayers = 64;
constexpr uint32_t kMaxTokensPerTile = 128;
constexpr uint32_t kMaxLaneTokens = 32768;
constexpr uint32_t kMaxNumHidden = 8192;
constexpr uint32_t kMaxCompletionBytes = 65536;
constexpr uint64_t kDefaultTimeoutCycles = 1000000000;
// Upper bound for make_ub_offsets() at the admitted shape maxima:
// 48*256 peer infos + 96*256 jetty info + 512 SQE + 2*128*16 metadata +
// 2*256*4 lane maps + 256*(4+4+8) cached lane fields + 256 control.
constexpr uint64_t kCombineSendUbBytes = 48uLL * 256uLL + 96uLL * 256uLL + 512uLL +
    2uLL * 128uLL * 4uLL * 4uLL + 2uLL * 256uLL * 4uLL +
    256uLL * (4uLL + 4uLL + 8uLL) + 256uLL;

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
    return value == nullptr ? fallback : *value;
}

// A supported partition assigns at least one expert to each rank.
uint32_t GetExpertsPerRank(int64_t numExperts, int64_t numRanks)
{
    if (numRanks > 0 && numRanks <= kMaxNumRanks && numExperts > 0 && numExperts <= kMaxNumExperts) {
        const auto partition = std::div(numExperts, numRanks);
        if (partition.rem == 0 && partition.quot <= kMaxExpertsPerRank) {
            return static_cast<uint32_t>(partition.quot);
        }
    }
    return 0;
}
}  // namespace

namespace optiling {
using CombineSendTiling = Cam::AfdAsyncCombineSendTilingData;

static ge::graphStatus ReadCombineSendAttrs(gert::TilingContext* context, CombineSendTiling* tiling)
{
    // Attr order follows the OpDef below: group_ep, num_src_ranks, num_ranks,
    // num_experts, num_topk, num_source_lanes, num_layers, max_padded_tokens,
    // num_tokens_per_tile, rank_idx, timeout_cycles, completion_bytes.
    const int64_t numSrcRanksValue = ReadIntAttr(context, 1U, kDefaultNumSrcRanks);
    const int64_t numRanksValue = ReadIntAttr(context, 2U, kDefaultNumRanks);
    const int64_t numExpertsValue = ReadIntAttr(context, 3U, kDefaultNumExperts);
    const int64_t numTopkValue = ReadIntAttr(context, 4U, kDefaultNumTopk);
    const int64_t numSourceLanesValue = ReadIntAttr(context, 5U, kDefaultNumSourceLanes);
    const int64_t numLayersValue = ReadIntAttr(context, 6U, kDefaultNumLayers);
    const int64_t maxPaddedTokensValue = ReadIntAttr(context, 7U, kDefaultMaxPaddedTokens);
    const int64_t numTokensPerTileValue = ReadIntAttr(context, 8U, kDefaultNumTokensPerTile);
    const int64_t rankIdxValue = ReadIntAttr(context, 9U, 0);
    const int64_t timeoutCyclesValue =
        ReadIntAttr(context, 10U, static_cast<int64_t>(kDefaultTimeoutCycles));
    const int64_t completionBytesValue =
        ReadIntAttr(context, 11U, static_cast<int64_t>(kDefaultCompletionBytes));

    const uint32_t expertsPerRank = GetExpertsPerRank(numExpertsValue, numRanksValue);
    OP_TILING_CHECK(numSrcRanksValue <= 0 || numSrcRanksValue > static_cast<int64_t>(kMaxNumRanks) ||
        expertsPerRank == 0 ||
        numTopkValue <= 0 || numTopkValue > static_cast<int64_t>(kMaxNumTopk) ||
        numSourceLanesValue <= 0 ||
        numSourceLanesValue > static_cast<int64_t>(kMaxNumSourceLanes) ||
        numLayersValue <= 0 || numLayersValue > static_cast<int64_t>(kMaxNumLayers) ||
        maxPaddedTokensValue <= 0 || maxPaddedTokensValue > std::numeric_limits<int32_t>::max() ||
        numTokensPerTileValue <= 0 || numTokensPerTileValue > static_cast<int64_t>(kMaxTokensPerTile) ||
        rankIdxValue < 0 || rankIdxValue >= numRanksValue ||
        timeoutCyclesValue <= 0 ||
        completionBytesValue <= 0 ||
        completionBytesValue > static_cast<int64_t>(kMaxCompletionBytes),
        OP_LOGE(context->GetNodeName(), "combine_send shape out of support domain"),
        return ge::GRAPH_FAILED);

    tiling->numSrcRanks = static_cast<uint32_t>(numSrcRanksValue);
    tiling->numRanks = static_cast<uint32_t>(numRanksValue);
    tiling->expertsPerRank = expertsPerRank;
    tiling->numTopk = static_cast<uint32_t>(numTopkValue);
    tiling->numSourceLanes = static_cast<uint32_t>(numSourceLanesValue);
    tiling->numLayers = static_cast<uint32_t>(numLayersValue);
    tiling->maxPaddedTokens = static_cast<uint32_t>(maxPaddedTokensValue);
    tiling->numTokensPerTile = static_cast<uint32_t>(numTokensPerTileValue);
    tiling->rankIdx = static_cast<uint32_t>(rankIdxValue);
    tiling->timeoutCycles = static_cast<uint64_t>(timeoutCyclesValue);
    tiling->completionBytes = static_cast<uint32_t>(completionBytesValue);
    return ge::GRAPH_SUCCESS;
}

static ge::graphStatus SetCombineSendShape(gert::TilingContext* context, CombineSendTiling* tiling)
{
    const gert::StorageShape* activeShape = context->GetInputShape(3);
    OP_TILING_CHECK(activeShape == nullptr || activeShape->GetStorageShape().GetDimNum() != 1 ||
        activeShape->GetStorageShape().GetDim(0) < 64,
        OP_LOGE(context->GetNodeName(), "combine_send active must be a byte vector covering its header"),
        return ge::GRAPH_FAILED);
    const uint64_t activeBytes = static_cast<uint64_t>(activeShape->GetStorageShape().GetDim(0));
    const uint64_t legacyActiveBytes = 64 + 64uLL * tiling->numSourceLanes +
        32uLL * tiling->numSourceLanes * tiling->expertsPerRank;
    OP_TILING_CHECK(tiling->maxPaddedTokens > kMaxLaneTokens && activeBytes <= legacyActiveBytes,
        OP_LOGE(context->GetNodeName(), "combine_send rows above the legacy limit require transaction storage"),
        return ge::GRAPH_FAILED);

    // hidden is a tensor dimension, not an attr: bf16 -> 2 bytes per element,
    // but the payload view stays bfloat16_t*, so tiling carries elements.
    uint32_t numHidden = kDefaultNumHidden;
    const gert::StorageShape* xShape = context->GetInputShape(0);
    if (xShape != nullptr && xShape->GetStorageShape().GetDimNum() >= 1) {
        const gert::Shape& xDims = xShape->GetStorageShape();
        const int64_t hidden = xDims.GetDim(xDims.GetDimNum() - 1);
        if (hidden > 0 && hidden <= static_cast<int64_t>(kMaxNumHidden)) {
            numHidden = static_cast<uint32_t>(hidden);
        }
    }
    if (activeBytes > legacyActiveBytes) {
        const gert::StorageShape* metadataShape = context->GetInputShape(1);
        OP_TILING_CHECK(xShape == nullptr || xShape->GetStorageShape().GetDimNum() != 2 ||
            xShape->GetStorageShape().GetDim(0) < tiling->maxPaddedTokens ||
            xShape->GetStorageShape().GetDim(1) != numHidden ||
            metadataShape == nullptr || metadataShape->GetStorageShape().GetDimNum() != 2 ||
            metadataShape->GetStorageShape().GetDim(0) < tiling->maxPaddedTokens ||
            metadataShape->GetStorageShape().GetDim(1) != 4,
            OP_LOGE(context->GetNodeName(),
                "combine_send transaction tensors do not cover the configured row capacity"),
            return ge::GRAPH_FAILED);
    }
    OP_TILING_CHECK(numHidden == 0 || numHidden > kMaxNumHidden,
        OP_LOGE(context->GetNodeName(), "combine_send hidden is outside the support domain"),
        return ge::GRAPH_FAILED);

    tiling->activeBytes = activeBytes;
    tiling->numHidden = numHidden;
    return ge::GRAPH_SUCCESS;
}

static ge::graphStatus SetCombineSendResources(gert::TilingContext* context, CombineSendTiling* tiling)
{
    auto ascendcPlatform = platform_ascendc::PlatformAscendC(context->GetPlatformInfo());
    const uint32_t aivNum = ascendcPlatform.GetCoreNumAiv();
    OP_TILING_CHECK(aivNum == 0, OP_LOGE(context->GetNodeName(), "no AIV core available"),
        return ge::GRAPH_FAILED);

    // num_vec_cores == 0 keeps the platform AIV count; see dispatch_send.
    const int64_t numVecCoresValue = ReadIntAttr(context, 12U, 0);
    OP_TILING_CHECK(numVecCoresValue < 0 ||
        numVecCoresValue > static_cast<int64_t>(aivNum),
        OP_LOGE(context->GetNodeName(), "combine_send num_vec_cores exceeds the AIV count"),
        return ge::GRAPH_FAILED);
    const uint32_t numVecCores = numVecCoresValue == 0 ?
        aivNum : static_cast<uint32_t>(numVecCoresValue);

    uint64_t ubSize = 0;
    ascendcPlatform.GetCoreMemSize(platform_ascendc::CoreMemType::UB, ubSize);
    const uint32_t dynUbSize = ubSize > 32768U ?
        static_cast<uint32_t>(ubSize) - 32768U : static_cast<uint32_t>(ubSize);
    OP_TILING_CHECK(dynUbSize < kCombineSendUbBytes,
        OP_LOGE(context->GetNodeName(), "combine_send UB layout exceeds the dynamic UB window"),
        return ge::GRAPH_FAILED);
    tiling->blockDim = numVecCores;
    tiling->numVecCores = numVecCores;
    // The SIMT vector functions address UB through the launch-time dynamic UB
    // window: with the attribute unset only a few KiB are visible, so a VF
    // that touches a routing array past it traps as aivec 341 no matter
    // the layout. Request all but 32 KiB of the vector buffer; the rest
    // covers the static shared-memory reserve the launcher adds on top.
    (void)context->SetDynUBufSize(dynUbSize);
    tiling->numUbBytes = dynUbSize;
    return ge::GRAPH_SUCCESS;
}

static ge::graphStatus TilingFunc(gert::TilingContext* context)
{
    auto* tiling = context->GetTilingData<CombineSendTiling>();
    OP_TILING_CHECK(tiling == nullptr, OP_LOGE(context->GetNodeName(), "tiling data is null"),
        return ge::GRAPH_FAILED);
    CombineSendTiling pending{};
    if (ReadCombineSendAttrs(context, &pending) != ge::GRAPH_SUCCESS ||
        SetCombineSendShape(context, &pending) != ge::GRAPH_SUCCESS ||
        SetCombineSendResources(context, &pending) != ge::GRAPH_SUCCESS) {
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
    // Completion is a fixed-size byte blob; its exact layout is the AFD ABI
    // (AFDCompletion per lane), so the shape is caller-driven via the attr.
    int64_t completionBytes = kDefaultCompletionBytes;
    auto attrs = context->GetAttrs();
    if (attrs != nullptr) {
        const int64_t* value = attrs->GetInt(11U);
        if (value != nullptr && *value > 0) {
            completionBytes = *value;
        }
    }
    gert::Shape* yShape = context->GetOutputShape(0);
    yShape->SetDimNum(1);
    yShape->SetDim(0, completionBytes);
    return GRAPH_SUCCESS;
}

static ge::graphStatus InferDataType(gert::InferDataTypeContext* context)
{
    context->SetOutputDataType(0, ge::DT_UINT8);
    return GRAPH_SUCCESS;
}
}  // namespace ge

namespace ops {
class AfdAsyncCombineSend : public OpDef {
public:
    explicit AfdAsyncCombineSend(const char* name) : OpDef(name)
    {
        RequiredAfdNdTensor(this->Input("x"), ge::DT_BF16);
        RequiredAfdNdTensor(this->Input("src_metadata"), ge::DT_INT32);
        // AFD control plane: context is immutable during a round. Control and
        // execution advance in place, as does the optional Active trailer.
        RequiredAfdNdTensor(this->Input("context"), ge::DT_UINT8);
        RequiredAfdNdTensor(this->Input("active"), ge::DT_UINT8);
        RequiredAfdNdTensor(this->Input("control_buffer"), ge::DT_UINT8);
        RequiredAfdNdTensor(this->Input("execution_state"), ge::DT_UINT8);
        RequiredAfdNdTensor(this->Input("workspace"), ge::DT_UINT8);
        RequiredAfdNdTensor(this->Input("jetty_ptrs"), ge::DT_INT64);

        RequiredAfdNdTensor(this->Output("completion"), ge::DT_UINT8);

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
        this->Attr("num_src_ranks").Int();
        this->Attr("num_ranks").Int();
        this->Attr("num_experts").Int();
        this->Attr("num_topk").Int();
        this->Attr("num_source_lanes").Int();
        this->Attr("num_layers").Int();
        this->Attr("max_padded_tokens").Int();
        this->Attr("num_tokens_per_tile").Int();
        this->Attr("rank_idx").Int();
        this->Attr("timeout_cycles").Int();
        this->Attr("completion_bytes").Int();
        this->Attr("num_vec_cores").Int();
    }
};
OP_ADD(AfdAsyncCombineSend);
}  // namespace ops
