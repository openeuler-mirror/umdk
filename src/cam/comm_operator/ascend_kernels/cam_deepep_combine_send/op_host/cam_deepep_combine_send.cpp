/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2026-2026. All rights reserved.
 * Description: cam_deepep_combine_send operator definition and tiling
 * Create: 2026-11-03
 * Note: model-dependent sizes are read at tiling time and passed as runtime
 *       fields; the tiling key stays constant. max_padded_tokens is the physical
 *       row budget (q_alloc) of the matching dispatch_recv receive buffer and
 *       must be the same value for the whole transaction.
 * History: 2026-11-03 create runtime parameter port;
 *          2026-11-03 real tensor interface (completion output, rank/limits);
 *          2026-11-04 document the max_padded_tokens contract
 */

#include "../op_kernel/cam_deepep_combine_send_tiling.h"
#include "register/op_def_registry.h"
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
constexpr uint32_t kMaxNumTopk = 32;
constexpr uint32_t kMaxNumSourceLanes = 256;
constexpr uint32_t kMaxNumLayers = 64;
constexpr uint32_t kMaxTokensPerTile = 128;
constexpr uint32_t kMaxLaneTokens = 32768;
constexpr uint32_t kMaxNumHidden = 8192;
constexpr uint32_t kMaxCompletionBytes = 65536;
constexpr uint64_t kDefaultTimeoutCycles = 1000000000;
// Cam mirrors the static device view CombineSendUBRT (ABI maxima, address 0):
// 48*256 peer infos + 96*256 jetty info + 512 SQE + 2*128*16 metadata +
// 2*256*4 lane maps + 256 control.
constexpr uint64_t kCombineSendUbBytes = 48uLL * 256uLL + 96uLL * 256uLL + 512uLL +
    2uLL * 128uLL * 4uLL * 4uLL + 2uLL * 256uLL * 4uLL + 256uLL;

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
}  // namespace

namespace optiling {
static ge::graphStatus TilingFunc(gert::TilingContext* context)
{
    Cam::CamDeepepCombineSendTilingData* tiling =
        context->GetTilingData<Cam::CamDeepepCombineSendTilingData>();
    OP_TILING_CHECK(tiling == nullptr, OP_LOGE(context->GetNodeName(), "tiling data is null"),
        return ge::GRAPH_FAILED);

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

    // Domain check on the int64 values, before any narrowing. The divisibility
    // and per-rank tests are safe because the rank bounds come first.
    OP_TILING_CHECK(numSrcRanksValue <= 0 || numSrcRanksValue > static_cast<int64_t>(kMaxNumRanks) ||
        numRanksValue <= 0 || numRanksValue > static_cast<int64_t>(kMaxNumRanks) ||
        numExpertsValue <= 0 || numExpertsValue > static_cast<int64_t>(kMaxNumExperts) ||
        numExpertsValue % numRanksValue != 0 || numExpertsValue / numRanksValue > 512 ||
        numTopkValue <= 0 || numTopkValue > static_cast<int64_t>(kMaxNumTopk) ||
        numSourceLanesValue <= 0 ||
        numSourceLanesValue > static_cast<int64_t>(kMaxNumSourceLanes) ||
        numLayersValue <= 0 || numLayersValue > static_cast<int64_t>(kMaxNumLayers) ||
        maxPaddedTokensValue <= 0 || maxPaddedTokensValue > static_cast<int64_t>(kMaxLaneTokens) ||
        numTokensPerTileValue <= 0 || numTokensPerTileValue > static_cast<int64_t>(kMaxTokensPerTile) ||
        rankIdxValue < 0 || rankIdxValue >= numRanksValue ||
        timeoutCyclesValue <= 0 ||
        completionBytesValue <= 0 ||
        completionBytesValue > static_cast<int64_t>(kMaxCompletionBytes),
        OP_LOGE(context->GetNodeName(), "combine_send shape out of support domain"),
        return ge::GRAPH_FAILED);

    const uint32_t numSrcRanks = static_cast<uint32_t>(numSrcRanksValue);
    const uint32_t numRanks = static_cast<uint32_t>(numRanksValue);
    const uint32_t numExperts = static_cast<uint32_t>(numExpertsValue);
    const uint32_t numTopk = static_cast<uint32_t>(numTopkValue);
    const uint32_t numSourceLanes = static_cast<uint32_t>(numSourceLanesValue);
    const uint32_t numLayers = static_cast<uint32_t>(numLayersValue);
    const uint32_t maxPaddedTokens = static_cast<uint32_t>(maxPaddedTokensValue);
    const uint32_t numTokensPerTile = static_cast<uint32_t>(numTokensPerTileValue);

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
    OP_TILING_CHECK(ubSize < kCombineSendUbBytes,
        OP_LOGE(context->GetNodeName(), "combine_send UB layout exceeds available UB"),
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
    OP_TILING_CHECK(numHidden == 0 || numHidden > kMaxNumHidden,
        OP_LOGE(context->GetNodeName(), "combine_send hidden is outside the support domain"),
        return ge::GRAPH_FAILED);

    tiling->blockDim = numVecCores;
    tiling->numSrcRanks = numSrcRanks;
    tiling->numRanks = numRanks;
    tiling->expertsPerRank = numExperts / numRanks;
    tiling->numTopk = numTopk;
    tiling->numHidden = numHidden;
    tiling->numVecCores = numVecCores;
    tiling->numSourceLanes = numSourceLanes;
    tiling->numLayers = numLayers;
    tiling->maxPaddedTokens = maxPaddedTokens;
    tiling->numTokensPerTile = numTokensPerTile;
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
    tiling->timeoutCycles = static_cast<uint64_t>(timeoutCyclesValue);
    tiling->reserved[0] = 0U;
    tiling->reserved[1] = 0U;

    context->SetBlockDim(numVecCores);
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
class CamDeepepCombineSend : public OpDef {
public:
    explicit CamDeepepCombineSend(const char* name) : OpDef(name)
    {
        this->Input("x")
            .ParamType(REQUIRED)
            .DataType({ge::DT_BF16})
            .Format({ge::FORMAT_ND})
            .UnknownShapeFormat({ge::FORMAT_ND});
        this->Input("src_metadata")
            .ParamType(REQUIRED)
            .DataType({ge::DT_INT32})
            .Format({ge::FORMAT_ND})
            .UnknownShapeFormat({ge::FORMAT_ND});
        // AFD control plane: context is immutable during a round, while
        // control_buffer / execution_state are advanced in place.
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
        this->Input("control_buffer")
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
        this->Input("jetty_ptrs")
            .ParamType(REQUIRED)
            .DataType({ge::DT_INT64})
            .Format({ge::FORMAT_ND})
            .UnknownShapeFormat({ge::FORMAT_ND});

        this->Output("completion")
            .ParamType(REQUIRED)
            .DataType({ge::DT_UINT8})
            .Format({ge::FORMAT_ND})
            .UnknownShapeFormat({ge::FORMAT_ND});

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
OP_ADD(CamDeepepCombineSend);
}  // namespace ops
