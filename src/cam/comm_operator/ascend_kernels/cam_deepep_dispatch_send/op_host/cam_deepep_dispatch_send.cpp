/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2026-2026. All rights reserved.
 * Description: cam_deepep_dispatch_send operator definition and tiling
 * Create: 2026-11-03
 * Note: AFD control-plane objects are tensors; model-dependent sizes are
 *       runtime tiling fields. The tiling key stays 0.
 * History: 2026-11-03 create probe shell; 2026-11-03 runtime tiling fields;
 *          2026-11-03 real tensor interface (AFD pointers -> tensors/attrs)
 */

#include "../op_kernel/cam_deepep_dispatch_send_tiling.h"
#include "register/op_def_registry.h"
#include "tiling/platform/platform_ascendc.h"
#include "error_log.h"

namespace {
constexpr uint32_t kDefaultNumRanks = 2;
constexpr uint32_t kDefaultNumExperts = 16;
constexpr uint32_t kDefaultNumTopk = 8;
constexpr uint32_t kDefaultNumTokensPerTile = 16;
constexpr uint32_t kDefaultNumHiddenBytes = 128;
constexpr uint32_t kMaxNumRanks = 256;
constexpr uint32_t kMaxNumExperts = 2048;
constexpr uint32_t kMaxNumTopk = 32;
constexpr uint32_t kMaxHiddenBytes = 16384;
constexpr uint32_t kDefaultSendStatusWords = 8;
constexpr int64_t kDefaultTimeoutCycles = 1000000000;
constexpr int64_t kMaxTokensPerTile = 32768;
constexpr int64_t kMaxStatusWords = 4096;
constexpr int64_t kMaxInt32 = 2147483647;
// The payload is bf16, so one hidden element occupies two bytes.
constexpr uint32_t kBytesPerHiddenElement = 2;

// Attributes reach tiling as int64. Read the full value and let the caller
// check the domain before narrowing: the old order narrowed first, so a
// negative or > UINT32_MAX value silently became a plausible small number and
// reached the kernel instead of being rejected.
int64_t ReadIntAttrOr(const gert::TilingContext* context, size_t idx, int64_t fallback)
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
    Cam::CamDeepepDispatchSendTilingData* tiling =
        context->GetTilingData<Cam::CamDeepepDispatchSendTilingData>();
    OP_TILING_CHECK(tiling == nullptr, OP_LOGE(context->GetNodeName(), "tiling data is null"),
        return ge::GRAPH_FAILED);

    // Attr order follows the OpDef below: group_ep, num_ranks, num_experts,
    // num_topk, num_tokens_per_tile, sf_token_stride, sf_hidden_stride,
    // num_sf_packs, timeout_cycles, send_status_words, num_vec_cores.
    const int64_t numRanksValue = ReadIntAttrOr(context, 1U, kDefaultNumRanks);
    const int64_t numExpertsValue = ReadIntAttrOr(context, 2U, kDefaultNumExperts);
    const int64_t numTopkValue = ReadIntAttrOr(context, 3U, kDefaultNumTopk);
    const int64_t numTokensPerTileValue = ReadIntAttrOr(context, 4U, kDefaultNumTokensPerTile);
    const int64_t sfTokenStride = ReadIntAttrOr(context, 5U, 0);
    const int64_t sfHiddenStride = ReadIntAttrOr(context, 6U, 0);
    const int64_t numSFPacksValue = ReadIntAttrOr(context, 7U, 0);
    const int64_t timeoutCyclesValue = ReadIntAttrOr(context, 8U, kDefaultTimeoutCycles);
    const int64_t sendStatusWordsValue = ReadIntAttrOr(context, 9U, kDefaultSendStatusWords);

    // Domain check on the int64 values. The divisibility test is safe because
    // the rank bounds are evaluated first and short-circuit the expression.
    OP_TILING_CHECK(numRanksValue <= 0 || numRanksValue > static_cast<int64_t>(kMaxNumRanks) ||
        numExpertsValue <= 0 || numExpertsValue > static_cast<int64_t>(kMaxNumExperts) ||
        numExpertsValue % numRanksValue != 0 ||
        numTopkValue <= 0 || numTopkValue > static_cast<int64_t>(kMaxNumTopk) ||
        numTokensPerTileValue <= 0 || numTokensPerTileValue > kMaxTokensPerTile ||
        numSFPacksValue < 0 || numSFPacksValue > static_cast<int64_t>(kMaxNumExperts) ||
        sfTokenStride < 0 || sfTokenStride > kMaxInt32 ||
        sfHiddenStride < 0 || sfHiddenStride > kMaxInt32 ||
        timeoutCyclesValue <= 0 ||
        sendStatusWordsValue <= 0 || sendStatusWordsValue > kMaxStatusWords,
        OP_LOGE(context->GetNodeName(),
            "dispatch_send attrs out of support domain: num_ranks=%lld num_experts=%lld "
            "num_topk=%lld num_tokens_per_tile=%lld num_sf_packs=%lld sf_token_stride=%lld "
            "sf_hidden_stride=%lld timeout_cycles=%lld send_status_words=%lld",
            static_cast<long long>(numRanksValue), static_cast<long long>(numExpertsValue),
            static_cast<long long>(numTopkValue), static_cast<long long>(numTokensPerTileValue),
            static_cast<long long>(numSFPacksValue), static_cast<long long>(sfTokenStride),
            static_cast<long long>(sfHiddenStride), static_cast<long long>(timeoutCyclesValue),
            static_cast<long long>(sendStatusWordsValue)),
        return ge::GRAPH_FAILED);

    const uint32_t numRanks = static_cast<uint32_t>(numRanksValue);
    const uint32_t numExperts = static_cast<uint32_t>(numExpertsValue);
    const uint32_t numTopk = static_cast<uint32_t>(numTopkValue);
    const uint32_t numTokensPerTile = static_cast<uint32_t>(numTokensPerTileValue);
    const uint32_t numSFPacks = static_cast<uint32_t>(numSFPacksValue);
    const uint64_t timeoutCycles = static_cast<uint64_t>(timeoutCyclesValue);
    const uint32_t sendStatusWords = static_cast<uint32_t>(sendStatusWordsValue);

    auto ascendcPlatform = platform_ascendc::PlatformAscendC(context->GetPlatformInfo());
    const uint32_t aivNum = ascendcPlatform.GetCoreNumAiv();
    OP_TILING_CHECK(aivNum == 0, OP_LOGE(context->GetNodeName(), "no AIV core available"),
        return ge::GRAPH_FAILED);

    // num_vec_cores == 0 keeps the platform AIV count. The AFD context records
    // the value its buffers were sized for, so a caller that shares those
    // buffers (test harness) must pin this to the same number; callers
    // that coexist with another kernel on a second stream can reserve cores.
    const int64_t numVecCoresValue = ReadIntAttrOr(context, 10U, 0);
    OP_TILING_CHECK(numVecCoresValue < 0 ||
        numVecCoresValue > static_cast<int64_t>(aivNum),
        OP_LOGE(context->GetNodeName(), "dispatch_send num_vec_cores exceeds the AIV count"),
        return ge::GRAPH_FAILED);
    const uint32_t numVecCores = numVecCoresValue == 0 ?
        aivNum : static_cast<uint32_t>(numVecCoresValue);

    uint64_t ubSize = 0;
    ascendcPlatform.GetCoreMemSize(platform_ascendc::CoreMemType::UB, ubSize);

    // hidden is a tensor dimension, not an attr: bf16 -> 2 bytes per element.
    uint32_t numHiddenBytes = kDefaultNumHiddenBytes;
    const gert::StorageShape* xShape = context->GetInputShape(0);
    OP_TILING_CHECK(xShape == nullptr,
        OP_LOGE(context->GetNodeName(), "dispatch_send x shape is null"),
        return ge::GRAPH_FAILED);
    const gert::Shape& xDims = xShape->GetStorageShape();
    if (xDims.GetDimNum() >= 1) {
        const int64_t hidden = xDims.GetDim(xDims.GetDimNum() - 1);
        if (hidden > 0 &&
            hidden <= static_cast<int64_t>(kMaxHiddenBytes / kBytesPerHiddenElement)) {
            numHiddenBytes = static_cast<uint32_t>(hidden) * kBytesPerHiddenElement;
        }
    }
    OP_TILING_CHECK(numHiddenBytes == 0 || numHiddenBytes > kMaxHiddenBytes,
        OP_LOGE(context->GetNodeName(), "dispatch_send hidden is outside the support domain"),
        return ge::GRAPH_FAILED);

    tiling->blockDim = numVecCores;
    tiling->numRanks = numRanks;
    tiling->numExperts = numExperts;
    tiling->expertsPerRank = numExperts / numRanks;
    tiling->numTopk = numTopk;
    tiling->numTokensPerTile = numTokensPerTile;
    tiling->numVecCores = numVecCores;
    tiling->numHiddenBytes = numHiddenBytes;
    tiling->numSFPacks = numSFPacks;
    // The SIMT vector functions address UB through the launch-time dynamic UB
    // window: with the attribute unset only a few KiB are visible, so a VF
    // that touches a routing array past it traps as aivec 341 no matter
    // the layout. Request all but 32 KiB of the vector buffer; the rest
    // covers the static shared-memory reserve the launcher adds on top.
    const uint32_t dynUbSize = ubSize > 32768U ?
        static_cast<uint32_t>(ubSize) - 32768U : static_cast<uint32_t>(ubSize);
    (void)context->SetDynUBufSize(dynUbSize);
    tiling->numUbBytes = static_cast<uint32_t>(ubSize);
    tiling->timeoutCycles = timeoutCycles;
    tiling->sfTokenStride = static_cast<int32_t>(sfTokenStride);
    tiling->sfHiddenStride = static_cast<int32_t>(sfHiddenStride);
    tiling->sendStatusWords = sendStatusWords;
    tiling->reserved = 0U;

    context->SetBlockDim(numVecCores);
    return ge::GRAPH_SUCCESS;
}
}  // namespace optiling

namespace ge {
static ge::graphStatus InferShape(gert::InferShapeContext* context)
{
    // Output: send_status words. Fallback keeps the default shape when the attr
    // is absent (hand-built graphs).
    int64_t words = kDefaultSendStatusWords;
    auto attrs = context->GetAttrs();
    if (attrs != nullptr) {
        const int64_t* value = attrs->GetInt(9U);
        if (value != nullptr && *value > 0) {
            words = *value;
        }
    }
    gert::Shape* yShape = context->GetOutputShape(0);
    yShape->SetDimNum(1);
    yShape->SetDim(0, words);
    return GRAPH_SUCCESS;
}

static ge::graphStatus InferDataType(gert::InferDataTypeContext* context)
{
    context->SetOutputDataType(0, ge::DT_INT32);
    return GRAPH_SUCCESS;
}
}  // namespace ge

namespace ops {
class CamDeepepDispatchSend : public OpDef {
public:
    explicit CamDeepepDispatchSend(const char* name) : OpDef(name)
    {
        // Payload and metadata inputs.
        this->Input("x")
            .ParamType(REQUIRED)
            .DataType({ge::DT_BF16})
            .Format({ge::FORMAT_ND})
            .UnknownShapeFormat({ge::FORMAT_ND});
        this->Input("sf")
            .ParamType(REQUIRED)
            .DataType({ge::DT_INT16})
            .Format({ge::FORMAT_ND})
            .UnknownShapeFormat({ge::FORMAT_ND});
        this->Input("topk_idx")
            .ParamType(REQUIRED)
            .DataType({ge::DT_INT64})
            .Format({ge::FORMAT_ND})
            .UnknownShapeFormat({ge::FORMAT_ND});
        this->Input("topk_weights")
            .ParamType(REQUIRED)
            .DataType({ge::DT_FLOAT})
            .Format({ge::FORMAT_ND})
            .UnknownShapeFormat({ge::FORMAT_ND});
        this->Input("token_mask")
            .ParamType(REQUIRED)
            .DataType({ge::DT_BOOL})
            .Format({ge::FORMAT_ND})
            .UnknownShapeFormat({ge::FORMAT_ND});
        // AFD control plane.
        this->Input("task_info")
            .ParamType(REQUIRED)
            .DataType({ge::DT_UINT8})
            .Format({ge::FORMAT_ND})
            .UnknownShapeFormat({ge::FORMAT_ND});
        this->Input("context")
            .ParamType(REQUIRED)
            .DataType({ge::DT_UINT8})
            .Format({ge::FORMAT_ND})
            .UnknownShapeFormat({ge::FORMAT_ND});
        this->Input("control_buffer")
            .ParamType(REQUIRED)
            .DataType({ge::DT_UINT8})
            .Format({ge::FORMAT_ND})
            .UnknownShapeFormat({ge::FORMAT_ND});
        this->Input("round_ledger")
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

        this->Output("send_status")
            .ParamType(REQUIRED)
            .DataType({ge::DT_INT32})
            .Format({ge::FORMAT_ND})
            .UnknownShapeFormat({ge::FORMAT_ND});

        this->Attr("group_ep").String();
        this->Attr("num_ranks").Int();
        this->Attr("num_experts").Int();
        this->Attr("num_topk").Int();
        this->Attr("num_tokens_per_tile").Int();
        this->Attr("sf_token_stride").Int();
        this->Attr("sf_hidden_stride").Int();
        this->Attr("num_sf_packs").Int();
        this->Attr("timeout_cycles").Int();
        this->Attr("send_status_words").Int();
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
OP_ADD(CamDeepepDispatchSend);
}  // namespace ops
