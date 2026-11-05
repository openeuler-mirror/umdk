/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2026-2026. All rights reserved.
 * Description: cam_deepep_combine_recv operator definition and tiling
 * Create: 2026-11-03
 * Note: model-dependent sizes are read at tiling time and passed as runtime
 *       fields; the tiling key stays constant. round_step/start are attrs
 *       so single-round and multi-round correctness share one binary.
 * History: 2026-11-03 create runtime parameter port;
 *          2026-11-03 real tensor interface (payload/ledger tensors, outputs)
 */

#include "../op_kernel/cam_deepep_combine_recv_tiling.h"
#include "register/op_def_registry.h"
#include "tiling/platform/platform_ascendc.h"
#include "error_log.h"

namespace {
constexpr uint32_t kDefaultNumExperts = 16;
constexpr uint32_t kDefaultNumRanks = 2;
constexpr uint32_t kDefaultNumTopk = 6;
constexpr uint32_t kDefaultNumHidden = 3584;
constexpr uint32_t kDefaultTokenCapacity = 4096;
constexpr uint32_t kDefaultRecvStatusWords = 8;
constexpr uint32_t kDefaultReturnProgressBytes = 64;
constexpr uint32_t kMaxNumRanks = 256;
constexpr uint32_t kMaxNumExperts = 2048;
constexpr uint32_t kMaxNumTopk = 32;
constexpr uint32_t kMaxHiddenChunk = 8192;
constexpr uint32_t kMaxTokenCapacity = 32768;
constexpr uint32_t kMaxStatusWords = 4096;
constexpr uint32_t kMaxReturnProgressBytes = 65536;
constexpr uint64_t kDefaultTimeoutCycles = 1000000000;
// Cam mirrors the static device view CombineRecvUBRT (address 0):
// 2*8192 bf16 stages + 2*8192 fp32 accumulators + 8192 bf16 output + weights +
// expert ids + ledger + control stages.
constexpr uint64_t kCombineRecvUbBytes = 2uLL * 8192uLL * 2uLL + 2uLL * 8192uLL * 4uLL +
    8192uLL * 2uLL + 32uLL * 4uLL + 32uLL * 8uLL + 64uLL + 64uLL + 128uLL;
// Rank of the tiled outputs and their positions in the OpDef output list.
constexpr size_t kOutputRank = 2;
constexpr size_t kVectorRank = 1;
constexpr size_t kOutputCombinedX = 0;
constexpr size_t kOutputTopkIdx = 1;
constexpr size_t kOutputTopkWeights = 2;
constexpr size_t kOutputRecvStatus = 3;
constexpr size_t kOutputReturnProgress = 4;

uint64_t Align32(uint64_t v)
{
    return (v + 31uLL) & ~31uLL;
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
    return value == nullptr ? fallback : *value;
}
}  // namespace

namespace optiling {
static ge::graphStatus TilingFunc(gert::TilingContext* context)
{
    Cam::CamDeepepCombineRecvTilingData* tiling =
        context->GetTilingData<Cam::CamDeepepCombineRecvTilingData>();
    OP_TILING_CHECK(tiling == nullptr, OP_LOGE(context->GetNodeName(), "tiling data is null"),
        return ge::GRAPH_FAILED);

    // Attr order follows the OpDef below: group_ep, num_experts, num_ranks,
    // num_topk, round_step, start, num_hidden, num_token_capacity,
    // recv_status_words, return_progress_bytes, timeout_cycles.
    const int64_t numExpertsValue = ReadIntAttr(context, 1U, kDefaultNumExperts);
    const int64_t numRanksValue = ReadIntAttr(context, 2U, kDefaultNumRanks);
    const int64_t numTopkValue = ReadIntAttr(context, 3U, kDefaultNumTopk);
    const int64_t roundStepValue = ReadIntAttr(context, 4U, 0);
    const int64_t startValue = ReadIntAttr(context, 5U, 0);
    const int64_t numHiddenValue = ReadIntAttr(context, 6U, kDefaultNumHidden);
    const int64_t tokenCapacityValue = ReadIntAttr(context, 7U, kDefaultTokenCapacity);
    const int64_t recvStatusWordsValue =
        ReadIntAttr(context, 8U, static_cast<int64_t>(kDefaultRecvStatusWords));
    const int64_t returnProgressBytesValue =
        ReadIntAttr(context, 9U, static_cast<int64_t>(kDefaultReturnProgressBytes));
    const int64_t timeoutCyclesValue =
        ReadIntAttr(context, 10U, static_cast<int64_t>(kDefaultTimeoutCycles));

    // Domain check on the int64 values, before any narrowing. The two mode
    // flags are booleans: the old reader folded any nonzero value into 1.
    OP_TILING_CHECK(roundStepValue != 0 && roundStepValue != 1,
        OP_LOGE(context->GetNodeName(), "combine_recv round_step must be 0 or 1"),
        return ge::GRAPH_FAILED);
    OP_TILING_CHECK(startValue != 0 && startValue != 1,
        OP_LOGE(context->GetNodeName(), "combine_recv start must be 0 or 1"),
        return ge::GRAPH_FAILED);
    OP_TILING_CHECK(numExpertsValue <= 0 || numExpertsValue > static_cast<int64_t>(kMaxNumExperts) ||
        numRanksValue <= 0 || numRanksValue > static_cast<int64_t>(kMaxNumRanks) ||
        numTopkValue <= 0 || numTopkValue > static_cast<int64_t>(kMaxNumTopk) ||
        numHiddenValue <= 0 || numHiddenValue > static_cast<int64_t>(kMaxHiddenChunk) ||
        numHiddenValue % 128 != 0 ||
        tokenCapacityValue <= 0 ||
        tokenCapacityValue > static_cast<int64_t>(kMaxTokenCapacity) ||
        recvStatusWordsValue <= 0 || recvStatusWordsValue > static_cast<int64_t>(kMaxStatusWords) ||
        returnProgressBytesValue < 0 ||
        returnProgressBytesValue > static_cast<int64_t>(kMaxReturnProgressBytes) ||
        timeoutCyclesValue <= 0,
        OP_LOGE(context->GetNodeName(), "combine_recv shape out of support domain"),
        return ge::GRAPH_FAILED);

    const uint32_t numExperts = static_cast<uint32_t>(numExpertsValue);
    const uint32_t numRanks = static_cast<uint32_t>(numRanksValue);
    const uint32_t numTopk = static_cast<uint32_t>(numTopkValue);
    const uint32_t numHidden = static_cast<uint32_t>(numHiddenValue);
    const uint32_t tokenCapacity = static_cast<uint32_t>(tokenCapacityValue);
    const uint32_t roundStep = static_cast<uint32_t>(roundStepValue);
    const uint32_t start = static_cast<uint32_t>(startValue);

    auto ascendcPlatform = platform_ascendc::PlatformAscendC(context->GetPlatformInfo());
    const uint32_t aivNum = ascendcPlatform.GetCoreNumAiv();
    OP_TILING_CHECK(aivNum == 0, OP_LOGE(context->GetNodeName(), "no AIV core available"),
        return ge::GRAPH_FAILED);

    // num_vec_cores == 0 keeps the platform AIV count; see dispatch_send.
    const int64_t numVecCoresValue = ReadIntAttr(context, 11U, 0);
    OP_TILING_CHECK(numVecCoresValue < 0 ||
        numVecCoresValue > static_cast<int64_t>(aivNum),
        OP_LOGE(context->GetNodeName(), "combine_recv num_vec_cores exceeds the AIV count"),
        return ge::GRAPH_FAILED);
    const uint32_t numVecCores = numVecCoresValue == 0 ?
        aivNum : static_cast<uint32_t>(numVecCoresValue);

    uint64_t ubSize = 0;
    ascendcPlatform.GetCoreMemSize(platform_ascendc::CoreMemType::UB, ubSize);
    OP_TILING_CHECK(ubSize < kCombineRecvUbBytes,
        OP_LOGE(context->GetNodeName(), "combine_recv UB layout exceeds available UB"),
        return ge::GRAPH_FAILED);

    // Production formula: fixed = align32(4K) + align32(8K) + 256, and the
    // per-element budget is 14 B (two bf16 stages, two fp32 accumulators, one
    // bf16 output). Clamp to the static view so the address-0 struct matches.
    const uint64_t fixed = Align32(4uLL * numTopk) + Align32(8uLL * numTopk) + 256uLL;
    uint64_t chunk = ubSize > fixed ? (ubSize - fixed) / 14uLL : 0uLL;
    if (chunk > numHidden) {
        chunk = numHidden;
    }
    chunk = chunk / 128uLL * 128uLL;
    OP_TILING_CHECK(chunk == 0 || chunk > kMaxHiddenChunk,
        OP_LOGE(context->GetNodeName(), "combine_recv hidden chunk is outside the support domain"),
        return ge::GRAPH_FAILED);

    tiling->blockDim = numVecCores;
    tiling->numExperts = numExperts;
    tiling->numRanks = numRanks;
    tiling->numTopk = numTopk;
    tiling->numHidden = numHidden;
    tiling->numHiddenChunk = static_cast<uint32_t>(chunk);
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
    tiling->roundStep = roundStep;
    tiling->start = start;
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
    auto attrs = context->GetAttrs();
    int64_t numTopk = kDefaultNumTopk;
    int64_t numHidden = kDefaultNumHidden;
    int64_t tokenCapacity = kDefaultTokenCapacity;
    int64_t recvStatusWords = kDefaultRecvStatusWords;
    int64_t returnProgressBytes = kDefaultReturnProgressBytes;
    if (attrs != nullptr) {
        const int64_t* topk = attrs->GetInt(3U);
        const int64_t* hidden = attrs->GetInt(6U);
        const int64_t* capacity = attrs->GetInt(7U);
        const int64_t* words = attrs->GetInt(8U);
        const int64_t* progress = attrs->GetInt(9U);
        if (topk != nullptr && *topk > 0) {
            numTopk = *topk;
        }
        if (hidden != nullptr && *hidden > 0) {
            numHidden = *hidden;
        }
        if (capacity != nullptr && *capacity > 0) {
            tokenCapacity = *capacity;
        }
        if (words != nullptr && *words > 0) {
            recvStatusWords = *words;
        }
        // 0 is valid: single-round mode allocates no progress output.
        if (progress != nullptr && *progress >= 0) {
            returnProgressBytes = *progress;
        }
    }

    gert::Shape* xShape = context->GetOutputShape(kOutputCombinedX);
    xShape->SetDimNum(kOutputRank);
    xShape->SetDim(0, tokenCapacity);
    xShape->SetDim(1, numHidden);

    gert::Shape* idxShape = context->GetOutputShape(kOutputTopkIdx);
    idxShape->SetDimNum(kOutputRank);
    idxShape->SetDim(0, tokenCapacity);
    idxShape->SetDim(1, numTopk);

    gert::Shape* weightShape = context->GetOutputShape(kOutputTopkWeights);
    weightShape->SetDimNum(kOutputRank);
    weightShape->SetDim(0, tokenCapacity);
    weightShape->SetDim(1, numTopk);

    gert::Shape* statusShape = context->GetOutputShape(kOutputRecvStatus);
    statusShape->SetDimNum(kVectorRank);
    statusShape->SetDim(0, recvStatusWords);

    gert::Shape* progressShape = context->GetOutputShape(kOutputReturnProgress);
    progressShape->SetDimNum(kVectorRank);
    progressShape->SetDim(0, returnProgressBytes);
    return GRAPH_SUCCESS;
}

static ge::graphStatus InferDataType(gert::InferDataTypeContext* context)
{
    context->SetOutputDataType(kOutputCombinedX, ge::DT_BF16);
    context->SetOutputDataType(kOutputTopkIdx, ge::DT_INT64);
    context->SetOutputDataType(kOutputTopkWeights, ge::DT_FLOAT);
    context->SetOutputDataType(kOutputRecvStatus, ge::DT_INT32);
    context->SetOutputDataType(kOutputReturnProgress, ge::DT_UINT8);
    return GRAPH_SUCCESS;
}
}  // namespace ge

namespace ops {
class CamDeepepCombineRecv : public OpDef {
public:
    explicit CamDeepepCombineRecv(const char* name) : OpDef(name)
    {
        // Inbound payload plus the AFD control plane. control_buffer and
        // round_ledger are advanced in place, mirroring the production contract.
        this->Input("payload")
            .ParamType(REQUIRED)
            .DataType({ge::DT_UINT8})
            .Format({ge::FORMAT_ND})
            .UnknownShapeFormat({ge::FORMAT_ND});
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
        this->Input("token_mask")
            .ParamType(REQUIRED)
            .DataType({ge::DT_BOOL})
            .Format({ge::FORMAT_ND})
            .UnknownShapeFormat({ge::FORMAT_ND});

        this->Output("combined_x")
            .ParamType(REQUIRED)
            .DataType({ge::DT_BF16})
            .Format({ge::FORMAT_ND})
            .UnknownShapeFormat({ge::FORMAT_ND});
        this->Output("combined_topk_idx")
            .ParamType(REQUIRED)
            .DataType({ge::DT_INT64})
            .Format({ge::FORMAT_ND})
            .UnknownShapeFormat({ge::FORMAT_ND});
        this->Output("topk_weights")
            .ParamType(REQUIRED)
            .DataType({ge::DT_FLOAT})
            .Format({ge::FORMAT_ND})
            .UnknownShapeFormat({ge::FORMAT_ND});
        this->Output("recv_status")
            .ParamType(REQUIRED)
            .DataType({ge::DT_INT32})
            .Format({ge::FORMAT_ND})
            .UnknownShapeFormat({ge::FORMAT_ND});
        this->Output("return_progress")
            .ParamType(REQUIRED)
            .DataType({ge::DT_UINT8})
            .Format({ge::FORMAT_ND})
            .UnknownShapeFormat({ge::FORMAT_ND});

        this->Attr("group_ep").String();
        this->Attr("num_experts").Int();
        this->Attr("num_ranks").Int();
        this->Attr("num_topk").Int();
        this->Attr("round_step").Int();
        this->Attr("start").Int();
        this->Attr("num_hidden").Int();
        this->Attr("num_token_capacity").Int();
        this->Attr("recv_status_words").Int();
        this->Attr("return_progress_bytes").Int();
        this->Attr("timeout_cycles").Int();
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
OP_ADD(CamDeepepCombineRecv);
}  // namespace ops
