/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2026-2026. All rights reserved.
 * Description: combine normal A2 host part tiling
 * Create: 2026-01-15
 * Note:
 * History: 2026-01-15 create combine normal A2 host part tiling
 */

#include <queue>
#include <vector>
#include <dlfcn.h>
#include <fcntl.h>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <sys/types.h>
#include <unistd.h>
#include <cmath>
#include <cstdint>
#include <string>

#include "register/tilingdata_base.h"
#include "tiling/tiling_api.h"
#include "ops_log.h"
#include "ops_error.h"
#include "graph/utils/type_utils.h"

#include "register/op_def_registry.h"
#include "tiling_args.h"
#include "mc2_tiling_utils.h"
#include "../op_kernel/moe_combine_normal_a2_tiling.h"

using namespace AscendC;
using namespace ge;
using namespace Moe;
namespace {
constexpr const char *OPS_UTILS_LOG_SUB_MOD_NAME = "MOE_COMBINE_NORMAL_A2";
constexpr const char *OPS_UTILS_LOG_PACKAGE_TYPE = "CAM_OPS";
constexpr uint32_t EXPAND_X_INDEX = 0;
constexpr uint32_t EXPERT_IDS_INDEX = 1;
constexpr uint32_t EXPAND_IDX_INDEX = 2;
constexpr uint32_t EP_SEND_COUNTS_INDEX = 3;
constexpr uint32_t EXPERT_SCALES_INDEX = 4;
constexpr uint32_t TP_SEND_COUNTS_INDEX = 5;
constexpr uint32_t X_ACTIVE_MASK_INDEX = 6;
constexpr uint32_t OUTPUT_X_INDEX = 0;

constexpr uint32_t ATTR_GROUP_EP_INDEX = 0;
constexpr uint32_t ATTR_EP_WORLD_SIZE_INDEX = 1;
constexpr uint32_t ATTR_EP_RANK_ID_INDEX = 2;
constexpr uint32_t ATTR_MOE_EXPERT_NUM_INDEX = 3;
constexpr uint32_t ATTR_GROUP_TP_INDEX = 4;
constexpr uint32_t ATTR_TP_WORLD_SIZE_INDEX = 5;
constexpr uint32_t ATTR_TP_RANK_ID_INDEX = 6;
constexpr uint32_t ATTR_EXPERT_SHARD_TYPE_INDEX = 7;
constexpr uint32_t ATTR_SHARED_EXPERT_NUM_INDEX = 8;
constexpr uint32_t ATTR_SHARED_EXPERT_RANK_NUM_INDEX = 9;
constexpr uint32_t ATTR_GLOBAL_BS_INDEX = 10;

constexpr uint32_t TWO_DIMS = 2U;
constexpr uint32_t ONE_DIM = 1U;
constexpr uint32_t EXPAND_IDX_DIMS = 1U;
constexpr uint64_t INIT_TILINGKEY_TP_2 = 1100UL;
constexpr uint64_t INIT_TILINGKEY_TP_1 = 1000UL;
constexpr uint64_t TILING_KEY_BASE_A2 = 2000UL;
constexpr uint64_t TILING_KEY_LAYERED_COMM_A2 = 3000UL;
constexpr uint32_t ARR_LENGTH = 128U;
constexpr uint32_t OP_TYPE_ALL_TO_ALL = 8U;      // numeric representation of AlltoAll
constexpr uint32_t OP_TYPE_REDUCE_SCATTER = 7U;  // numeric representation of AlltoAll

constexpr int32_t MAX_EP_WORLD_SIZE_A2 = 256;
constexpr int32_t MAX_MOE_EXPERT_NUMS_A2 = 512;
constexpr int32_t MAX_HIDDEN_SIZE_A2 = 7168;
constexpr uint32_t MAX_BATCH_SIZE_LAYERED_A2 = 4096;
constexpr uint32_t MAX_BATCH_SIZE_A2 = 256;
constexpr uint32_t RANK_NUM_PER_NODE_A2 = 8;
constexpr uint32_t BLOCK_SIZE_A2 = 32;
constexpr uint32_t MAX_K_VALUE_A2 = 8;
constexpr uint32_t MIN_K_VALUE_A2 = 2;
const char *K_INNER_DEBUG = "MoeDistributeCombine Tiling Debug";
const size_t MAX_GROUP_NAME_LENGTH = 128UL;
const int64_t MAX_EP_WORLD_SIZE = 288;
const int64_t MAX_TP_WORLD_SIZE = 2;
const int64_t BS_UPPER_BOUND = 4096;

constexpr uint32_t SYSTEM_NEED_WORKSPACE = 16 * 1024 * 1024;
constexpr int32_t HCCL_BUFFER_SIZE_DEFAULT = 200 * 1024 * 1024;  // Bytes
constexpr uint32_t VERSION_2 = 2;
constexpr uint32_t HCOMMCNT_2 = 2;
constexpr int64_t MOE_EXPERT_MAX_NUM = 512;
constexpr int64_t K_MAX = 8;
constexpr uint64_t MB_SIZE = 1024UL * 1024UL;
}  // namespace

namespace optiling {
static ge::graphStatus MoeCombineNormalA2CheckAttrAndSetTiling(const gert::TilingContext &context,
                                                               MoeCombineNormalA2Info &info)
{
    auto attrs = context.GetAttrs();
    OPS_ERR_IF(attrs == nullptr, OPS_LOG_E(K_INNER_DEBUG, "attrs is null."), return ge::GRAPH_FAILED);

    auto epWorldSizePtr = attrs->GetAttrPointer<int>(ATTR_EP_WORLD_SIZE_INDEX);
    auto epRankIdPtr = attrs->GetAttrPointer<int>(ATTR_EP_RANK_ID_INDEX);
    auto moeExpertNumPtr = attrs->GetAttrPointer<int>(ATTR_MOE_EXPERT_NUM_INDEX);
    auto tpWorldSizePtr = attrs->GetAttrPointer<int>(ATTR_TP_WORLD_SIZE_INDEX);
    auto tpRankIdPtr = attrs->GetAttrPointer<int>(ATTR_TP_RANK_ID_INDEX);
    auto expertSharedTypePtr = attrs->GetAttrPointer<int>(ATTR_EXPERT_SHARD_TYPE_INDEX);
    auto sharedExpertRankNumPtr = attrs->GetAttrPointer<int>(ATTR_SHARED_EXPERT_RANK_NUM_INDEX);
    auto globalBsPtr = attrs->GetAttrPointer<int>(ATTR_GLOBAL_BS_INDEX);

    OPS_ERR_IF(epWorldSizePtr == nullptr || *epWorldSizePtr <= 0 || *epWorldSizePtr > MAX_EP_WORLD_SIZE_A2 ||
                   *epWorldSizePtr % RANK_NUM_PER_NODE_A2 != 0,
               OPS_LOG_E(K_INNER_DEBUG, "epWorldSize is invalid."), return GRAPH_FAILED);
    OPS_ERR_IF(epRankIdPtr == nullptr || *epRankIdPtr < 0 || *epRankIdPtr >= *epWorldSizePtr,
               OPS_LOG_E(K_INNER_DEBUG, "epRankId is invalid."), return GRAPH_FAILED);
    OPS_ERR_IF(moeExpertNumPtr == nullptr || *moeExpertNumPtr <= 0 || *moeExpertNumPtr > MAX_MOE_EXPERT_NUMS_A2 ||
                   *moeExpertNumPtr % *epWorldSizePtr != 0,
               OPS_LOG_E(K_INNER_DEBUG, "moeExpertNum is invalid."), return GRAPH_FAILED);
    OPS_ERR_IF(tpWorldSizePtr == nullptr, OPS_LOG_E(K_INNER_DEBUG, "tpWorldSize is null."), return GRAPH_FAILED);
    OPS_ERR_IF(tpRankIdPtr == nullptr, OPS_LOG_E(K_INNER_DEBUG, "tpRankId is null."), return GRAPH_FAILED);
    OPS_ERR_IF(expertSharedTypePtr == nullptr, OPS_LOG_E(K_INNER_DEBUG, "expertSharedType is null."),
               return GRAPH_FAILED);
    OPS_ERR_IF(sharedExpertRankNumPtr == nullptr, OPS_LOG_E(K_INNER_DEBUG, "sharedExpertRankNum is null."),
               return GRAPH_FAILED);
    OPS_ERR_IF(globalBsPtr == nullptr, OPS_LOG_E(K_INNER_DEBUG, "globalBs is null."), return GRAPH_FAILED);

    const gert::StorageShape *expertIdStorageShape = context.GetInputShape(EXPERT_IDS_INDEX);
    OPS_ERR_IF(expertIdStorageShape == nullptr, OPS_LOG_E(K_INNER_DEBUG, "xShape is null."), return false);
    int32_t globalBs = *epWorldSizePtr * expertIdStorageShape->GetStorageShape().GetDim(0);

    info.epWorldSize = *epWorldSizePtr;
    info.tpWorldSize = static_cast<uint32_t>(0);
    info.epRankId = *epRankIdPtr;
    info.tpRankId = static_cast<uint32_t>(0);
    info.expertSharedType = static_cast<uint32_t>(0);
    info.sharedExpertRankNum = static_cast<uint32_t>(0);
    info.moeExpertNum = *moeExpertNumPtr;
    if (*globalBsPtr == 0) {
        info.globalBs = static_cast<uint32_t>(globalBs);
    } else {
        info.globalBs = *globalBsPtr;
    }

    OPS_LOG_D(K_INNER_DEBUG, "epWorldSize=%u", info.epWorldSize);
    OPS_LOG_D(K_INNER_DEBUG, "tpWorldSize=%u", info.tpWorldSize);
    OPS_LOG_D(K_INNER_DEBUG, "epRankId=%u", info.epRankId);
    OPS_LOG_D(K_INNER_DEBUG, "tpRankId=%u", info.tpRankId);
    OPS_LOG_D(K_INNER_DEBUG, "expertSharedType=%u", info.expertSharedType);
    OPS_LOG_D(K_INNER_DEBUG, "sharedExpertRankNum=%u", info.sharedExpertRankNum);
    OPS_LOG_D(K_INNER_DEBUG, "moeExpertNum=%u", info.moeExpertNum);
    OPS_LOG_D(K_INNER_DEBUG, "globalBs=%u", info.globalBs);

    return ge::GRAPH_SUCCESS;
}

static ge::graphStatus MoeCombineNormalA2CheckShapeAndSetTiling(const gert::TilingContext &context,
                                                                MoeCombineNormalA2Info &info,
                                                                const bool isLayered)
{
    const gert::StorageShape *expandXStorageShape = context.GetInputShape(EXPAND_X_INDEX);
    const gert::StorageShape *expertIdStorageShape = context.GetInputShape(EXPERT_IDS_INDEX);
    OPS_ERR_IF(expandXStorageShape == nullptr, OPS_LOG_E(K_INNER_DEBUG, "expandXShape is null."), return GRAPH_FAILED);
    OPS_ERR_IF(expertIdStorageShape == nullptr, OPS_LOG_E(K_INNER_DEBUG, "expertId is null."), return GRAPH_FAILED);

    OPS_ERR_IF(expandXStorageShape->GetStorageShape().GetDimNum() != TWO_DIMS,
               OPS_LOG_E(K_INNER_DEBUG, "expandXshape is invalid"), return GRAPH_FAILED);
    int32_t h = expandXStorageShape->GetStorageShape().GetDim(1);
    OPS_ERR_IF(h <= 0 || h > MAX_HIDDEN_SIZE_A2 || h % BLOCK_SIZE_A2 != 0,
               OPS_LOG_E(K_INNER_DEBUG, "hiddensize is invalid."), return GRAPH_FAILED);
    OPS_ERR_IF(expertIdStorageShape->GetStorageShape().GetDimNum() != TWO_DIMS,
               OPS_LOG_E(K_INNER_DEBUG, "expertIdshape is invalid"), return GRAPH_FAILED);
    int32_t bs = expertIdStorageShape->GetStorageShape().GetDim(0);
    OPS_ERR_IF(bs <= 0, OPS_LOG_E(K_INNER_DEBUG, "batchsize is invalid."), return GRAPH_FAILED);
    int32_t k = expertIdStorageShape->GetStorageShape().GetDim(1);
    OPS_ERR_IF(k < MIN_K_VALUE_A2 || k > MAX_K_VALUE_A2, OPS_LOG_E(K_INNER_DEBUG, "k is invalid."),
               return GRAPH_FAILED);
    const uint32_t maxBatchSize = isLayered ? MAX_BATCH_SIZE_LAYERED_A2 : MAX_BATCH_SIZE_A2;
    OPS_ERR_IF(bs > maxBatchSize, OPS_LOG_E(K_INNER_DEBUG, "Batchsize must be smaller than %u.", maxBatchSize),
               return ge::GRAPH_FAILED);
    info.bs = static_cast<uint32_t>(bs);
    info.k = static_cast<uint32_t>(k);
    info.h = static_cast<uint32_t>(h);

    OPS_LOG_D(K_INNER_DEBUG, "batchSize=%u", bs);
    OPS_LOG_D(K_INNER_DEBUG, "k=%u", k);
    OPS_LOG_D(K_INNER_DEBUG, "hidenSize=%u", h);

    return ge::GRAPH_SUCCESS;
}

static ge::graphStatus MoeCombineNormalA2GetPlatformInfoAndSetTiling(const gert::TilingContext &context,
                                                                     MoeCombineNormalA2Info &info)
{
    auto ascendcPlatform = platform_ascendc::PlatformAscendC(context.GetPlatformInfo());
    uint32_t aivNum = ascendcPlatform.GetCoreNumAiv();
    uint64_t ubSize = 0U;
    ascendcPlatform.GetCoreMemSize(platform_ascendc::CoreMemType::UB, ubSize);

    info.aivNum = aivNum;
    info.totalUbSize = ubSize;

    OPS_LOG_D(K_INNER_DEBUG, "aivNum=%u", info.aivNum);
    OPS_LOG_D(K_INNER_DEBUG, "ubSize=%lu", info.totalUbSize);

    return ge::GRAPH_SUCCESS;
}

static bool MoeCombineNormalA2IsLayered()
{
    const char *hcclIntraPcieEnable = getenv("HCCL_INTRA_PCIE_ENABLE");
    std::string pcieEnable = (hcclIntraPcieEnable != nullptr) ? std::string(hcclIntraPcieEnable) : std::string();
    const char *hcclIntraRoceEnable = getenv("HCCL_INTRA_ROCE_ENABLE");
    std::string roceEnable = (hcclIntraRoceEnable != nullptr) ? std::string(hcclIntraRoceEnable) : std::string();
    if (pcieEnable.empty() || roceEnable.empty()) {
        OPS_LOG_D(K_INNER_DEBUG, "ENV HCCL_INTRA_PCIE_ENABLE or HCCL_INTRA_ROCE_ENABLE don't set");
        return false;
    }
    if (pcieEnable == "1" && roceEnable == "0") {
        OPS_LOG_D(K_INNER_DEBUG,
                  "ENV HCCL_INTRA_PCIE_ENABLE = 1 and HCCL_INTRA_ROCE_ENABLE = 0, use layered solution.");
        return true;
    }
    OPS_LOG_D(K_INNER_DEBUG, "ENV HCCL_INTRA_PCIE_ENABLE != 1 or HCCL_INTRA_ROCE_ENABLE != 0, use default solution.");
    return false;
}

static uint64_t MoeCombineNormalA2CalcTilingKey(const gert::TilingContext &context, const bool isLayered)
{
    const char *nodeName = context.GetNodeName();
    OPS_LOG_I(nodeName, "Enter MoeCombineNormalA2 calc tiling func.");

    uint64_t tilingKey = TILING_KEY_BASE_A2;

    if (isLayered) {
        tilingKey = TILING_KEY_LAYERED_COMM_A2;
    }

    OPS_LOG_D(K_INNER_DEBUG, "tilingKey=%lu", tilingKey);

    return tilingKey;
}

static ge::graphStatus MoeCombineNormalA2TilingFuncImpl(gert::TilingContext &context)
{
    const char *nodeName = context.GetNodeName();
    OPS_ERR_IF(nodeName == nullptr, OPS_LOG_E("unKnownNodeName", "nodeName is nullptr."), return ge::GRAPH_FAILED);
    OPS_LOG_I(nodeName, "Enter MoeCombineNormalA2 tiling func.");

    // tilingData
    MoeCombineNormalA2TilingData *tilingData = context.GetTilingData<MoeCombineNormalA2TilingData>();
    OPS_ERR_IF(tilingData == nullptr, OPS_REPORT_VECTOR_INNER_ERR(nodeName, "tilingData is nullptr."),
               return ge::GRAPH_FAILED);
    OPS_LOG_I(nodeName, "MoeCombineNormalA2 get tilingData.");
    MoeCombineNormalA2Info &info = tilingData->moeCombineNormalInfo;

    bool isLayered = MoeCombineNormalA2IsLayered();
    OPS_ERR_IF(
        MoeCombineNormalA2CheckShapeAndSetTiling(context, info, isLayered) != ge::GRAPH_SUCCESS,
        OPS_REPORT_VECTOR_INNER_ERR(context.GetNodeName(), "MoeCombineNormalA2 CheckShapeAndSetTiling Failed"),
        return ge::GRAPH_FAILED);
    OPS_ERR_IF(
        MoeCombineNormalA2CheckAttrAndSetTiling(context, info) != ge::GRAPH_SUCCESS,
        OPS_REPORT_VECTOR_INNER_ERR(context.GetNodeName(), "MoeCombineNormalA2 CheckAttrAndSetTiling Failed"),
        return ge::GRAPH_FAILED);
    OPS_ERR_IF(
        MoeCombineNormalA2GetPlatformInfoAndSetTiling(context, info) != ge::GRAPH_SUCCESS,
        OPS_REPORT_VECTOR_INNER_ERR(context.GetNodeName(),
                                    "MoeCombineNormalA2 GetPlatformInfoAndSetTiling Failed"),
        return ge::GRAPH_FAILED);

    uint32_t blockDim = 1U;
    auto ascendcPlatform = platform_ascendc::PlatformAscendC(context.GetPlatformInfo());
    uint32_t aivNum = ascendcPlatform.GetCoreNumAiv();
    blockDim = ascendcPlatform.CalcTschBlockDim(aivNum, 0, aivNum);
    context.SetBlockDim(blockDim);

    uint64_t tilingKey = MoeCombineNormalA2CalcTilingKey(context, isLayered);
    context.SetTilingKey(tilingKey);
    // 2. workspace
    size_t *workSpaces = context.GetWorkspaceSizes(1);
    OPS_ERR_IF(workSpaces == nullptr, OPS_REPORT_VECTOR_INNER_ERR(nodeName, "workSpaces is nullptr."),
               return ge::GRAPH_FAILED);
    uint32_t userWorkspaceSize = static_cast<uint32_t>(info.moeExpertNum) * sizeof(uint32_t) * 2;
    workSpaces[0] = SYSTEM_NEED_WORKSPACE + userWorkspaceSize;

    // 3. communication
    auto attrs = context.GetAttrs();
    OPS_ERR_IF(attrs == nullptr, OPS_LOG_E(nodeName, "attrs is null."), return ge::GRAPH_FAILED);
    auto group = attrs->GetAttrPointer<char>(static_cast<int>(ATTR_GROUP_EP_INDEX));
    OPS_ERR_IF(group == nullptr, OPS_LOG_E(nodeName, "group is null."), return ge::GRAPH_FAILED);
    uint32_t opType = 18;  // batch write=18,
    std::string algConfig = "MultiPut=level0:fullmesh";
    AscendC::Mc2CcTilingConfig mc2CcTilingConfig(group, opType, algConfig);
    mc2CcTilingConfig.GetTiling(tilingData->mc2InitTiling);
    mc2CcTilingConfig.GetTiling(tilingData->mc2CcTiling);

    OPS_LOG_I(nodeName, "Leave MoeCombineNormalA2 tiling func.");
    return ge::GRAPH_SUCCESS;
}

static ge::graphStatus MoeDistributeCombineTilingFunc(gert::TilingContext *context)
{
    // not support int32 type for expandX
    auto expandXDesc = context->GetInputDesc(EXPAND_X_INDEX);
    const char *nodeName = context->GetNodeName();
    OPS_ERR_IF(expandXDesc == nullptr, OPS_LOG_E(nodeName, "expandxDesc is null."), return ge::GRAPH_FAILED);
    // check expandX dataType
    OPS_ERR_IF((expandXDesc->GetDataType() == ge::DT_INT32),
               OPS_LOG_E(nodeName, "expandX dataType is invalid, dataType should be bf16 or float16, but is %d",
                         static_cast<ge::DataType>(expandXDesc->GetDataType())),
               return ge::GRAPH_FAILED);

    return MoeCombineNormalA2TilingFuncImpl(*context);
}

struct MoeDistributeCombineCompileInfo {};
ge::graphStatus TilingParseForMoeCombineNormalA2(gert::TilingParseContext *context)
{
    (void)context;
    return ge::GRAPH_SUCCESS;
}

IMPL_OP_OPTILING(MoeCombineNormalA2)
    .Tiling(MoeDistributeCombineTilingFunc)
    .TilingParse<MoeDistributeCombineCompileInfo>(TilingParseForMoeCombineNormalA2);
}  // namespace optiling
