/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2026-2026. All rights reserved.
 * Description: dispatch normal A2 host part
 * Create: 2026-01-15
 * Note:
 * History: 2026-01-15 create dispatch normal A2 host part
 */

#include <queue>
#include <vector>
#include <dlfcn.h>
#include <fcntl.h>
#include <cstdio>
#include <cstdlib>
#include <sys/types.h>
#include <unistd.h>
#include <cmath>
#include <cstdint>
#include <string>

#include "graph/utils/type_utils.h"
#include "register/op_def_registry.h"
#include "tiling/platform/platform_ascendc.h"
#include "tiling/hccl/hccl_tiling.h"
#include "mc2_tiling_utils.h"
#include "ops_log.h"
#include "ops_error.h"
#include "tiling_args.h"
#include "../op_kernel/moe_dispatch_normal_a2_tiling.h"

#ifdef USE_CANN83_PATH
#include "platform/platform_infos_def.h"
#elif defined(USE_CANN82_PATH)
#include "experiment/platform/platform/platform_infos_def.h"
#else
#error "CANN version not supported or platform_infos_def.h not found. Check CANN_VERSION_MACRO definition."
#endif

using namespace AscendC;
using namespace ge;
using namespace Cam;

namespace {
constexpr const char *OPS_UTILS_LOG_SUB_MOD_NAME = "MOE_DISTRIBUTE_DISPATCH_A2";
constexpr const char *OPS_UTILS_LOG_PACKAGE_TYPE = "CAM_OPS";
constexpr uint32_t X_INDEX = 0;
constexpr uint32_t EXPERT_IDS_INDEX = 1;
constexpr uint32_t SCALES_INDEX = 2;

constexpr uint32_t TOKEN_SERVER_IDX_INDEX = 5;
constexpr uint32_t TOKEN_SERVER_CNT_INDEX = 6;
constexpr uint32_t EP_RANK_TOKEN_CNT_INDEX = 7;
constexpr uint32_t SRC_OFFSET_RANK_TOKEN_IDX_INDEX = 8;
constexpr uint32_t DST_OFFSET_RANK_TOKEN_IDX_INDEX = 9;
constexpr uint32_t OUTPUT_EXPAND_X_INDEX = 0;
constexpr uint32_t OUTPUT_DYNAMIC_SCALES_INDEX = 1;
constexpr uint32_t OUTPUT_EXPAND_IDX_INDEX = 2;
constexpr uint32_t OUTPUT_EXPERT_TOKEN_NUMS_INDEX = 3;
constexpr uint32_t OUTPUT_EP_RECV_COUNTS_INDEX = 4;
constexpr uint32_t OUTPUT_TP_RECV_COUNTS_INDEX = 5;

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
constexpr uint32_t ATTR_QUANT_MODE_INDEX = 10;
constexpr uint32_t ATTR_GLOBAL_BS_INDEX = 11;
constexpr uint32_t ATTR_EXPERT_TOKEN_NUMS_TYPE_INDEX = 12;

constexpr uint32_t TWO_DIMS = 2;
constexpr uint32_t ONE_DIM = 1;
constexpr uint32_t DYN_SCALE_DIMS = 1;
constexpr uint32_t EXPAND_IDX_DIMS = 1;
constexpr uint32_t DYNAMIC_SCALE_DIM_NUM = 1;
constexpr uint64_t INIT_TILINGKEY = 1000;
constexpr uint32_t ARR_LENGTH = 128;
constexpr uint32_t OP_TYPE_ALL_TO_ALL = 8;
constexpr uint32_t NO_SCALES = 0;
constexpr uint32_t STATIC_SCALES = 1;
constexpr uint32_t DYNAMIC_SCALES = 2;
constexpr uint32_t OP_TYPE_ALL_GATHER = 6;

constexpr uint32_t UNQUANT_MODE = 0;
constexpr uint32_t STATIC_QUANT_MODE = 1;
constexpr uint32_t DYNAMIC_QUANT_MODE = 2;
constexpr uint32_t RANK_NUM_PER_NODE_A2 = 8;
constexpr uint32_t BLOCK_SIZE_A2 = 32;
constexpr uint32_t MAX_K_VALUE_A2 = 8;
constexpr uint32_t MIN_K_VALUE_A2 = 2;
constexpr int32_t MAX_HIDDEN_SIZE_A2 = 7168;
constexpr int32_t MAX_EP_WORLD_SIZE_A2 = 256;
constexpr int32_t MAX_MOE_EXPERT_NUMS_A2 = 512;
constexpr uint32_t SUPPORT_HIDDEN_SIZE = 7168;
const char *K_INNER_DEBUG = "CamHCommMoeDistributeDispatch Tiling Debug";
const size_t MAX_GROUP_NAME_LENGTH = 128UL;
const int64_t MAX_EP_WORLD_SIZE = 288;
const int64_t MAX_TP_WORLD_SIZE = 2;
const int64_t BS_UPPER_BOUND = 4096;

constexpr uint32_t SHARED_EXPERT_NUM = 1;
constexpr uint64_t BUFF_NUM = 2;
constexpr uint64_t FLOAT16_SIZE = 2;
constexpr uint32_t EXPERT_TOKEN_NUM_TYPE_SUM = 0;
constexpr uint32_t EXPERT_TOKEN_NUM_TYPE_COUNT = 1;
constexpr uint32_t SCALES_TILING_KEY = 10;
constexpr uint32_t TP_TILING_KEY = 100;
constexpr uint32_t VERSION_2 = 2;
constexpr uint32_t HCOMMCNT_2 = 2;
constexpr int64_t MOE_EXPERT_MAX_NUM = 512;
constexpr int64_t K_MAX = 8;
constexpr uint32_t SYSTEM_NEED_WORKSPACE = 16 * 1024 * 1024;
constexpr uint32_t USER_WORKSPACE_A2 = 1 * 1024 * 1024;  // moeExpertNum_ * sizeof(uint32_t) + epWorldSize_ * 2 * 32
constexpr int32_t HCCL_BUFFER_SIZE_DEFAULT = 200 * 1024 * 1024;  // Bytes
constexpr uint64_t MB_SIZE = 1024UL * 1024UL;

constexpr uint64_t TILING_KEY_BASE_A2 = 2000000000;
constexpr uint64_t TILING_KEY_LAYERED_COMM_A2 = 100000000;
}  // namespace

namespace optiling {
static void PrintTilingDataInfo(const char *nodeName, const MoeDispatchNormalA2NonA2TilingData &tilingData)
{
    OPS_LOG_D(nodeName, "epWorldSize is %u.", tilingData.moeDistributeDispatchInfo.epWorldSize);
    OPS_LOG_D(nodeName, "tpWorldSize is %u.", tilingData.moeDistributeDispatchInfo.tpWorldSize);
    OPS_LOG_D(nodeName, "epRankId is %u.", tilingData.moeDistributeDispatchInfo.epRankId);
    OPS_LOG_D(nodeName, "tpRankId is %u.", tilingData.moeDistributeDispatchInfo.tpRankId);
    OPS_LOG_D(nodeName, "expertShardType is %u.", tilingData.moeDistributeDispatchInfo.expertShardType);
    OPS_LOG_D(nodeName, "sharedExpertRankNum is %u.", tilingData.moeDistributeDispatchInfo.sharedExpertRankNum);
    OPS_LOG_D(nodeName, "moeExpertNum is %u.", tilingData.moeDistributeDispatchInfo.moeExpertNum);
    OPS_LOG_D(nodeName, "quantMode is %u.", tilingData.moeDistributeDispatchInfo.quantMode);
    OPS_LOG_D(nodeName, "globalBs is %u.", tilingData.moeDistributeDispatchInfo.globalBs);
    OPS_LOG_D(nodeName, "isQuant is %d.", tilingData.moeDistributeDispatchInfo.isQuant);
    OPS_LOG_D(nodeName, "bs is %u.", tilingData.moeDistributeDispatchInfo.bs);
    OPS_LOG_D(nodeName, "k is %u.", tilingData.moeDistributeDispatchInfo.k);
    OPS_LOG_D(nodeName, "h is %u.", tilingData.moeDistributeDispatchInfo.h);
    OPS_LOG_D(nodeName, "aivNum is %u.", tilingData.moeDistributeDispatchInfo.aivNum);
    OPS_LOG_D(nodeName, "totalUbSize is %lu.", tilingData.moeDistributeDispatchInfo.totalUbSize);
    OPS_LOG_D(nodeName, "totalWinSize is %lu.", tilingData.moeDistributeDispatchInfo.totalWinSize);
}

static void CalTilingKey(uint64_t &tilingKey, const bool isScales, const uint32_t quantMode, const uint32_t tpWorldSize)
{
    tilingKey += static_cast<uint64_t>(quantMode);
    tilingKey += static_cast<uint64_t>((isScales ? SCALES_TILING_KEY : 0));
    if (tpWorldSize == MAX_TP_WORLD_SIZE) {
        tilingKey += static_cast<uint64_t>(TP_TILING_KEY);
    }
    return;
}

static void SetHcommCfg(const gert::TilingContext &context, MoeDispatchNormalA2NonA2TilingData &tiling,
                        const std::string groupEp, const std::string groupTp)
{
    const char *nodeName = context.GetNodeName();
    OPS_LOG_D(nodeName, "CamHCommMoeDistributeDispatch groupEp = %s, groupTp = %s", groupEp.c_str(), groupTp.c_str());
    uint32_t opType1 = OP_TYPE_ALL_TO_ALL;
    uint32_t opType2 = OP_TYPE_ALL_GATHER;
    std::string algConfigAllToAllStr = "AlltoAll=level0:fullmesh;level1:pairwise";
    std::string algConfigAllGatherStr = "AllGather=level0:ring";

    AscendC::Mc2CcTilingConfig mc2CcTilingConfig(groupEp, opType1, algConfigAllToAllStr);
    mc2CcTilingConfig.GetTiling(tiling.mc2InitTiling);
    mc2CcTilingConfig.GetTiling(tiling.mc2CcTiling1);

    mc2CcTilingConfig.SetGroupName(groupTp);
    mc2CcTilingConfig.SetOpType(opType2);
    mc2CcTilingConfig.SetAlgConfig(algConfigAllGatherStr);
    mc2CcTilingConfig.GetTiling(tiling.mc2CcTiling2);
}

static ge::graphStatus SetWorkSpace(gert::TilingContext &context, const char *nodeName)
{
    size_t *workSpaces = context.GetWorkspaceSizes(1);
    OPS_ERR_IF(workSpaces == nullptr, OPS_LOG_E(nodeName, "workSpaces is nullptr."), return ge::GRAPH_FAILED);
    workSpaces[0] = SYSTEM_NEED_WORKSPACE;
    return ge::GRAPH_SUCCESS;
}

static bool CheckIsA2(const gert::TilingContext &context)
{
    const char *nodeName = context.GetNodeName();
    fe::PlatFormInfos *platformInfoPtr = context.GetPlatformInfo();
    OPS_ERR_IF(platformInfoPtr == nullptr, OPS_LOG_E(nodeName, "platformInfoPtr is nullptr."), return 0);
    fe::PlatFormInfos &platformInfo = *platformInfoPtr;

    std::string socVersion;
    (void)platformInfo.GetPlatformResWithLock("version", "Short_SoC_version", socVersion);
    if (socVersion == "Ascend910B") {
        return true;
    }
    return false;
}

static ge::graphStatus MoeDistributeDispatchA2CheckShapeAndSetTiling(const gert::TilingContext &context,
                                                                     MoeDispatchNormalA2Info &info)
{
    const char *nodeName = context.GetNodeName();
    OPS_LOG_I(nodeName, "MoeDistributeDispatchA2 MoeDistributeDispatchA2CheckShapeAndSetTiling.");
    const gert::StorageShape *xStorageShape = context.GetInputShape(X_INDEX);
    const gert::StorageShape *expertIdStorageShape = context.GetInputShape(EXPERT_IDS_INDEX);
    const gert::StorageShape *scalesStorageShape = context.GetOptionalInputShape(SCALES_INDEX);

    OPS_ERR_IF(xStorageShape == nullptr, OPS_LOG_E(K_INNER_DEBUG, "xShape is null."),
               return GRAPH_FAILED);
    OPS_ERR_IF(expertIdStorageShape == nullptr, OPS_LOG_E(K_INNER_DEBUG, "expertIdShape is null."),
        return GRAPH_FAILED);
    OPS_ERR_IF(xStorageShape->GetStorageShape().GetDimNum() != TWO_DIMS,
        OPS_LOG_E(K_INNER_DEBUG, "x dims is invalid."), return false);
    OPS_ERR_IF(expertIdStorageShape->GetStorageShape().GetDimNum() != TWO_DIMS,
        OPS_LOG_E(K_INNER_DEBUG, "expertId dims is invalid."), return false);
    OPS_LOG_D(nodeName, "X dim0 = %ld", xStorageShape->GetStorageShape().GetDim(0));
    OPS_LOG_D(nodeName, "X dim1 = %ld", xStorageShape->GetStorageShape().GetDim(1));
    OPS_LOG_D(nodeName, "expertId dim0 = %ld", expertIdStorageShape->GetStorageShape().GetDim(0));
    OPS_LOG_D(nodeName, "expertId dim1 = %ld", expertIdStorageShape->GetStorageShape().GetDim(1));

    uint32_t h = static_cast<uint32_t>(xStorageShape->GetStorageShape().GetDim(1));
    uint32_t bs = static_cast<uint32_t>(expertIdStorageShape->GetStorageShape().GetDim(0));
    uint32_t k = static_cast<uint32_t>(expertIdStorageShape->GetStorageShape().GetDim(1));
    bool isScales = (scalesStorageShape != nullptr);
    auto attrs = context.GetAttrs();
    OPS_ERR_IF(attrs == nullptr, OPS_LOG_E(K_INNER_DEBUG, "attrs is null."), return ge::GRAPH_FAILED);
    auto quantModePtr = attrs->GetAttrPointer<int>(ATTR_QUANT_MODE_INDEX);
    OPS_ERR_IF(quantModePtr == nullptr, OPS_LOG_E(K_INNER_DEBUG, "quantModePtr is null."), return ge::GRAPH_FAILED);
    OPS_ERR_IF(h % BLOCK_SIZE_A2 != 0 || h <= 0 || h > MAX_HIDDEN_SIZE_A2,
        OPS_LOG_E(K_INNER_DEBUG, "hiddensize is invalid."), return GRAPH_FAILED);
    OPS_ERR_IF(
        bs <= 0 || bs > BS_UPPER_BOUND,
        OPS_LOG_E(K_INNER_DEBUG, "batchsize is invalid. bs: %u, should satisfy 0<bs<=%ld", bs, BS_UPPER_BOUND),
        return GRAPH_FAILED);
    OPS_ERR_IF(k < MIN_K_VALUE_A2 || k > MAX_K_VALUE_A2,
        OPS_LOG_E(K_INNER_DEBUG, "k is invalid, only support [%u, %u].", MIN_K_VALUE_A2, MAX_K_VALUE_A2),
        return GRAPH_FAILED);
    OPS_ERR_IF(*quantModePtr == UNQUANT_MODE && isScales,
        OPS_LOG_E(K_INNER_DEBUG, "scales should be null when quantMode is unQuant."), return GRAPH_FAILED);

    const gert::StorageShape *tokenServerIdxStorageShape = context.GetInputShape(TOKEN_SERVER_IDX_INDEX);
    OPS_ERR_IF(tokenServerIdxStorageShape == nullptr,
        OPS_LOG_E(K_INNER_DEBUG, "tokenServerIdxStorageShape is null."), return GRAPH_FAILED);
    const gert::StorageShape *tokenServerCntStorageShape = context.GetInputShape(TOKEN_SERVER_CNT_INDEX);
    OPS_ERR_IF(tokenServerCntStorageShape == nullptr,
        OPS_LOG_E(K_INNER_DEBUG, "tokenServerCntStorageShape is null."), return GRAPH_FAILED);
    const gert::StorageShape *epRankTokenCntStorageShape = context.GetInputShape(EP_RANK_TOKEN_CNT_INDEX);
    OPS_ERR_IF(epRankTokenCntStorageShape == nullptr,
        OPS_LOG_E(K_INNER_DEBUG, "epRankTokenCntStorageShape is null."), return GRAPH_FAILED);
    const gert::StorageShape *srcOffsetRankTokenIdxStorageShape =
        context.GetInputShape(SRC_OFFSET_RANK_TOKEN_IDX_INDEX);
    OPS_ERR_IF(srcOffsetRankTokenIdxStorageShape == nullptr,
        OPS_LOG_E(K_INNER_DEBUG, "srcOffsetRankTokenIdxStorageShape is null."), return GRAPH_FAILED);
    const gert::StorageShape *dstOffsetRankTokenIdxStorageShape =
        context.GetInputShape(DST_OFFSET_RANK_TOKEN_IDX_INDEX);
    OPS_ERR_IF(dstOffsetRankTokenIdxStorageShape == nullptr,
        OPS_LOG_E(K_INNER_DEBUG, "dstOffsetRankTokenIdxStorageShape is null."), return GRAPH_FAILED);

    info.isQuant = isScales;
    info.bs = bs;
    info.k = k;
    info.h = h;

    OPS_LOG_D(K_INNER_DEBUG, "isQuant=%d", info.isQuant);
    OPS_LOG_D(K_INNER_DEBUG, "batchSize=%d", info.bs);
    OPS_LOG_D(K_INNER_DEBUG, "k=%d", info.k);
    OPS_LOG_D(K_INNER_DEBUG, "hidenSize=%d", info.h);

    return ge::GRAPH_SUCCESS;
}

static ge::graphStatus MoeDistributeDispatchA2CheckAttrAndSetTiling(const gert::TilingContext &context,
                                                                    MoeDispatchNormalA2Info &info)
{
    auto attrs = context.GetAttrs();
    OPS_ERR_IF(attrs == nullptr, OPS_LOG_E(K_INNER_DEBUG, "attrs is null."), return ge::GRAPH_FAILED);

    auto groupEpPtr = attrs->GetAttrPointer<char>(static_cast<int>(ATTR_GROUP_EP_INDEX));
    auto epWorldSizePtr = attrs->GetAttrPointer<int>(ATTR_EP_WORLD_SIZE_INDEX);
    auto epRankIdPtr = attrs->GetAttrPointer<int>(ATTR_EP_RANK_ID_INDEX);
    auto moeExpertNumPtr = attrs->GetAttrPointer<int>(ATTR_MOE_EXPERT_NUM_INDEX);
    auto tpWorldSizePtr = attrs->GetAttrPointer<int>(ATTR_TP_WORLD_SIZE_INDEX);
    auto tpRankIdPtr = attrs->GetAttrPointer<int>(ATTR_TP_RANK_ID_INDEX);
    auto expertSharedTypePtr = attrs->GetAttrPointer<int>(ATTR_EXPERT_SHARD_TYPE_INDEX);
    auto sharedExpertRankNumPtr = attrs->GetAttrPointer<int>(ATTR_SHARED_EXPERT_RANK_NUM_INDEX);
    auto quantModePtr = attrs->GetAttrPointer<int>(ATTR_QUANT_MODE_INDEX);
    auto globalBsPtr = attrs->GetAttrPointer<int>(ATTR_GLOBAL_BS_INDEX);
    auto expertTokenNumsTypePtr = attrs->GetAttrPointer<int>(ATTR_EXPERT_TOKEN_NUMS_TYPE_INDEX);

    const gert::StorageShape *expertIdStorageShape = context.GetInputShape(EXPERT_IDS_INDEX);
    OPS_ERR_IF(expertIdStorageShape == nullptr, OPS_LOG_E(K_INNER_DEBUG, "expertIdShape is null."),
        return GRAPH_FAILED);
    int32_t bs = expertIdStorageShape->GetStorageShape().GetDim(0);

    OPS_ERR_IF(groupEpPtr == nullptr || strlen(groupEpPtr) == 0, OPS_LOG_E(K_INNER_DEBUG, "groupEp is invalid."),
        return GRAPH_FAILED);
    OPS_ERR_IF(epWorldSizePtr == nullptr || *epWorldSizePtr <= 0 || *epWorldSizePtr > MAX_EP_WORLD_SIZE_A2 ||
        *epWorldSizePtr % RANK_NUM_PER_NODE_A2 != 0,
        OPS_LOG_E(K_INNER_DEBUG, "epWorldSize is invalid."), return GRAPH_FAILED);
    OPS_ERR_IF(epRankIdPtr == nullptr || *epRankIdPtr < 0 || *epRankIdPtr >= *epWorldSizePtr,
        OPS_LOG_E(K_INNER_DEBUG, "epRankId is invalid."), return GRAPH_FAILED);
    OPS_ERR_IF(moeExpertNumPtr == nullptr, OPS_LOG_E(K_INNER_DEBUG, "moeExpertNumPtr is null."),
        return GRAPH_FAILED);
    OPS_ERR_IF(
        *moeExpertNumPtr % *epWorldSizePtr != 0 || *moeExpertNumPtr <= 0 || *moeExpertNumPtr > MAX_MOE_EXPERT_NUMS_A2,
        OPS_LOG_E(K_INNER_DEBUG, "moeExpertNum is invalid, only support (0, %d], but got moeExpertNum=%d.",
                  MAX_MOE_EXPERT_NUMS_A2, *moeExpertNumPtr),
        return GRAPH_FAILED);
    OPS_ERR_IF(tpWorldSizePtr == nullptr, OPS_LOG_E(K_INNER_DEBUG, "tpWorldSize is null."), return GRAPH_FAILED);
    OPS_ERR_IF(tpRankIdPtr == nullptr, OPS_LOG_E(K_INNER_DEBUG, "tpRankId is null."), return GRAPH_FAILED);
    OPS_ERR_IF(expertSharedTypePtr == nullptr, OPS_LOG_E(K_INNER_DEBUG, "expertSharedType is null."),
        return GRAPH_FAILED);
    OPS_ERR_IF(sharedExpertRankNumPtr == nullptr, OPS_LOG_E(K_INNER_DEBUG, "sharedExpertRankNum is null."),
        return GRAPH_FAILED);
    OPS_ERR_IF(quantModePtr == nullptr || (*quantModePtr != UNQUANT_MODE && *quantModePtr != DYNAMIC_QUANT_MODE),
        OPS_LOG_E(K_INNER_DEBUG, "quantMode is invalid."), return GRAPH_FAILED);
    OPS_ERR_IF(globalBsPtr == nullptr, OPS_LOG_E(K_INNER_DEBUG, "globalBs is null."), return GRAPH_FAILED);
    OPS_ERR_IF(expertTokenNumsTypePtr == nullptr || *expertTokenNumsTypePtr < 0 || *expertTokenNumsTypePtr > 1,
        OPS_LOG_E(K_INNER_DEBUG, "expertTokenNumsType is invalid. Must be 0 or 1. "), return GRAPH_FAILED);

    info.epWorldSize = *epWorldSizePtr;
    info.tpWorldSize = static_cast<uint32_t>(0);
    info.epRankId = *epRankIdPtr;
    info.tpRankId = static_cast<uint32_t>(0);
    info.expertSharedType = static_cast<uint32_t>(0);
    info.sharedExpertRankNum = static_cast<uint32_t>(0);
    info.moeExpertNum = *moeExpertNumPtr;
    info.quantMode = *quantModePtr;
    info.globalBs = static_cast<uint32_t>(*epWorldSizePtr * bs);
    info.expertTokenNumsType = *expertTokenNumsTypePtr;

    OPS_LOG_D(K_INNER_DEBUG, "quantMode=%d", info.quantMode);
    OPS_LOG_D(K_INNER_DEBUG, "globalBs=%d", info.globalBs);
    OPS_LOG_D(K_INNER_DEBUG, "expertTokenNumsType=%d", info.expertTokenNumsType);
    OPS_LOG_D(K_INNER_DEBUG, "expertSharedType=%d", info.expertSharedType);
    OPS_LOG_D(K_INNER_DEBUG, "sharedExpertRankNum=%d", info.sharedExpertRankNum);
    OPS_LOG_D(K_INNER_DEBUG, "moeExpertNum=%d", info.moeExpertNum);
    OPS_LOG_D(K_INNER_DEBUG, "epWorldSize=%d", info.epWorldSize);
    OPS_LOG_D(K_INNER_DEBUG, "tpWorldSize=%d", info.tpWorldSize);
    OPS_LOG_D(K_INNER_DEBUG, "epRankId=%d", info.epRankId);
    OPS_LOG_D(K_INNER_DEBUG, "tpRankId=%d", info.tpRankId);

    return ge::GRAPH_SUCCESS;
}

static ge::graphStatus MoeDistributeDispatchA2GetPlatformInfoAndSetTiling(const gert::TilingContext &context,
                                                                          MoeDispatchNormalA2Info &info)
{
    auto ascendcPlatform = platform_ascendc::PlatformAscendC(context.GetPlatformInfo());
    uint32_t aivNum = ascendcPlatform.GetCoreNumAiv();
    uint64_t ubSize = 0U;
    ascendcPlatform.GetCoreMemSize(platform_ascendc::CoreMemType::UB, ubSize);
    info.aivNum = aivNum;
    info.totalUbSize = ubSize;

    OPS_LOG_D(K_INNER_DEBUG, "aivNum=%d", info.aivNum);
    OPS_LOG_D(K_INNER_DEBUG, "ubSize=%lu", info.totalUbSize);

    return ge::GRAPH_SUCCESS;
}

static uint64_t MoeDistributeDispatchA2CalcTilingKey(const gert::TilingContext &context)
{
    uint64_t tilingKey = TILING_KEY_BASE_A2 + INIT_TILINGKEY;
    std::string hcclIntraPcieEnableStr;
    std::string hcclIntraRoceEnableStr;
    const char *hcclIntraPcieEnable = getenv("HCCL_INTRA_PCIE_ENABLE");
    if (hcclIntraPcieEnable != nullptr) {
        hcclIntraPcieEnableStr = hcclIntraPcieEnable;
    }
    const char *hcclIntraRoceEnable = getenv("HCCL_INTRA_ROCE_ENABLE");
    if (hcclIntraRoceEnable != nullptr) {
        hcclIntraRoceEnableStr = hcclIntraRoceEnable;
    }

    if (hcclIntraPcieEnableStr.empty() || hcclIntraRoceEnableStr.empty()) {
        OPS_LOG_D(K_INNER_DEBUG, "ENV HCCL_INTRA_PCIE_ENABLE or HCCL_INTRA_ROCE_ENABLE don't set");
    } else if (hcclIntraPcieEnableStr == "1" && hcclIntraRoceEnableStr == "0") {
        tilingKey += TILING_KEY_LAYERED_COMM_A2;
        OPS_LOG_D(K_INNER_DEBUG,
            "ENV HCCL_INTRA_PCIE_ENABLE = 1 and HCCL_INTRA_ROCE_ENABLE = 0, use layered solution.");
    } else {
        OPS_LOG_D(K_INNER_DEBUG,
            "ENV HCCL_INTRA_PCIE_ENABLE != 1 or HCCL_INTRA_ROCE_ENABLE != 0, use default solution.");
    }

    auto attrs = context.GetAttrs();
    const char *nodeName = context.GetNodeName();
    OPS_ERR_IF(attrs == nullptr, OPS_LOG_E(nodeName, "attrs is null."), return 0);
    auto quantModePtr = attrs->GetAttrPointer<int>(ATTR_QUANT_MODE_INDEX);
    tilingKey += static_cast<uint64_t>(*quantModePtr);

    const gert::StorageShape *scalesStorageShape = context.GetOptionalInputShape(SCALES_INDEX);
    bool isScales = (scalesStorageShape != nullptr);
    tilingKey += static_cast<uint64_t>((isScales ? SCALES_TILING_KEY : 0));

    OPS_LOG_D(K_INNER_DEBUG, "tilingKey=%lu", tilingKey);

    return tilingKey;
}

static ge::graphStatus MoeDistributeDispatchA2TilingFuncImpl(gert::TilingContext &context)
{
    const char *nodeName = context.GetNodeName();
    OPS_ERR_IF(nodeName == nullptr, OPS_LOG_E("unKnownNodeName", "nodeName is nullptr."), return ge::GRAPH_FAILED);
    OPS_LOG_D(nodeName, "start MoeDistributeDispatchA2TilingFuncImpl func.");
    OPS_LOG_I(nodeName, "Enter MoeDistributeDispatchA2 tiling func.");

    // 1. tilingData
    MoeDispatchNormalA2TilingData *tilingData = context.GetTilingData<MoeDispatchNormalA2TilingData>();
    OPS_ERR_IF(tilingData == nullptr, VECTOR_INNER_ERR_REPORT_TILIING(nodeName, "tilingData is nullptr."),
        return ge::GRAPH_FAILED);
    OPS_LOG_I(nodeName, "MoeDistributeDispatchA2 get tilingData.");
    MoeDispatchNormalA2Info &info = tilingData->moeDistributeDispatchInfo;
    OPS_LOG_I(nodeName, "MoeDistributeDispatchA2 get tilingData info.");

    OPS_ERR_IF(
        MoeDistributeDispatchA2CheckShapeAndSetTiling(context, info) != ge::GRAPH_SUCCESS,
        VECTOR_INNER_ERR_REPORT_TILIING(context.GetNodeName(), "MoeDistributeDispatchA2 CheckShapeAndSetTiling Failed"),
        return ge::GRAPH_FAILED);
    OPS_ERR_IF(
        MoeDistributeDispatchA2CheckAttrAndSetTiling(context, info) != ge::GRAPH_SUCCESS,
        VECTOR_INNER_ERR_REPORT_TILIING(context.GetNodeName(), "MoeDistributeDispatchA2 CheckAttrAndSetTiling Failed"),
        return ge::GRAPH_FAILED);
    OPS_ERR_IF(
        MoeDistributeDispatchA2GetPlatformInfoAndSetTiling(context, info) != ge::GRAPH_SUCCESS,
        VECTOR_INNER_ERR_REPORT_TILIING(context.GetNodeName(),
            "MoeDistributeDispatchA2 GetPlatformInfoAndSetTiling Failed"),
        return ge::GRAPH_FAILED);

    uint32_t blockDim = 1U;
    auto ascendcPlatform = platform_ascendc::PlatformAscendC(context.GetPlatformInfo());
    uint32_t aivNum = ascendcPlatform.GetCoreNumAiv();
    blockDim = ascendcPlatform.CalcTschBlockDim(aivNum, 0, aivNum);
    context.SetBlockDim(blockDim);

    uint64_t tilingKey = MoeDistributeDispatchA2CalcTilingKey(context);
    context.SetTilingKey(tilingKey);
    if ((tilingKey & TILING_KEY_LAYERED_COMM_A2) != 0) {
        OPS_ERR_IF(info.k < MIN_K_VALUE_A2 || info.k > MAX_K_VALUE_A2,
            OPS_LOG_E(nodeName, "As layered, K must be in range [%u, %u].", MIN_K_VALUE_A2, MAX_K_VALUE_A2),
            return ge::GRAPH_FAILED);
    }
    // 2. workspace
    size_t *workSpaces = context.GetWorkspaceSizes(1);
    OPS_ERR_IF(workSpaces == nullptr, VECTOR_INNER_ERR_REPORT_TILIING(nodeName, "workSpaces is nullptr."),
        return ge::GRAPH_FAILED);
    // wyl second USER_WORKSPACE_A2 is for dumpprof
    workSpaces[0] = SYSTEM_NEED_WORKSPACE + USER_WORKSPACE_A2 + USER_WORKSPACE_A2;

    // 3. communication
    auto attrs = context.GetAttrs();
    OPS_ERR_IF(attrs == nullptr, OPS_LOG_E(nodeName, "attrs is nullptr."), return ge::GRAPH_FAILED);
    auto group = attrs->GetAttrPointer<char>(static_cast<int>(ATTR_GROUP_EP_INDEX));
    uint32_t opType = 18;  // batch write=18,
    std::string algConfig = "MultiPut=level0:fullmesh";
    AscendC::Mc2CcTilingConfig mc2CcTilingConfig(group, opType, algConfig);
    mc2CcTilingConfig.GetTiling(tilingData->mc2InitTiling);
    mc2CcTilingConfig.GetTiling(tilingData->mc2CcTiling);

    OPS_LOG_D(nodeName, "Leave MoeDistributeDispatchA2 tiling func.");
    return ge::GRAPH_SUCCESS;
}

static ge::graphStatus MoeDispatchNormalA2TilingFunc(gert::TilingContext *context)
{
    ge::graphStatus ret = MoeDistributeDispatchA2TilingFuncImpl(*context);
    return ret;
}

struct MoeDispatchNormalA2CompileInfo {};
ge::graphStatus TilingParseForMoeDispatchNormalA2(gert::TilingParseContext *context)
{
    (void)context;
    return ge::GRAPH_SUCCESS;
}

IMPL_OP_OPTILING(MoeDispatchNormalA2)
    .Tiling(MoeDispatchNormalA2TilingFunc)
    .TilingParse<MoeDispatchNormalA2CompileInfo>(TilingParseForMoeDispatchNormalA2);
}  // namespace optiling
