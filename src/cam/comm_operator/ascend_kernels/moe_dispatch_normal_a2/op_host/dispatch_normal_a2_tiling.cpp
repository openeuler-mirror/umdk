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
#include "error_log.h"
#include "tiling_args.h"
#include "../op_kernel/cam_moe_distribute_dispatch_tiling.h"

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
static void PrintTilingDataInfo(const char *nodeName, const CamMoeDistributeDispatchTilingData &tilingData)
{
    OP_LOGD(nodeName, "epWorldSize is %u.", tilingData.moeDistributeDispatchInfo.epWorldSize);
    OP_LOGD(nodeName, "tpWorldSize is %u.", tilingData.moeDistributeDispatchInfo.tpWorldSize);
    OP_LOGD(nodeName, "epRankId is %u.", tilingData.moeDistributeDispatchInfo.epRankId);
    OP_LOGD(nodeName, "tpRankId is %u.", tilingData.moeDistributeDispatchInfo.tpRankId);
    OP_LOGD(nodeName, "expertShardType is %u.", tilingData.moeDistributeDispatchInfo.expertShardType);
    OP_LOGD(nodeName, "sharedExpertRankNum is %u.", tilingData.moeDistributeDispatchInfo.sharedExpertRankNum);
    OP_LOGD(nodeName, "moeExpertNum is %u.", tilingData.moeDistributeDispatchInfo.moeExpertNum);
    OP_LOGD(nodeName, "quantMode is %u.", tilingData.moeDistributeDispatchInfo.quantMode);
    OP_LOGD(nodeName, "globalBs is %u.", tilingData.moeDistributeDispatchInfo.globalBs);
    OP_LOGD(nodeName, "isQuant is %d.", tilingData.moeDistributeDispatchInfo.isQuant);
    OP_LOGD(nodeName, "bs is %u.", tilingData.moeDistributeDispatchInfo.bs);
    OP_LOGD(nodeName, "k is %u.", tilingData.moeDistributeDispatchInfo.k);
    OP_LOGD(nodeName, "h is %u.", tilingData.moeDistributeDispatchInfo.h);
    OP_LOGD(nodeName, "aivNum is %u.", tilingData.moeDistributeDispatchInfo.aivNum);
    OP_LOGD(nodeName, "totalUbSize is %lu.", tilingData.moeDistributeDispatchInfo.totalUbSize);
    OP_LOGD(nodeName, "totalWinSize is %lu.", tilingData.moeDistributeDispatchInfo.totalWinSize);
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

static void SetHcommCfg(const gert::TilingContext &context, CamMoeDistributeDispatchTilingData &tiling,
                        const std::string groupEp, const std::string groupTp)
{
    const char *nodeName = context.GetNodeName();
    OP_LOGD(nodeName, "CamHCommMoeDistributeDispatch groupEp = %s, groupTp = %s", groupEp.c_str(), groupTp.c_str());
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
    OP_TILING_CHECK(workSpaces == nullptr, OP_LOGE(nodeName, "workSpaces is nullptr."), return ge::GRAPH_FAILED);
    workSpaces[0] = SYSTEM_NEED_WORKSPACE;
    return ge::GRAPH_SUCCESS;
}

static bool CheckIsA2(const gert::TilingContext &context)
{
    const char *nodeName = context.GetNodeName();
    fe::PlatFormInfos *platformInfoPtr = context.GetPlatformInfo();
    OP_TILING_CHECK(platformInfoPtr == nullptr, OP_LOGE(nodeName, "platformInfoPtr is nullptr."), return 0);
    fe::PlatFormInfos &platformInfo = *platformInfoPtr;

    std::string socVersion;
    (void)platformInfo.GetPlatformResWithLock("version", "Short_SoC_version", socVersion);
    if (socVersion == "Ascend910B") {
        return true;
    }
    return false;
}

static ge::graphStatus MoeDistributeDispatchA2CheckShapeAndSetTiling(const gert::TilingContext &context,
                                                                     CamMoeDistributeDispatchA2Info &info)
{
    const char *nodeName = context.GetNodeName();
    OP_LOGI(nodeName, "MoeDistributeDispatchA2 MoeDistributeDispatchA2CheckShapeAndSetTiling.");
    const gert::StorageShape *xStorageShape = context.GetInputShape(X_INDEX);
    const gert::StorageShape *expertIdStorageShape = context.GetInputShape(EXPERT_IDS_INDEX);
    const gert::StorageShape *scalesStorageShape = context.GetOptionalInputShape(SCALES_INDEX);

    OP_TILING_CHECK(xStorageShape == nullptr, OP_LOGE(K_INNER_DEBUG, "xShape is null."), return GRAPH_FAILED);
    OP_TILING_CHECK(expertIdStorageShape == nullptr, OP_LOGE(K_INNER_DEBUG, "expertIdShape is null."),
                    return GRAPH_FAILED);
    OP_TILING_CHECK(xStorageShape->GetStorageShape().GetDimNum() != TWO_DIMS,
                    OP_LOGE(K_INNER_DEBUG, "x dims is invalid."), return false);
    OP_TILING_CHECK(expertIdStorageShape->GetStorageShape().GetDimNum() != TWO_DIMS,
                    OP_LOGE(K_INNER_DEBUG, "expertId dims is invalid."), return false);
    OP_LOGD(nodeName, "X dim0 = %ld", xStorageShape->GetStorageShape().GetDim(0));
    OP_LOGD(nodeName, "X dim1 = %ld", xStorageShape->GetStorageShape().GetDim(1));
    OP_LOGD(nodeName, "expertId dim0 = %ld", expertIdStorageShape->GetStorageShape().GetDim(0));
    OP_LOGD(nodeName, "expertId dim1 = %ld", expertIdStorageShape->GetStorageShape().GetDim(1));

    uint32_t h = static_cast<uint32_t>(xStorageShape->GetStorageShape().GetDim(1));
    uint32_t bs = static_cast<uint32_t>(expertIdStorageShape->GetStorageShape().GetDim(0));
    uint32_t k = static_cast<uint32_t>(expertIdStorageShape->GetStorageShape().GetDim(1));
    bool isScales = (scalesStorageShape != nullptr);
    auto attrs = context.GetAttrs();
    OP_TILING_CHECK(attrs == nullptr, OP_LOGE(K_INNER_DEBUG, "attrs is null."), return ge::GRAPH_FAILED);
    auto quantModePtr = attrs->GetAttrPointer<int>(ATTR_QUANT_MODE_INDEX);
    OP_TILING_CHECK(h % BLOCK_SIZE_A2 != 0 || h <= 0 || h > MAX_HIDDEN_SIZE_A2,
                    OP_LOGE(K_INNER_DEBUG, "hiddensize is invalid."), return GRAPH_FAILED);
    OP_TILING_CHECK(
        bs <= 0 || bs > BS_UPPER_BOUND,
        OP_LOGE(K_INNER_DEBUG, "batchsize is invalid. bs: %u, should satisfy 0<bs<=%ld", bs, BS_UPPER_BOUND),
        return GRAPH_FAILED);
    OP_TILING_CHECK(k <= 0 || k > MAX_K_VALUE_A2, OP_LOGE(K_INNER_DEBUG, "k is invalid."), return GRAPH_FAILED);
    OP_TILING_CHECK(*quantModePtr == UNQUANT_MODE && isScales,
                    OP_LOGE(K_INNER_DEBUG, "scales should be null when quantMode is unQuant."), return GRAPH_FAILED);

    const gert::StorageShape *tokenServerIdxStorageShape = context.GetInputShape(TOKEN_SERVER_IDX_INDEX);
    OP_TILING_CHECK(tokenServerIdxStorageShape == nullptr,
                    OP_LOGE(K_INNER_DEBUG, "tokenServerIdxStorageShape is null."), return GRAPH_FAILED);
    const gert::StorageShape *tokenServerCntStorageShape = context.GetInputShape(TOKEN_SERVER_CNT_INDEX);
    OP_TILING_CHECK(tokenServerCntStorageShape == nullptr,
                    OP_LOGE(K_INNER_DEBUG, "tokenServerCntStorageShape is null."), return GRAPH_FAILED);
    const gert::StorageShape *epRankTokenCntStorageShape = context.GetInputShape(EP_RANK_TOKEN_CNT_INDEX);
    OP_TILING_CHECK(epRankTokenCntStorageShape == nullptr,
                    OP_LOGE(K_INNER_DEBUG, "epRankTokenCntStorageShape is null."), return GRAPH_FAILED);
    const gert::StorageShape *srcOffsetRankTokenIdxStorageShape =
        context.GetInputShape(SRC_OFFSET_RANK_TOKEN_IDX_INDEX);
    OP_TILING_CHECK(srcOffsetRankTokenIdxStorageShape == nullptr,
                    OP_LOGE(K_INNER_DEBUG, "srcOffsetRankTokenIdxStorageShape is null."), return GRAPH_FAILED);
    const gert::StorageShape *dstOffsetRankTokenIdxStorageShape =
        context.GetInputShape(DST_OFFSET_RANK_TOKEN_IDX_INDEX);
    OP_TILING_CHECK(dstOffsetRankTokenIdxStorageShape == nullptr,
                    OP_LOGE(K_INNER_DEBUG, "dstOffsetRankTokenIdxStorageShape is null."), return GRAPH_FAILED);

    info.isQuant = isScales;
    info.bs = bs;
    info.k = k;
    info.h = h;

    OP_LOGD(K_INNER_DEBUG, "isQuant=%d", info.isQuant);
    OP_LOGD(K_INNER_DEBUG, "batchSize=%d", info.bs);
    OP_LOGD(K_INNER_DEBUG, "k=%d", info.k);
    OP_LOGD(K_INNER_DEBUG, "hidenSize=%d", info.h);

    return ge::GRAPH_SUCCESS;
}

static ge::graphStatus MoeDistributeDispatchA2CheckAttrAndSetTiling(const gert::TilingContext &context,
                                                                    CamMoeDistributeDispatchA2Info &info)
{
    auto attrs = context.GetAttrs();
    OP_TILING_CHECK(attrs == nullptr, OP_LOGE(K_INNER_DEBUG, "attrs is null."), return ge::GRAPH_FAILED);

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
    OP_TILING_CHECK(expertIdStorageShape == nullptr, OP_LOGE(K_INNER_DEBUG, "expertIdShape is null."),
                    return GRAPH_FAILED);
    int32_t bs = expertIdStorageShape->GetStorageShape().GetDim(0);

    OP_TILING_CHECK(groupEpPtr == nullptr || strlen(groupEpPtr) == 0, OP_LOGE(K_INNER_DEBUG, "groupEp is invalid."),
                    return GRAPH_FAILED);
    OP_TILING_CHECK(epWorldSizePtr == nullptr || *epWorldSizePtr <= 0 || *epWorldSizePtr > MAX_EP_WORLD_SIZE_A2 ||
                        *epWorldSizePtr % RANK_NUM_PER_NODE_A2 != 0,
                    OP_LOGE(K_INNER_DEBUG, "epWorldSize is invalid."), return GRAPH_FAILED);
    OP_TILING_CHECK(epRankIdPtr == nullptr || *epRankIdPtr < 0 || *epRankIdPtr >= *epWorldSizePtr,
                    OP_LOGE(K_INNER_DEBUG, "epRankId is invalid."), return GRAPH_FAILED);
    OP_TILING_CHECK(moeExpertNumPtr == nullptr, OP_LOGE(K_INNER_DEBUG, "moeExpertNumPtr is null."),
                    return GRAPH_FAILED);
    OP_TILING_CHECK(
        *moeExpertNumPtr % *epWorldSizePtr != 0 || *moeExpertNumPtr <= 0 || *moeExpertNumPtr > MAX_MOE_EXPERT_NUMS_A2,
        OP_LOGE(K_INNER_DEBUG, "moeExpertNum is invalid, only support (0, %d], but got moeExpertNum=%d.",
                MAX_MOE_EXPERT_NUMS_A2, *moeExpertNumPtr),
        return GRAPH_FAILED);
    OP_TILING_CHECK(tpWorldSizePtr == nullptr, OP_LOGE(K_INNER_DEBUG, "tpWorldSize is null."), return GRAPH_FAILED);
    OP_TILING_CHECK(tpRankIdPtr == nullptr, OP_LOGE(K_INNER_DEBUG, "tpRankId is null."), return GRAPH_FAILED);
    OP_TILING_CHECK(expertSharedTypePtr == nullptr, OP_LOGE(K_INNER_DEBUG, "expertSharedType is null."),
                    return GRAPH_FAILED);
    OP_TILING_CHECK(sharedExpertRankNumPtr == nullptr, OP_LOGE(K_INNER_DEBUG, "sharedExpertRankNum is null."),
                    return GRAPH_FAILED);
    OP_TILING_CHECK(quantModePtr == nullptr || (*quantModePtr != UNQUANT_MODE && *quantModePtr != DYNAMIC_QUANT_MODE),
                    OP_LOGE(K_INNER_DEBUG, "quantMode is invalid."), return GRAPH_FAILED);
    OP_TILING_CHECK(globalBsPtr == nullptr, OP_LOGE(K_INNER_DEBUG, "globalBs is null."), return GRAPH_FAILED);
    OP_TILING_CHECK(expertTokenNumsTypePtr == nullptr || *expertTokenNumsTypePtr < 0 || *expertTokenNumsTypePtr > 1,
                    OP_LOGE(K_INNER_DEBUG, "expertTokenNumsType is invalid. Must be 0 or 1. "), return GRAPH_FAILED);

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

    OP_LOGD(K_INNER_DEBUG, "quantMode=%d", info.quantMode);
    OP_LOGD(K_INNER_DEBUG, "globalBs=%d", info.globalBs);
    OP_LOGD(K_INNER_DEBUG, "expertTokenNumsType=%d", info.expertTokenNumsType);
    OP_LOGD(K_INNER_DEBUG, "expertSharedType=%d", info.expertSharedType);
    OP_LOGD(K_INNER_DEBUG, "sharedExpertRankNum=%d", info.sharedExpertRankNum);
    OP_LOGD(K_INNER_DEBUG, "moeExpertNum=%d", info.moeExpertNum);
    OP_LOGD(K_INNER_DEBUG, "epWorldSize=%d", info.epWorldSize);
    OP_LOGD(K_INNER_DEBUG, "tpWorldSize=%d", info.tpWorldSize);
    OP_LOGD(K_INNER_DEBUG, "epRankId=%d", info.epRankId);
    OP_LOGD(K_INNER_DEBUG, "tpRankId=%d", info.tpRankId);

    return ge::GRAPH_SUCCESS;
}

static ge::graphStatus MoeDistributeDispatchA2GetPlatformInfoAndSetTiling(const gert::TilingContext &context,
                                                                          CamMoeDistributeDispatchA2Info &info)
{
    auto ascendcPlatform = platform_ascendc::PlatformAscendC(context.GetPlatformInfo());
    uint32_t aivNum = ascendcPlatform.GetCoreNumAiv();
    uint64_t ubSize = 0U;
    ascendcPlatform.GetCoreMemSize(platform_ascendc::CoreMemType::UB, ubSize);
    info.aivNum = aivNum;
    info.totalUbSize = ubSize;

    OP_LOGD(K_INNER_DEBUG, "aivNum=%d", info.aivNum);
    OP_LOGD(K_INNER_DEBUG, "ubSize=%lu", info.totalUbSize);

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
        OP_LOGD(K_INNER_DEBUG, "ENV HCCL_INTRA_PCIE_ENABLE or HCCL_INTRA_ROCE_ENABLE don't set");
    } else if (hcclIntraPcieEnableStr == "1" && hcclIntraRoceEnableStr == "0") {
        tilingKey += TILING_KEY_LAYERED_COMM_A2;
        OP_LOGD(K_INNER_DEBUG, "ENV HCCL_INTRA_PCIE_ENABLE = 1 and HCCL_INTRA_ROCE_ENABLE = 0, use layered solution.");
    } else {
        OP_LOGD(K_INNER_DEBUG, "ENV HCCL_INTRA_PCIE_ENABLE != 1 or HCCL_INTRA_ROCE_ENABLE != 0, use default solution.");
    }

    auto attrs = context.GetAttrs();
    const char *nodeName = context.GetNodeName();
    OP_TILING_CHECK(attrs == nullptr, OP_LOGE(nodeName, "attrs is null."), return 0);
    auto quantModePtr = attrs->GetAttrPointer<int>(ATTR_QUANT_MODE_INDEX);
    tilingKey += static_cast<uint64_t>(*quantModePtr);

    const gert::StorageShape *scalesStorageShape = context.GetOptionalInputShape(SCALES_INDEX);
    bool isScales = (scalesStorageShape != nullptr);
    tilingKey += static_cast<uint64_t>((isScales ? SCALES_TILING_KEY : 0));

    OP_LOGD(K_INNER_DEBUG, "tilingKey=%lu", tilingKey);

    return tilingKey;
}

static ge::graphStatus MoeDistributeDispatchA2TilingFuncImpl(gert::TilingContext &context)
{
    const char *nodeName = context.GetNodeName();
    OP_LOGD(nodeName, "start MoeDistributeDispatchA2TilingFuncImpl func.");
    OP_LOGI(nodeName, "Enter MoeDistributeDispatchA2 tiling func.");

    // 1. tilingData
    CamMoeDistributeDispatchA2TilingData *tilingData = context.GetTilingData<CamMoeDistributeDispatchA2TilingData>();
    OP_TILING_CHECK(tilingData == nullptr, VECTOR_INNER_ERR_REPORT_TILIING(nodeName, "tilingData is nullptr."),
                    return ge::GRAPH_FAILED);
    OP_LOGI(nodeName, "MoeDistributeDispatchA2 get tilingData.");
    CamMoeDistributeDispatchA2Info &info = tilingData->moeDistributeDispatchInfo;
    OP_LOGI(nodeName, "MoeDistributeDispatchA2 get tilingData info.");

    OP_TILING_CHECK(
        MoeDistributeDispatchA2CheckShapeAndSetTiling(context, info) != ge::GRAPH_SUCCESS,
        VECTOR_INNER_ERR_REPORT_TILIING(context.GetNodeName(), "MoeDistributeDispatchA2 CheckShapeAndSetTiling Failed"),
        return ge::GRAPH_FAILED);
    OP_TILING_CHECK(
        MoeDistributeDispatchA2CheckAttrAndSetTiling(context, info) != ge::GRAPH_SUCCESS,
        VECTOR_INNER_ERR_REPORT_TILIING(context.GetNodeName(), "MoeDistributeDispatchA2 CheckAttrAndSetTiling Failed"),
        return ge::GRAPH_FAILED);
    OP_TILING_CHECK(MoeDistributeDispatchA2GetPlatformInfoAndSetTiling(context, info) != ge::GRAPH_SUCCESS,
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
        OP_TILING_CHECK(info.k != 8, OP_LOGE(nodeName, "As layered, K must be 8."), return ge::GRAPH_FAILED);
    }
    // 2. workspace
    size_t *workSpaces = context.GetWorkspaceSizes(1);
    OP_TILING_CHECK(workSpaces == nullptr, VECTOR_INNER_ERR_REPORT_TILIING(nodeName, "workSpaces is nullptr."),
                    return ge::GRAPH_FAILED);
    // wyl second USER_WORKSPACE_A2 is for dumpprof
    workSpaces[0] = SYSTEM_NEED_WORKSPACE + USER_WORKSPACE_A2 + USER_WORKSPACE_A2;

    // 3. communication
    auto attrs = context.GetAttrs();
    OP_TILING_CHECK(attrs == nullptr, OP_LOGE(nodeName, "attrs is nullptr."), return ge::GRAPH_FAILED);
    auto group = attrs->GetAttrPointer<char>(static_cast<int>(ATTR_GROUP_EP_INDEX));
    uint32_t opType = 18;  // batch write=18,
    std::string algConfig = "MultiPut=level0:fullmesh";
    AscendC::Mc2CcTilingConfig mc2CcTilingConfig(group, opType, algConfig);
    mc2CcTilingConfig.GetTiling(tilingData->mc2InitTiling);
    mc2CcTilingConfig.GetTiling(tilingData->mc2CcTiling);

    OP_LOGD(nodeName, "Leave MoeDistributeDispatchA2 tiling func.");
    return ge::GRAPH_SUCCESS;
}

static ge::graphStatus DispatchNormalA2TilingFunc(gert::TilingContext *context)
{
    ge::graphStatus ret = MoeDistributeDispatchA2TilingFuncImpl(*context);
    return ret;
}

struct DispatchNormalA2CompileInfo {};
ge::graphStatus TilingParseForDispatchNormalA2(gert::TilingParseContext *context)
{
    (void)context;
    return ge::GRAPH_SUCCESS;
}

IMPL_OP_OPTILING(DispatchNormalA2)
    .Tiling(DispatchNormalA2TilingFunc)
    .TilingParse<DispatchNormalA2CompileInfo>(TilingParseForDispatchNormalA2);
}  // namespace optiling
