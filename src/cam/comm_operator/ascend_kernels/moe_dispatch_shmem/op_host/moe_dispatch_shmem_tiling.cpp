/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2026-2026. All rights reserved.
 * Description: shmem dispatch tiling function implementation file
 * Create: 2026-01-06
 * Note:
 * History: 2026-01-06 create shmem dispatch tiling function file
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
#include "tiling/tiling_api.h"
#include "tiling/platform/platform_ascendc.h"
#include "ops_log.h"
#include "ops_error.h"
#include "../op_kernel/moe_dispatch_shmem_tiling.h"

#ifndef OPS_UTILS_LOG_SUB_MOD_NAME
#define OPS_UTILS_LOG_SUB_MOD_NAME "MOE_DISPATCH_SHMEM"
#endif

#ifndef OPS_UTILS_LOG_PACKAGE_TYPE
#define OPS_UTILS_LOG_PACKAGE_TYPE "CAM_OPS"
#endif

using namespace ge;
using namespace Moe;

namespace {
constexpr uint32_t X_INDEX = 0U;
constexpr uint32_t EXPERT_IDS_INDEX = 1U;
constexpr uint32_t SCALES_INDEX = 2U;
constexpr uint32_t X_ACTIVE_MASK_INDEX = 3U;
constexpr uint32_t OUTPUT_EXPAND_X_INDEX = 0U;
constexpr uint32_t OUTPUT_DYNAMIC_SCALES_INDEX = 1U;
constexpr uint32_t OUTPUT_EXPAND_IDX_INDEX = 2U;
constexpr uint32_t OUTPUT_EXPERT_TOKEN_NUMS_INDEX = 3U;
constexpr uint32_t OUTPUT_EP_RECV_COUNTS_INDEX = 4U;
constexpr uint32_t OUTPUT_TP_RECV_COUNTS_INDEX = 5U;

constexpr uint32_t ATTR_EP_WORLD_SIZE_INDEX = 0;
constexpr uint32_t ATTR_EP_RANK_ID_INDEX = 1;
constexpr uint32_t ATTR_MOE_EXPERT_NUM_INDEX = 2;
constexpr uint32_t ATTR_TP_WORLD_SIZE_INDEX = 3;
constexpr uint32_t ATTR_TP_RANK_ID_INDEX = 4;
constexpr uint32_t ATTR_EXPERT_SHARD_TYPE_INDEX = 5;
constexpr uint32_t ATTR_SHARED_EXPERT_NUM_INDEX = 6;
constexpr uint32_t ATTR_SHARED_EXPERT_RANK_NUM_INDEX = 7;
constexpr uint32_t ATTR_QUANT_MODE_INDEX = 8;
constexpr uint32_t ATTR_GLOBAL_BS_INDEX = 9;
constexpr uint32_t ATTR_EXPERT_TOKEN_NUMS_TYPE_INDEX = 10;
constexpr uint32_t ATTR_EXT_INFO_INDEX = 11;

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
const char *K_INNER_DEBUG = "MoeDispatchShmem Tiling Debug";
const size_t MAX_GROUP_NAME_LENGTH = 128UL;
const int64_t MAX_EP_WORLD_SIZE = 288;
const int64_t MAX_TP_WORLD_SIZE = 2;
const int64_t BS_UPPER_BOUND = 512;

constexpr uint32_t NUM_10 = 10;
constexpr uint32_t NUM_100 = 100;
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
static void PrintTilingDataInfo(const char *nodeName, const MoeDispatchShmemTilingData &tilingData)
{
    OPS_LOG_D(nodeName, "epWorldSize is %u.", tilingData.moeDistributeDispatchInfo.epWorldSize);
    OPS_LOG_D(nodeName, "tpWorldSize is %u.", tilingData.moeDistributeDispatchInfo.tpWorldSize);
    OPS_LOG_D(nodeName, "epRankId is %u.", tilingData.moeDistributeDispatchInfo.epRankId);
    OPS_LOG_D(nodeName, "tpRankId is %u.", tilingData.moeDistributeDispatchInfo.tpRankId);
    OPS_LOG_D(nodeName, "expertSharedType is %u.", tilingData.moeDistributeDispatchInfo.expertSharedType);
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

static bool CheckTensorDim(const gert::TilingContext &context, const char *nodeName, const bool isScales,
                           const uint32_t quantMode)
{
    const gert::StorageShape *xStorageShape = context.GetInputShape(X_INDEX);
    OPS_ERR_IF(xStorageShape == nullptr, OPS_LOG_E(nodeName, "xShape is null."), return false);
    OPS_ERR_IF(xStorageShape->GetStorageShape().GetDimNum() != TWO_DIMS,
                    OPS_LOG_E(nodeName, "xShape dims must be 2, but current dim num is %lu.",
                            xStorageShape->GetStorageShape().GetDimNum()),
                    return false);
    OPS_LOG_D(nodeName, "x dim0 = %ld", xStorageShape->GetStorageShape().GetDim(0));
    OPS_LOG_D(nodeName, "x dim1 = %ld", xStorageShape->GetStorageShape().GetDim(1));

    const gert::StorageShape *expertIdStorageShape = context.GetInputShape(EXPERT_IDS_INDEX);
    OPS_ERR_IF(expertIdStorageShape == nullptr, OPS_LOG_E(nodeName, "expertIdShape is null."), return false);
    OPS_ERR_IF(expertIdStorageShape->GetStorageShape().GetDimNum() != TWO_DIMS,
                    OPS_LOG_E(nodeName, "expertIdShape dims must be 2, but current dim num is %lu.",
                            expertIdStorageShape->GetStorageShape().GetDimNum()),
                    return false);
    OPS_LOG_D(nodeName, "expertId dim0 = %ld", expertIdStorageShape->GetStorageShape().GetDim(0));
    OPS_LOG_D(nodeName, "expertId dim1 = %ld", expertIdStorageShape->GetStorageShape().GetDim(1));
    // 如果scales不为空进行shape维度检查
    if (isScales) {
        const gert::StorageShape *scalesStorageShape = context.GetOptionalInputShape(SCALES_INDEX);
        OPS_ERR_IF(scalesStorageShape == nullptr, OPS_LOG_E(nodeName, "scalesShape is null."), return false);
        OPS_ERR_IF(scalesStorageShape->GetStorageShape().GetDimNum() != TWO_DIMS,
                        OPS_LOG_E(nodeName, "scalesShape dims must be 2, but current dim num is %lu.",
                                scalesStorageShape->GetStorageShape().GetDimNum()),
                        return false);
        OPS_LOG_D(nodeName, "scales dim0 = %ld", scalesStorageShape->GetStorageShape().GetDim(0));
        OPS_LOG_D(nodeName, "scales dim1 = %ld", scalesStorageShape->GetStorageShape().GetDim(1));
    }

    const gert::StorageShape *expandXStorageShape = context.GetOutputShape(OUTPUT_EXPAND_X_INDEX);
    OPS_ERR_IF(expandXStorageShape == nullptr, OPS_LOG_E(nodeName, "expandXShape is null."), return false);
    OPS_ERR_IF(expandXStorageShape->GetStorageShape().GetDimNum() != TWO_DIMS,
                    OPS_LOG_E(nodeName, "expandXShape dims must be 2, but current dim num is %lu.",
                            expandXStorageShape->GetStorageShape().GetDimNum()),
                    return false);
    OPS_LOG_D(nodeName, "expandX dim0 = %ld", expandXStorageShape->GetStorageShape().GetDim(0));
    OPS_LOG_D(nodeName, "expandX dim1 = %ld", expandXStorageShape->GetStorageShape().GetDim(1));

    if (quantMode == DYNAMIC_SCALES) {
        const gert::StorageShape *dynamicScalesStorageShape = context.GetOutputShape(OUTPUT_DYNAMIC_SCALES_INDEX);
        OPS_ERR_IF(dynamicScalesStorageShape == nullptr, OPS_LOG_E(nodeName, "dynamicScalesShape is null."),
                        return false);
        OPS_ERR_IF(dynamicScalesStorageShape->GetStorageShape().GetDimNum() != DYNAMIC_SCALE_DIM_NUM,
                        OPS_LOG_E(nodeName, "dynamicScalesShape dims must be %u, but current dim num is %lu.",
                                DYNAMIC_SCALE_DIM_NUM, dynamicScalesStorageShape->GetStorageShape().GetDimNum()),
                        return false);
        OPS_LOG_D(nodeName, "dynamicScales dim0 = %ld", dynamicScalesStorageShape->GetStorageShape().GetDim(0));
    }

    const gert::StorageShape *expandIdxStorageShape = context.GetOutputShape(OUTPUT_EXPAND_IDX_INDEX);
    OPS_ERR_IF(expandIdxStorageShape == nullptr, OPS_LOG_E(nodeName, "expandIdxShape is null."), return false);
    OPS_ERR_IF(expandIdxStorageShape->GetStorageShape().GetDimNum() != ONE_DIM,
                    OPS_LOG_E(nodeName, "expandIdxShape dims must be 1, but current dim num is %lu.",
                            expandIdxStorageShape->GetStorageShape().GetDimNum()),
                    return false);
    OPS_LOG_D(nodeName, "expandIdx dim0 = %ld", expandIdxStorageShape->GetStorageShape().GetDim(0));

    const gert::StorageShape *expertTokenNumsStorageShape = context.GetOutputShape(OUTPUT_EXPERT_TOKEN_NUMS_INDEX);
    OPS_ERR_IF(expertTokenNumsStorageShape == nullptr, OPS_LOG_E(nodeName, "expertTokenNumsShape is null."),
                    return false);
    OPS_ERR_IF(expertTokenNumsStorageShape->GetStorageShape().GetDimNum() != ONE_DIM,
                    OPS_LOG_E(nodeName, "expertTokenNumsShape dims must be 1, but current dim num is %lu.",
                            expertTokenNumsStorageShape->GetStorageShape().GetDimNum()),
                    return false);
    OPS_LOG_D(nodeName, "expertTokenNums dim0 = %ld", expertTokenNumsStorageShape->GetStorageShape().GetDim(0));

    const gert::StorageShape *epRecvCountStorageShape = context.GetOutputShape(OUTPUT_EP_RECV_COUNTS_INDEX);
    OPS_ERR_IF(epRecvCountStorageShape == nullptr, OPS_LOG_E(nodeName, "epRecvCountShape is null."), return false);
    OPS_ERR_IF(epRecvCountStorageShape->GetStorageShape().GetDimNum() != ONE_DIM,
                    OPS_LOG_E(nodeName, "epRecvCountShape dims must be 1, but current dim num is %lu.",
                            epRecvCountStorageShape->GetStorageShape().GetDimNum()),
                    return false);
    OPS_LOG_D(nodeName, "epRecvCount dim0 = %ld", epRecvCountStorageShape->GetStorageShape().GetDim(0));

    const gert::StorageShape *tpRecvCountStorageShape = context.GetOutputShape(OUTPUT_TP_RECV_COUNTS_INDEX);
    OPS_ERR_IF(tpRecvCountStorageShape == nullptr, OPS_LOG_E(nodeName, "tpRecvCountShape is null."), return false);
    OPS_ERR_IF(tpRecvCountStorageShape->GetStorageShape().GetDimNum() != ONE_DIM,
                    OPS_LOG_E(nodeName, "tpRecvCountShape dims must be 1, but current dim num is %lu.",
                            tpRecvCountStorageShape->GetStorageShape().GetDimNum()),
                    return false);
    OPS_LOG_D(nodeName, "tpRecvCount dim0 = %ld", tpRecvCountStorageShape->GetStorageShape().GetDim(0));

    return true;
}

static bool CheckTensorDataType(const gert::TilingContext &context, const char *nodeName, const bool isScales,
                                const uint32_t quantMode)
{
    auto xDesc = context.GetInputDesc(X_INDEX);
    OPS_ERR_IF(xDesc == nullptr, OPS_LOG_E(nodeName, "xDesc is null."), return false);
    OPS_ERR_IF((xDesc->GetDataType() != ge::DT_BF16) && (xDesc->GetDataType() != ge::DT_FLOAT16),
                    OPS_LOG_E(nodeName, "x datatype is invalid, datatype should be bf16 or float16, but is %d.",
                            static_cast<ge::DataType>(xDesc->GetDataType())),
                    return false);

    auto expertIdDesc = context.GetInputDesc(EXPERT_IDS_INDEX);
    OPS_ERR_IF(expertIdDesc == nullptr, OPS_LOG_E(nodeName, "expertIdDesc is null."), return false);
    OPS_ERR_IF(expertIdDesc->GetDataType() != ge::DT_INT32,
                    OPS_LOG_E(nodeName, "expertId datatype is invalid, datatype should be int32, but is %d.",
                            static_cast<ge::DataType>(expertIdDesc->GetDataType())),
                    return false);

    if (isScales) {
        auto scalesDesc = context.GetOptionalInputDesc(SCALES_INDEX);
        OPS_ERR_IF(scalesDesc == nullptr, OPS_LOG_E(nodeName, "scalesDesc is null."), return false);
        OPS_ERR_IF(scalesDesc->GetDataType() != ge::DT_FLOAT,
                        OPS_LOG_E(nodeName, "scales datatype is invalid, datatype should be float, but is %d.",
                                static_cast<ge::DataType>(scalesDesc->GetDataType())),
                        return false);
    }

    auto expandXDesc = context.GetOutputDesc(OUTPUT_EXPAND_X_INDEX);
    OPS_ERR_IF(expandXDesc == nullptr, OPS_LOG_E(nodeName, "expandXDesc is null."), return false);
    if (quantMode != NO_SCALES) {
        OPS_ERR_IF(expandXDesc->GetDataType() != ge::DT_INT8,
                        OPS_LOG_E(nodeName, "expandX datatype is invalid, datatype should be int8, but is %d.",
                                static_cast<ge::DataType>(expandXDesc->GetDataType())),
                        return false);
    } else {
        OPS_ERR_IF(
            expandXDesc->GetDataType() != xDesc->GetDataType(),
            OPS_LOG_E(nodeName, "expandX dataType is invalid, dataType should be equal to x dataType %d, but is %d.",
                    static_cast<ge::DataType>(xDesc->GetDataType()),
                    static_cast<ge::DataType>(expandXDesc->GetDataType())),
            return false);
    }

    if (quantMode == DYNAMIC_SCALES) {
        auto dynamicScalesDesc = context.GetOutputDesc(OUTPUT_DYNAMIC_SCALES_INDEX);
        OPS_ERR_IF(dynamicScalesDesc == nullptr, OPS_LOG_E(nodeName, "dynamicScalesDesc is null."), return false);
        OPS_ERR_IF(dynamicScalesDesc->GetDataType() != ge::DT_FLOAT,
                        OPS_LOG_E(nodeName, "dynamicScales datatype is invalid, datatype should be float, but is %d.",
                                static_cast<ge::DataType>(dynamicScalesDesc->GetDataType())),
                        return false);
    }

    auto expandIdxDesc = context.GetOutputDesc(OUTPUT_EXPAND_IDX_INDEX);
    OPS_ERR_IF(expandIdxDesc == nullptr, OPS_LOG_E(nodeName, "expandIdxDesc is null."), return false);
    OPS_ERR_IF(expandIdxDesc->GetDataType() != ge::DT_INT32,
                    OPS_LOG_E(nodeName, "expandIdx datatype is invalid, datatype should be int32, but is %d.",
                            static_cast<ge::DataType>(expandIdxDesc->GetDataType())),
                    return false);

    auto expertTokenNumsDesc = context.GetOutputDesc(OUTPUT_EXPERT_TOKEN_NUMS_INDEX);
    OPS_ERR_IF(expertTokenNumsDesc == nullptr, OPS_LOG_E(nodeName, "expertTokenNumsDesc is null."), return false);
    OPS_ERR_IF(expertTokenNumsDesc->GetDataType() != ge::DT_INT64,
                    OPS_LOG_E(nodeName, "expertTokenNums datatype is invalid, datatype should be int64, but is %d.",
                            static_cast<ge::DataType>(expertTokenNumsDesc->GetDataType())),
                    return false);

    auto epRecvCountsDesc = context.GetOutputDesc(OUTPUT_EP_RECV_COUNTS_INDEX);
    OPS_ERR_IF(epRecvCountsDesc == nullptr, OPS_LOG_E(nodeName, "epRecvCountsDesc is null."), return false);
    OPS_ERR_IF(epRecvCountsDesc->GetDataType() != ge::DT_INT32,
                    OPS_LOG_E(nodeName, "epRecvCounts datatype is invalid, datatype should be int32, but is %d.",
                            static_cast<ge::DataType>(epRecvCountsDesc->GetDataType())),
                    return false);

    auto tpRecvCountsDesc = context.GetOutputDesc(OUTPUT_TP_RECV_COUNTS_INDEX);
    OPS_ERR_IF(tpRecvCountsDesc == nullptr, OPS_LOG_E(nodeName, "tpRecvCountsDesc is null."), return false);
    OPS_ERR_IF(tpRecvCountsDesc->GetDataType() != ge::DT_INT32,
                    OPS_LOG_E(nodeName, "tpRecvCounts datatype is invalid, datatype should be int32, but is %d.",
                            static_cast<ge::DataType>(tpRecvCountsDesc->GetDataType())),
                    return false);
    return true;
}

static bool CheckTensorFormat(const gert::TilingContext &context, const char *nodeName, const bool isScales,
                              const uint32_t quantMode)
{
    auto xDesc = context.GetInputDesc(X_INDEX);
    OPS_ERR_IF(xDesc == nullptr, OPS_LOG_E(nodeName, "xDesc is null."), return false);
    OPS_ERR_IF(static_cast<ge::Format>(ge::GetPrimaryFormat(xDesc->GetStorageFormat())) == ge::FORMAT_FRACTAL_NZ,
                    OPS_LOG_E(nodeName, "x format is invalid."), return false);

    auto expertIdDesc = context.GetInputDesc(EXPERT_IDS_INDEX);
    OPS_ERR_IF(expertIdDesc == nullptr, OPS_LOG_E(nodeName, "expertIdDesc is null."), return false);
    OPS_ERR_IF(
        static_cast<ge::Format>(ge::GetPrimaryFormat(expertIdDesc->GetStorageFormat())) == ge::FORMAT_FRACTAL_NZ,
        OPS_LOG_E(nodeName, "expertId format is invalid."), return false);

    if (isScales) {
        auto scalesDesc = context.GetOptionalInputDesc(SCALES_INDEX);
        OPS_ERR_IF(scalesDesc == nullptr, OPS_LOG_E(nodeName, "scalesDesc is null."), return false);
        OPS_ERR_IF(
            static_cast<ge::Format>(ge::GetPrimaryFormat(scalesDesc->GetStorageFormat())) == ge::FORMAT_FRACTAL_NZ,
            OPS_LOG_E(nodeName, "scales format is invalid."), return false);
    }

    auto expandXDesc = context.GetOutputDesc(OUTPUT_EXPAND_X_INDEX);
    OPS_ERR_IF(expandXDesc == nullptr, OPS_LOG_E(nodeName, "expandXDesc is null."), return false);
    OPS_ERR_IF(
        static_cast<ge::Format>(ge::GetPrimaryFormat(expandXDesc->GetStorageFormat())) == ge::FORMAT_FRACTAL_NZ,
        OPS_LOG_E(nodeName, "expandX format is invalid."), return false);

    if (quantMode == DYNAMIC_SCALES) {
        auto dynamicScalesDesc = context.GetOutputDesc(OUTPUT_DYNAMIC_SCALES_INDEX);
        OPS_ERR_IF(dynamicScalesDesc == nullptr, OPS_LOG_E(nodeName, "dynamicScalesDesc is null."), return false);
        OPS_ERR_IF(static_cast<ge::Format>(ge::GetPrimaryFormat(dynamicScalesDesc->GetStorageFormat())) ==
                            ge::FORMAT_FRACTAL_NZ,
                        OPS_LOG_E(nodeName, "dynamicScales format is invalid."), return false);
    }

    auto expandIdxDesc = context.GetOutputDesc(OUTPUT_EXPAND_IDX_INDEX);
    OPS_ERR_IF(expandIdxDesc == nullptr, OPS_LOG_E(nodeName, "expandIdxDesc is null."), return false);
    OPS_ERR_IF(
        static_cast<ge::Format>(ge::GetPrimaryFormat(expandIdxDesc->GetStorageFormat())) == ge::FORMAT_FRACTAL_NZ,
        OPS_LOG_E(nodeName, "expandIdx format is invalid."), return false);

    auto expertTokenNumsDesc = context.GetOutputDesc(OUTPUT_EXPERT_TOKEN_NUMS_INDEX);
    OPS_ERR_IF(expertTokenNumsDesc == nullptr, OPS_LOG_E(nodeName, "expertTokenNumsDesc is null."), return false);
    OPS_ERR_IF(
        static_cast<ge::Format>(ge::GetPrimaryFormat(expertTokenNumsDesc->GetStorageFormat())) == ge::FORMAT_FRACTAL_NZ,
        OPS_LOG_E(nodeName, "expertTokenNums format is invalid."), return false);

    auto epRecvCountsDesc = context.GetOutputDesc(OUTPUT_EP_RECV_COUNTS_INDEX);
    OPS_ERR_IF(epRecvCountsDesc == nullptr, OPS_LOG_E(nodeName, "epRecvCountsDesc is null."), return false);
    OPS_ERR_IF(
        static_cast<ge::Format>(ge::GetPrimaryFormat(epRecvCountsDesc->GetStorageFormat())) == ge::FORMAT_FRACTAL_NZ,
        OPS_LOG_E(nodeName, "epRecvCounts format is invalid."), return false);

    auto tpRecvCountsDesc = context.GetOutputDesc(OUTPUT_TP_RECV_COUNTS_INDEX);
    OPS_ERR_IF(tpRecvCountsDesc == nullptr, OPS_LOG_E(nodeName, "tpRecvCountsDesc is null."), return false);
    OPS_ERR_IF(
        static_cast<ge::Format>(ge::GetPrimaryFormat(tpRecvCountsDesc->GetStorageFormat())) == ge::FORMAT_FRACTAL_NZ,
        OPS_LOG_E(nodeName, "tpRecvCounts format is invalid."), return false);
    return true;
}

static ge::graphStatus GetAttrAndSetTilingData(const gert::TilingContext &context, const char *nodeName,
                                               MoeDispatchShmemTilingData &tilingData)
{
    auto attrs = context.GetAttrs();
    OPS_ERR_IF(attrs == nullptr, OPS_LOG_E(nodeName, "attrs is nullptr."), return ge::GRAPH_FAILED);

    auto epWorldSizePtr = attrs->GetAttrPointer<int64_t>(ATTR_EP_WORLD_SIZE_INDEX);
    auto tpWorldSizePtr = attrs->GetAttrPointer<int64_t>(ATTR_TP_WORLD_SIZE_INDEX);
    auto epRankIdPtr = attrs->GetAttrPointer<int64_t>(ATTR_EP_RANK_ID_INDEX);
    auto tpRankIdPtr = attrs->GetAttrPointer<int64_t>(ATTR_TP_RANK_ID_INDEX);
    auto expertShardPtr = attrs->GetAttrPointer<int64_t>(ATTR_EXPERT_SHARD_TYPE_INDEX);
    auto sharedExpertRankNumPtr = attrs->GetAttrPointer<int64_t>(ATTR_SHARED_EXPERT_RANK_NUM_INDEX);
    auto moeExpertNumPtr = attrs->GetAttrPointer<int64_t>(ATTR_MOE_EXPERT_NUM_INDEX);
    auto quantModePtr = attrs->GetAttrPointer<int64_t>(ATTR_QUANT_MODE_INDEX);
    auto sharedExpertNumPtr = attrs->GetAttrPointer<int64_t>(static_cast<int>(ATTR_SHARED_EXPERT_NUM_INDEX));
    auto expertTokenNumsTypePtr = attrs->GetAttrPointer<int64_t>(static_cast<int>(ATTR_EXPERT_TOKEN_NUMS_TYPE_INDEX));
    auto shmemPtr = attrs->GetAttrPointer<int64_t>(ATTR_EXT_INFO_INDEX);

    OPS_LOG_I(nodeName, "shmemPtr inside tiling is %ld", shmemPtr);

    // 判空
    OPS_ERR_IF(epWorldSizePtr == nullptr, OPS_LOG_E(nodeName, "epWorldSizePtr is null."), return ge::GRAPH_FAILED);
    OPS_ERR_IF(tpWorldSizePtr == nullptr, OPS_LOG_E(nodeName, "tpWorldSizePtr is null."), return ge::GRAPH_FAILED);
    OPS_ERR_IF(epRankIdPtr == nullptr, OPS_LOG_E(nodeName, "epRankIdPtr is null."), return ge::GRAPH_FAILED);
    OPS_ERR_IF(tpRankIdPtr == nullptr, OPS_LOG_E(nodeName, "tpRankIdPtr is null."), return ge::GRAPH_FAILED);
    OPS_ERR_IF(expertShardPtr == nullptr, OPS_LOG_E(nodeName, "expertShardPtr is null."), return ge::GRAPH_FAILED);
    OPS_ERR_IF(sharedExpertRankNumPtr == nullptr, OPS_LOG_E(nodeName, "sharedExpertRankNumPtr is null."),
                    return ge::GRAPH_FAILED);
    OPS_ERR_IF(moeExpertNumPtr == nullptr, OPS_LOG_E(nodeName, "moeExpertNumPtr is null."), return ge::GRAPH_FAILED);
    OPS_ERR_IF(quantModePtr == nullptr, OPS_LOG_E(nodeName, "quantModePtr is null."), return ge::GRAPH_FAILED);
    OPS_ERR_IF(sharedExpertNumPtr == nullptr, OPS_LOG_E(nodeName, "sharedExpertNum is null."),
                    return ge::GRAPH_FAILED);
    OPS_ERR_IF(expertTokenNumsTypePtr == nullptr, OPS_LOG_E(nodeName, "expertTokenNumsType is null."),
                    return ge::GRAPH_FAILED);
    // 判断是否满足uint32_t及其他限制
    OPS_ERR_IF((*epWorldSizePtr <= 0) || (*epWorldSizePtr > MAX_EP_WORLD_SIZE),
                    OPS_LOG_E(nodeName, "epWorldSize is invalid, only support (0, %ld], but got epWorldSize=%ld.",
                            MAX_EP_WORLD_SIZE, *epWorldSizePtr),
                    return ge::GRAPH_FAILED);
    OPS_ERR_IF((*tpWorldSizePtr < 0) || (*tpWorldSizePtr > MAX_TP_WORLD_SIZE),
                    OPS_LOG_E(nodeName, "tpWorldSize is invalid, only support [0, %ld], but got tpWorldSize=%ld.",
                            MAX_TP_WORLD_SIZE, *tpWorldSizePtr),
                    return ge::GRAPH_FAILED);
    OPS_ERR_IF((*epRankIdPtr < 0) || (*epRankIdPtr >= *epWorldSizePtr),
                    OPS_LOG_E(nodeName, "epRankId is invalid, only support [0, %ld), but got epRankId=%ld.",
                            *epWorldSizePtr, *epRankIdPtr),
                    return ge::GRAPH_FAILED);
    if (*tpWorldSizePtr > 1) {
        OPS_ERR_IF((*tpRankIdPtr < 0) || (*tpRankIdPtr >= *tpWorldSizePtr),
                        OPS_LOG_E(nodeName, "tpRankId is invalid, only support [0, %ld), but got tpRankId=%ld.",
                                *tpWorldSizePtr, *tpRankIdPtr),
                        return ge::GRAPH_FAILED);
    } else {
        OPS_ERR_IF(
            *tpRankIdPtr != 0,
            OPS_LOG_E(nodeName, "tpRankId is invalid, NoTp mode only support 0, but got tpRankId=%ld.", *tpRankIdPtr),
            return ge::GRAPH_FAILED);
    }
    OPS_ERR_IF(*expertShardPtr != 0,
                    OPS_LOG_E(nodeName, "expertSharedType is invalid, only support 0, but got expertSharedType=%ld.",
                            *expertShardPtr),
                    return ge::GRAPH_FAILED);
    OPS_ERR_IF(
        (*sharedExpertRankNumPtr < 0) || (*sharedExpertRankNumPtr >= *epWorldSizePtr),
        OPS_LOG_E(nodeName, "sharedExpertRankNum is invalid, only support [0, %ld), but got sharedExpertRankNum=%ld.",
                *epWorldSizePtr, *sharedExpertRankNumPtr),
        return ge::GRAPH_FAILED);
    OPS_ERR_IF((*moeExpertNumPtr <= 0) || (*moeExpertNumPtr > MOE_EXPERT_MAX_NUM),
                    OPS_LOG_E(nodeName, "moeExpertNum is invalid, only support (0, %ld], but got moeExpertNum=%ld.",
                            MOE_EXPERT_MAX_NUM, *moeExpertNumPtr),
                    return ge::GRAPH_FAILED);
    OPS_ERR_IF(
        (*quantModePtr < static_cast<int64_t>(NO_SCALES)) || (*quantModePtr > static_cast<int64_t>(DYNAMIC_SCALES)),
        OPS_LOG_E(nodeName, "quantMode is invalid, only support [0, %u], but got quantMode=%ld.", DYNAMIC_SCALES,
                *quantModePtr),
        return ge::GRAPH_FAILED);
    OPS_ERR_IF(
        *sharedExpertNumPtr != 1,
        OPS_LOG_E(nodeName, "sharedExpertNum only support 1, but got sharedExpertNum=%ld.", *sharedExpertNumPtr),
        return ge::GRAPH_FAILED);
    OPS_ERR_IF((*expertTokenNumsTypePtr != 0) && (*expertTokenNumsTypePtr != 1),
                    OPS_LOG_E(nodeName, "expertTokenNumsType only support 0 or 1, but got expertTokenNumsType=%ld.",
                            *expertTokenNumsTypePtr),
                    return ge::GRAPH_FAILED);

    tilingData.moeDistributeDispatchInfo.epWorldSize = static_cast<uint32_t>(*epWorldSizePtr);
    tilingData.moeDistributeDispatchInfo.tpWorldSize = static_cast<uint32_t>(*tpWorldSizePtr);
    tilingData.moeDistributeDispatchInfo.epRankId = static_cast<uint32_t>(*epRankIdPtr);
    tilingData.moeDistributeDispatchInfo.tpRankId = static_cast<uint32_t>(*tpRankIdPtr);
    tilingData.moeDistributeDispatchInfo.expertSharedType = static_cast<uint32_t>(*expertShardPtr);
    tilingData.moeDistributeDispatchInfo.sharedExpertRankNum = static_cast<uint32_t>(*sharedExpertRankNumPtr);
    tilingData.moeDistributeDispatchInfo.moeExpertNum = static_cast<uint32_t>(*moeExpertNumPtr);
    tilingData.moeDistributeDispatchInfo.quantMode = static_cast<uint32_t>(*quantModePtr);
    tilingData.moeDistributeDispatchInfo.expertTokenNumsType = static_cast<uint32_t>(*expertTokenNumsTypePtr);
    tilingData.moeDistributeDispatchInfo.shmemptr = static_cast<uint64_t>(*shmemPtr);

    OPS_LOG_I(nodeName, "shmemPtr send to tilingInfo is %ld", tilingData.moeDistributeDispatchInfo.shmemptr);

    return ge::GRAPH_SUCCESS;
}

static ge::graphStatus CheckAttrs(const gert::TilingContext &context, const char *nodeName,
                                  MoeDispatchShmemTilingData &tilingData, uint32_t &localMoeExpertNum)
{
    uint32_t epWorldSize = tilingData.moeDistributeDispatchInfo.epWorldSize;
    uint32_t tpWorldSize = tilingData.moeDistributeDispatchInfo.tpWorldSize;
    uint32_t moeExpertNum = tilingData.moeDistributeDispatchInfo.moeExpertNum;
    uint32_t sharedExpertRankNum = tilingData.moeDistributeDispatchInfo.sharedExpertRankNum;
    // 校验ep能否均分共享专家
    OPS_ERR_IF((sharedExpertRankNum != 0) && (epWorldSize % sharedExpertRankNum != 0),
                    OPS_LOG_E(nodeName,
                            "epWorldSize should be divisible by sharedExpertRankNum, but epWorldSize=%u, "
                            "sharedExpertRankNum=%u.",
                            epWorldSize, sharedExpertRankNum),
                    return ge::GRAPH_FAILED);
    // 校验moe专家数量能否均分给多机
    localMoeExpertNum = moeExpertNum / (epWorldSize - sharedExpertRankNum);
    OPS_ERR_IF(moeExpertNum % (epWorldSize - sharedExpertRankNum) != 0,
                    OPS_LOG_E(nodeName,
                            "moeExpertNum should be divisible by (epWorldSize - sharedExpertRankNum), "
                            "but moeExpertNum=%u, epWorldSize=%u, sharedExpertRankNum=%u.",
                            moeExpertNum, epWorldSize, sharedExpertRankNum),
                    return ge::GRAPH_FAILED);
    OPS_ERR_IF(localMoeExpertNum <= 0,
                    OPS_LOG_E(nodeName, "localMoeExpertNum is invalid, localMoeExpertNum = %u", localMoeExpertNum),
                    return ge::GRAPH_FAILED);
    OPS_ERR_IF((tpWorldSize > 1) && (localMoeExpertNum > 1),
                    OPS_LOG_E(nodeName,
                            "Cannot support multi-moeExpert %u "
                            "in a rank when tpWorldSize = %u > 1",
                            localMoeExpertNum, tpWorldSize),
                    return ge::GRAPH_FAILED);
    // 检验epWorldSize是否是8的倍数
    OPS_ERR_IF(epWorldSize % 8 != 0,
                    OPS_LOG_E(nodeName, "epWorldSize should be divisible by 8, but got epWorldSize = %u.", epWorldSize),
                    return ge::GRAPH_FAILED);

    OPS_ERR_IF(
        (256 % epWorldSize != 0) && (epWorldSize % 144 != 0),
        OPS_LOG_E(nodeName,
                "epWorldSize should be in the list[8, 16, 32, 64, 128, 144, 256, 288], but got epWorldSize = %u.",
                epWorldSize),
        return ge::GRAPH_FAILED);
    // 校验输入x的dim 0并设bs
    const gert::StorageShape *xStorageShape = context.GetInputShape(X_INDEX);
    OPS_ERR_IF(xStorageShape == nullptr, OPS_LOG_E(nodeName, "xStorageShape is nullptr."), return ge::GRAPH_FAILED);
    const int64_t xDim0 = xStorageShape->GetStorageShape().GetDim(0);
    OPS_ERR_IF((xDim0 > BS_UPPER_BOUND) || (xDim0 <= 0),
                    OPS_LOG_E(nodeName, "xDim0(BS) is invalid. Should be between [1, %ld], but got xDim0=%ld.",
                            BS_UPPER_BOUND, xDim0),
                    return ge::GRAPH_FAILED);
    tilingData.moeDistributeDispatchInfo.bs = static_cast<uint32_t>(xDim0);
    // 校验globalBS
    auto attrs = context.GetAttrs();
    OPS_ERR_IF(attrs == nullptr, OPS_LOG_E(nodeName, "attrs is nullptr."), return ge::GRAPH_FAILED);
    auto globalBsPtr = attrs->GetAttrPointer<int64_t>(ATTR_GLOBAL_BS_INDEX);
    OPS_ERR_IF(globalBsPtr == nullptr, OPS_LOG_E(nodeName, "globalBsPtr is nullptr."), return ge::GRAPH_FAILED);
    OPS_LOG_D(nodeName, "MoeDispatchShmem *globalBsPtr = %ld, bs = %ld, epWorldSize = %u\n", *globalBsPtr,
              xDim0, epWorldSize);
    OPS_ERR_IF(
        (*globalBsPtr != 0) && ((*globalBsPtr < xDim0 * static_cast<int64_t>(epWorldSize)) ||
                                ((*globalBsPtr) % (static_cast<int64_t>(epWorldSize)) != 0)),
        OPS_LOG_E(nodeName,
                "globalBS is invalid, only "
                "support 0 or maxBs(maxBs is the largest bs on all ranks) * epWorldSize, but got globalBS=%ld, "
                "bs=%ld, epWorldSize=%u.",
                *globalBsPtr, xDim0, epWorldSize),
        return ge::GRAPH_FAILED);
    if (*globalBsPtr == 0) {
        tilingData.moeDistributeDispatchInfo.globalBs = static_cast<uint32_t>(xDim0) * epWorldSize;
    } else {
        tilingData.moeDistributeDispatchInfo.globalBs = static_cast<uint32_t>(*globalBsPtr);
    }
    return ge::GRAPH_SUCCESS;
}

static ge::graphStatus CheckTensorShape(const gert::TilingContext &context, const char *nodeName,
                                        MoeDispatchShmemTilingData &tilingData, const uint32_t quantMode,
                                        const bool isScales, const bool isSharedExpert, const int64_t localMoeExpertNum)
{
    uint32_t A = 0;
    uint32_t globalBs = tilingData.moeDistributeDispatchInfo.globalBs;
    uint32_t sharedExpertRankNum = tilingData.moeDistributeDispatchInfo.sharedExpertRankNum;
    // 校验输入x的维度1并设h, bs已校验过
    const gert::StorageShape *xStorageShape = context.GetInputShape(X_INDEX);
    OPS_ERR_IF(xStorageShape == nullptr, OPS_LOG_E(nodeName, "xStorageShape is nullptr."), return ge::GRAPH_FAILED);
    const int64_t xDim0 = xStorageShape->GetStorageShape().GetDim(0);
    const int64_t xDim1 = xStorageShape->GetStorageShape().GetDim(1);
    OPS_ERR_IF((xDim1 != 7168), OPS_LOG_E(nodeName, "xShape dims1(H) only supports 7168, but got %ld.", xDim1),
                    return ge::GRAPH_FAILED);
    tilingData.moeDistributeDispatchInfo.h = static_cast<uint32_t>(xDim1);
    // 校验expert_id的维度并设k
    int64_t moeExpertNum = static_cast<int64_t>(tilingData.moeDistributeDispatchInfo.moeExpertNum);
    const gert::StorageShape *expertIdStorageShape = context.GetInputShape(EXPERT_IDS_INDEX);
    OPS_ERR_IF(expertIdStorageShape == nullptr, OPS_LOG_E(nodeName, "expertIdStorageShape is nullptr."),
                    return ge::GRAPH_FAILED);
    const int64_t expertIdsDim0 = expertIdStorageShape->GetStorageShape().GetDim(0);
    const int64_t expertIdsDim1 = expertIdStorageShape->GetStorageShape().GetDim(1);
    OPS_ERR_IF(xDim0 != expertIdsDim0,
                    OPS_LOG_E(nodeName,
                            "xShape's dim0 not equal to expertIdShape's dim0, "
                            "xShape's dim0 is %ld, expertIdShape's dim0 is %ld.",
                            xDim0, expertIdsDim0),
                    return ge::GRAPH_FAILED);
    OPS_ERR_IF(
        (expertIdsDim1 <= 0) || (expertIdsDim1 > K_MAX),
        OPS_LOG_E(nodeName, "expertIdShape's dim1(k) should be in (0, %ld], but got expertIdShape's dim1=%ld.", K_MAX,
                expertIdsDim1),
        return ge::GRAPH_FAILED);
    tilingData.moeDistributeDispatchInfo.k = static_cast<uint32_t>(expertIdsDim1);
    // 校验scales的维度
    if (isScales) {
        const gert::StorageShape *scalesStorageShape = context.GetOptionalInputShape(SCALES_INDEX);
        OPS_ERR_IF(scalesStorageShape == nullptr, OPS_LOG_E(nodeName, "scalesStorageShape is nullptr."),
                        return ge::GRAPH_FAILED);
        const int64_t scalesDim0 = scalesStorageShape->GetStorageShape().GetDim(0);
        const int64_t scalesDim1 = scalesStorageShape->GetStorageShape().GetDim(1);
        if (sharedExpertRankNum == 0U) {
            OPS_ERR_IF(
                scalesDim0 != moeExpertNum,
                OPS_LOG_E(nodeName,
                        "scales's dim0 not equal to moeExpertNum, scales's dim0 is %ld, moeExpertNum is %ld.",
                        scalesDim0, moeExpertNum),
                return ge::GRAPH_FAILED);
        } else {
            OPS_ERR_IF(
                scalesDim0 != (moeExpertNum + 1),
                OPS_LOG_E(nodeName,
                        "scales's dim0 not equal to moeExpertNum + 1, scales's dim0 is %ld, moeExpertNum + 1 is %ld.",
                        scalesDim0, moeExpertNum + 1),
                return ge::GRAPH_FAILED);
        }
        OPS_ERR_IF(xDim1 != scalesDim1,
                        OPS_LOG_E(nodeName,
                                "scales's dim1 not equal to xShape's dim1, "
                                "xShape's dim1 is %ld, scales's dim1 is %ld.",
                                xDim1, scalesDim1),
                        return ge::GRAPH_FAILED);
    }

    if (isSharedExpert && sharedExpertRankNum != 0) {  // 本卡为共享专家
        A = globalBs / sharedExpertRankNum;
    } else {  // 本卡为moe专家
        A = globalBs * std::min(localMoeExpertNum, expertIdsDim1);
    }
    // 校验expandX的维度
    int64_t tpWorldSize = static_cast<int64_t>(tilingData.moeDistributeDispatchInfo.tpWorldSize);
    const gert::StorageShape *expandXStorageShape = context.GetOutputShape(OUTPUT_EXPAND_X_INDEX);
    OPS_ERR_IF(expandXStorageShape == nullptr, OPS_LOG_E(nodeName, "expandXStorageShape is nullptr."),
                    return ge::GRAPH_FAILED);
    const int64_t expandXDim0 = expandXStorageShape->GetStorageShape().GetDim(0);
    const int64_t expandXDim1 = expandXStorageShape->GetStorageShape().GetDim(1);
    OPS_ERR_IF(expandXDim0 < tpWorldSize * static_cast<int64_t>(A),
                    OPS_LOG_E(nodeName,
                            "expandX's dim0 not greater than or equal to A*tpWorldSize, "
                            "expandX's dim0 is %ld, A*tpWorldSize is %ld.",
                            expandXDim0, tpWorldSize * A),
                    return ge::GRAPH_FAILED);
    OPS_ERR_IF(xDim1 != expandXDim1,
                    OPS_LOG_E(nodeName,
                            "expandX's dim1 not equal to xShape's dim1, "
                            "xShape's dim1 is %ld, expandX's dim1 is %ld.",
                            xDim1, expandXDim1),
                    return ge::GRAPH_FAILED);
    // 校验dynamicScales的维度
    if (quantMode != NO_SCALES) {
        const gert::StorageShape *dynamicScalesStorageShape = context.GetOutputShape(OUTPUT_DYNAMIC_SCALES_INDEX);
        OPS_ERR_IF(dynamicScalesStorageShape == nullptr,
                        OPS_LOG_E(nodeName, "dynamicScalesStorageShape is nullptr."), return ge::GRAPH_FAILED);
        const int64_t dynamicScalesDim0 = dynamicScalesStorageShape->GetStorageShape().GetDim(0);
        OPS_ERR_IF(dynamicScalesDim0 < static_cast<int64_t>(A) * tpWorldSize,
                        OPS_LOG_E(nodeName,
                                "dynamicScales's dim0 should be equal to or greater than A*tpWorldSize, "
                                "dynamicScales's dim0 is %ld, A*tpWorldSize is %ld.",
                                dynamicScalesDim0, A * tpWorldSize),
                        return ge::GRAPH_FAILED);
    }
    // 校验expandIdx的维度
    const gert::StorageShape *expandIdxStorageShape = context.GetOutputShape(OUTPUT_EXPAND_IDX_INDEX);
    OPS_ERR_IF(expandIdxStorageShape == nullptr, OPS_LOG_E(nodeName, "expandIdxStorageShape is nullptr."),
                    return ge::GRAPH_FAILED);
    const int64_t expandIdxDim0 = expandIdxStorageShape->GetStorageShape().GetDim(0);
    OPS_ERR_IF(expandIdxDim0 != expertIdsDim1 * xDim0,
                    OPS_LOG_E(nodeName, "expandIdxDim0 != bs * k, expandIdxDim0 is %ld, bs * k is %ld.", expandIdxDim0,
                            xDim0 * expertIdsDim1),
                    return ge::GRAPH_FAILED);
    // 校验expertTokenNums的维度
    const gert::StorageShape *expertTokenNumsStorageShape = context.GetOutputShape(OUTPUT_EXPERT_TOKEN_NUMS_INDEX);
    OPS_ERR_IF(expertTokenNumsStorageShape == nullptr,
                    OPS_LOG_E(nodeName, "expertTokenNumsStorageShape is nullptr."), return ge::GRAPH_FAILED);
    const int64_t expertTokenNumsDim0 = expertTokenNumsStorageShape->GetStorageShape().GetDim(0);
    if (isSharedExpert) {
        OPS_ERR_IF(expertTokenNumsDim0 != 1,
                        OPS_LOG_E(nodeName, "shared expertTokenNums's dim0 %ld not equal to 1.", expertTokenNumsDim0),
                        return ge::GRAPH_FAILED);
    } else {
        OPS_ERR_IF(
            expertTokenNumsDim0 != localMoeExpertNum,
            OPS_LOG_E(nodeName,
                    "moe expertTokenNums's Dim0 not equal to localMoeExpertNum, expertTokenNumsDim0 is %ld, "
                    "localMoeExpertNum is %ld.",
                    expertTokenNumsDim0, localMoeExpertNum),
            return ge::GRAPH_FAILED);
    }
    // 校验epRecvCount和tpRecvCount的维度
    int64_t epWorldSize = static_cast<int64_t>(tilingData.moeDistributeDispatchInfo.epWorldSize);
    const gert::StorageShape *epRecvCountStorageShape = context.GetOutputShape(OUTPUT_EP_RECV_COUNTS_INDEX);
    const gert::StorageShape *tpRecvCountStorageShape = context.GetOutputShape(OUTPUT_TP_RECV_COUNTS_INDEX);
    OPS_ERR_IF(epRecvCountStorageShape == nullptr, OPS_LOG_E(nodeName, "epRecvCountStorageShape is nullptr."),
                    return ge::GRAPH_FAILED);
    OPS_ERR_IF(tpRecvCountStorageShape == nullptr, OPS_LOG_E(nodeName, "tpRecvCountStorageShape is nullptr."),
                    return ge::GRAPH_FAILED);
    const int64_t epRecvCountDim0 = epRecvCountStorageShape->GetStorageShape().GetDim(0);
    const int64_t tpRecvCountDim0 = tpRecvCountStorageShape->GetStorageShape().GetDim(0);
    int64_t epRecvCount = (isSharedExpert) ? epWorldSize : epWorldSize * localMoeExpertNum;
    if (tpWorldSize == MAX_TP_WORLD_SIZE) {
        epRecvCount *= tpWorldSize;
    }
    OPS_ERR_IF(
        epRecvCountDim0 < epRecvCount,
        OPS_LOG_E(
            nodeName,
            "dimension 0 of epRecvCount should be greater than or equal to epWorldSize * localMoeExpertNum * "
            "tpWorldSize, "
            "but dimension 0 of epRecvCount is %ld, epWorldSize is %ld, localMoeExpertNum is %ld, tpWorldSize is %ld.",
            epRecvCountDim0, epWorldSize, localMoeExpertNum, tpWorldSize),
        return ge::GRAPH_FAILED);
    OPS_ERR_IF(
        tpRecvCountDim0 != tpWorldSize,
        OPS_LOG_E(nodeName,
                "dimension 0 of tpRecvCount should be equal to tpWorldSize, but dimension 0 of tpRecvCount is %ld, "
                "tpWorldSize is %ld.",
                tpRecvCountDim0, tpWorldSize),
        return ge::GRAPH_FAILED);
    return ge::GRAPH_SUCCESS;
}

static ge::graphStatus TilingCheckMoeDistributeDispatch(gert::TilingContext &context, const char *nodeName,
                                                        const bool isScales, const uint32_t quantMode)
{
    OPS_ERR_IF(!CheckTensorDim(context, nodeName, isScales, quantMode),
                    OPS_LOG_E(nodeName, "params shape is invalid."), return ge::GRAPH_FAILED);
    OPS_ERR_IF(!CheckTensorDataType(context, nodeName, isScales, quantMode),
                    OPS_LOG_E(nodeName, "params dataType is invalid."), return ge::GRAPH_FAILED);
    OPS_ERR_IF(!CheckTensorFormat(context, nodeName, isScales, quantMode),
                    OPS_LOG_E(nodeName, "params format is invalid."), return ge::GRAPH_FAILED);
    return ge::GRAPH_SUCCESS;
}

static void CalTilingKey(uint64_t &tilingKey, const bool isScales, const uint32_t quantMode, const uint32_t tpWorldSize)
{
    tilingKey += static_cast<uint64_t>(quantMode);
    tilingKey += static_cast<uint64_t>((isScales ? NUM_10 : 0));
    if (tpWorldSize == MAX_TP_WORLD_SIZE) {
        tilingKey += static_cast<uint64_t>(NUM_100);
    }
    return;
}

static void SetHcommCfg(const gert::TilingContext &context, MoeDispatchShmemTilingData &tiling,
                        const std::string groupEp, const std::string groupTp)
{
    const char *nodeName = context.GetNodeName();
    OPS_LOG_D(nodeName, "MoeDispatchShmem groupEp = %s, groupTp = %s", groupEp.c_str(), groupTp.c_str());
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

static ge::graphStatus MoeDistributeDispatchA3TilingFuncImpl(gert::TilingContext &context)
{
    const char *nodeName = context.GetNodeName();
    MoeDispatchShmemTilingData *tilingData = context.GetTilingData<MoeDispatchShmemTilingData>();
    OPS_ERR_IF(tilingData == nullptr, OPS_LOG_E(nodeName, "tilingData is nullptr."), return ge::GRAPH_FAILED);
    std::string groupEp = "";
    std::string groupTp = "";
    uint32_t quantMode = NO_SCALES;
    bool isScales = false;
    uint32_t localMoeExpertNum = 1;
    OPS_LOG_I(nodeName, "Enter MoeDispatchShmem tiling check func.");
    // 获取入参属性
    OPS_ERR_IF(GetAttrAndSetTilingData(context, nodeName, *tilingData) != ge::GRAPH_SUCCESS,
                    OPS_LOG_E(nodeName, "Get attr and set tiling data failed."), return ge::GRAPH_FAILED);
    // 获取scales
    const gert::StorageShape *scalesStorageShape = context.GetOptionalInputShape(SCALES_INDEX);
    isScales = (scalesStorageShape != nullptr);
    tilingData->moeDistributeDispatchInfo.isQuant = isScales;
    quantMode = tilingData->moeDistributeDispatchInfo.quantMode;
    // 检查quantMode和scales是否匹配
    OPS_ERR_IF(quantMode == STATIC_SCALES, OPS_LOG_E(nodeName, "cannot support static quant now."),
                    return ge::GRAPH_FAILED);
    OPS_ERR_IF((isScales && (quantMode == NO_SCALES)) || ((!isScales) && (quantMode == STATIC_SCALES)),
                    OPS_LOG_E(nodeName, "quant mode and scales not match, isScales is %d, quantMode is %u.",
                            static_cast<int32_t>(isScales), quantMode),
                    return ge::GRAPH_FAILED);
    // 检查输入输出的dim、format、dataType
    OPS_ERR_IF(TilingCheckMoeDistributeDispatch(context, nodeName, isScales, quantMode) != ge::GRAPH_SUCCESS,
                    OPS_LOG_E(nodeName, "Tiling check param failed."), return ge::GRAPH_FAILED);
    // 检查属性的取值是否合法
    OPS_ERR_IF(CheckAttrs(context, nodeName, *tilingData, localMoeExpertNum) != ge::GRAPH_SUCCESS,
                    OPS_LOG_E(nodeName, "Check attr failed."), return ge::GRAPH_FAILED);

    bool isSharedExpert = true;
    uint32_t sharedExpertRankNum = tilingData->moeDistributeDispatchInfo.sharedExpertRankNum;

    uint32_t epRankId = tilingData->moeDistributeDispatchInfo.epRankId;
    if (epRankId >= sharedExpertRankNum) {  // 本卡为moe专家
        isSharedExpert = false;
    }
    // 检查shape各维度并赋值h,k
    OPS_ERR_IF(CheckTensorShape(context, nodeName, *tilingData, quantMode, isScales, isSharedExpert,
                                     static_cast<int64_t>(localMoeExpertNum)) != ge::GRAPH_SUCCESS,
                    OPS_LOG_E(nodeName, "Check tensor shape failed."), return ge::GRAPH_FAILED);
    // 校验win区大小
    uint16_t defaultWindowSize = 200;
    const uint64_t maxWindowSize = static_cast<uint64_t>(defaultWindowSize) * 1024UL * 1024UL;
    uint64_t bs = static_cast<uint64_t>(tilingData->moeDistributeDispatchInfo.bs);
    uint64_t h = static_cast<uint64_t>(tilingData->moeDistributeDispatchInfo.h);
    uint64_t epWorldSize = static_cast<uint64_t>(tilingData->moeDistributeDispatchInfo.epWorldSize);
    uint64_t maxBs = static_cast<uint64_t>(tilingData->moeDistributeDispatchInfo.globalBs) / epWorldSize;
    uint64_t actualSize = epWorldSize * maxBs * h * 2UL * 2UL * static_cast<uint64_t>(localMoeExpertNum);
    tilingData->moeDistributeDispatchInfo.totalWinSize = maxWindowSize;

    OPS_ERR_IF(SetWorkSpace(context, nodeName) != ge::GRAPH_SUCCESS,
                    OPS_LOG_E(nodeName, "Tiling set workspace failed."), return ge::GRAPH_FAILED);
    SetHcommCfg(context, *tilingData, groupEp, groupTp);
    uint32_t tpWorldSize = tilingData->moeDistributeDispatchInfo.tpWorldSize;
    uint64_t tilingKey = INIT_TILINGKEY;
    CalTilingKey(tilingKey, isScales, quantMode, tpWorldSize);
    OPS_LOG_D(nodeName, "tilingKey is %lu", tilingKey);
    context.SetTilingKey(tilingKey);
    uint32_t blockDim = 1U;
    auto ascendcPlatform = platform_ascendc::PlatformAscendC(context.GetPlatformInfo());
    uint32_t aivNum = ascendcPlatform.GetCoreNumAiv();
    uint64_t ubSize = 0UL;
    ascendcPlatform.GetCoreMemSize(platform_ascendc::CoreMemType::UB, ubSize);
    blockDim = ascendcPlatform.CalcTschBlockDim(aivNum, 0, aivNum);
    context.SetBlockDim(blockDim);
    tilingData->moeDistributeDispatchInfo.totalUbSize = ubSize;
    tilingData->moeDistributeDispatchInfo.aivNum = aivNum;
    OPS_LOG_D(nodeName, "blockDim=%u, aivNum=%u, ubSize=%lu", blockDim, aivNum, ubSize);
    PrintTilingDataInfo(nodeName, *tilingData);
    return ge::GRAPH_SUCCESS;
}

static ge::graphStatus MoeDistributeDispatchTilingFunc(gert::TilingContext *context)
{
    ge::graphStatus ret = MoeDistributeDispatchA3TilingFuncImpl(*context);
    return ret;
}

struct MoeDistributeDispatchCompileInfo {};
ge::graphStatus TilingParseForMoeDistributeDispatch(gert::TilingParseContext *context)
{
    (void)context;
    return ge::GRAPH_SUCCESS;
}

IMPL_OP_OPTILING(MoeDispatchShmem)
    .Tiling(MoeDistributeDispatchTilingFunc)
    .TilingParse<MoeDistributeDispatchCompileInfo>(TilingParseForMoeDistributeDispatch);
}  // namespace optiling
