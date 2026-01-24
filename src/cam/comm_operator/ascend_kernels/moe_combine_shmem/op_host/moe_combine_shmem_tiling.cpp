/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2026-2026. All rights reserved.
 * Description: shmem combine tiling function implementation file
 * Create: 2026-01-06
 * Note:
 * History: 2026-01-06 create shmem combine tiling function file
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
#include <type_traits>

#include "graph/utils/type_utils.h"
#include "register/op_def_registry.h"
#include "tiling/tiling_api.h"
#include "tiling/platform/platform_ascendc.h"
#include "ops_log.h"
#include "ops_error.h"
#include "../op_kernel/moe_combine_shmem_tiling.h"

#ifndef OPS_UTILS_LOG_SUB_MOD_NAME
#define OPS_UTILS_LOG_SUB_MOD_NAME "MOE_COMBINE_SHMEM"
#endif

#ifndef OPS_UTILS_LOG_PACKAGE_TYPE
#define OPS_UTILS_LOG_PACKAGE_TYPE "CAM_OPS"
#endif

using namespace ge;
using namespace Moe;

namespace {
constexpr uint32_t EXPAND_X_INDEX = 0;
constexpr uint32_t EXPERT_IDS_INDEX = 1;
constexpr uint32_t EXPAND_IDX_INDEX = 2;
constexpr uint32_t EP_SEND_COUNTS_INDEX = 3;
constexpr uint32_t EXPERT_SCALES_INDEX = 4;
constexpr uint32_t TP_SEND_COUNTS_INDEX = 5;
constexpr uint32_t X_ACTIVE_MASK_INDEX = 6;
constexpr uint32_t OUTPUT_X_INDEX = 0;

constexpr uint32_t ATTR_EP_WORLD_SIZE_INDEX = 0;
constexpr uint32_t ATTR_EP_RANK_ID_INDEX = 1;
constexpr uint32_t ATTR_MOE_EXPERT_NUM_INDEX = 2;
constexpr uint32_t ATTR_TP_WORLD_SIZE_INDEX = 3;
constexpr uint32_t ATTR_TP_RANK_ID_INDEX = 4;
constexpr uint32_t ATTR_EXPERT_SHARD_TYPE_INDEX = 5;
constexpr uint32_t ATTR_SHARED_EXPERT_NUM_INDEX = 6;
constexpr uint32_t ATTR_SHARED_EXPERT_RANK_NUM_INDEX = 7;
constexpr uint32_t ATTR_GLOBAL_BS_INDEX = 8;
constexpr uint32_t ATTR_COMM_QUANT_MODE_INDEX = 9;
constexpr uint32_t ATTR_EXT_INFO_INDEX = 10;

constexpr uint32_t INT8_COMM_QUANT = 2U;
constexpr uint32_t TWO_DIMS = 2U;
constexpr uint32_t ONE_DIM = 1U;
constexpr uint32_t EXPAND_IDX_DIMS = 1U;
constexpr uint64_t INIT_TILINGKEY_TP_2 = 1100UL;
constexpr uint64_t INIT_TILINGKEY_TP_1 = 1000UL;
constexpr uint32_t TILINGKEY_INT8_COMM_QUANT = 20U;
constexpr uint64_t TILING_KEY_BASE_A2 = 2000UL;
constexpr uint64_t TILING_KEY_LAYERED_COMM_A2 = 3000UL;
constexpr uint64_t TILING_KEY_INT8_COMM_QUANT_A2 = 100UL;
constexpr uint32_t ARR_LENGTH = 128U;
constexpr uint32_t OP_TYPE_ALL_TO_ALL = 8U;      // numeric representation of AlltoAll
constexpr uint32_t OP_TYPE_REDUCE_SCATTER = 7U;  // numeric representation of AlltoAll

constexpr int32_t MAX_EP_WORLD_SIZE_A2 = 256;
constexpr int32_t MAX_MOE_EXPERT_NUMS_A2 = 512;
constexpr int32_t MAX_HIDDEN_SIZE_A2 = 7168;
constexpr uint32_t MAX_BATCH_SIZE_LAYERED_A2 = 128;
constexpr uint32_t MAX_BATCH_SIZE_A2 = 256;
constexpr uint32_t RANK_NUM_PER_NODE_A2 = 8;
constexpr uint32_t BLOCK_SIZE_A2 = 32;
constexpr uint32_t MAX_K_VALUE_A2 = 16;
constexpr uint32_t LAYERED_SUPPORT_K = 8;
constexpr uint32_t LAYERED_SUPPORT_K_MAX = 16;
const char *K_INNER_DEBUG = "MoeCombineShmem Tiling Debug";
const size_t MAX_GROUP_NAME_LENGTH = 128UL;
const int64_t MAX_EP_WORLD_SIZE = 288;
const int64_t MAX_TP_WORLD_SIZE = 2;
const int64_t BS_UPPER_BOUND = 512;

constexpr uint32_t SYSTEM_NEED_WORKSPACE = 16 * 1024 * 1024;
constexpr int32_t HCCL_BUFFER_SIZE_DEFAULT = 200 * 1024 * 1024;  // Bytes
constexpr uint32_t VERSION_2 = 2;
constexpr uint32_t HCOMMCNT_2 = 2;
constexpr int64_t MOE_EXPERT_MAX_NUM = 512;
constexpr int64_t K_MAX = 8;
constexpr uint64_t MB_SIZE = 1024UL * 1024UL;

enum class CommQuantMode : int32_t { NON_QUANT = 0, INT12_QUANT = 1, INT8_QUANT = 2 };
using CommQuantModeType = std::underlying_type<CommQuantMode>::type;
}  // namespace

namespace optiling {
static void PrintTilingDataInfo(const char *nodeName, const MoeCombineShmemTilingData &tilingData)
{
    OPS_LOG_D(nodeName, "epWorldSize is %u.", tilingData.moeDistributeCombineInfo.epWorldSize);
    OPS_LOG_D(nodeName, "tpWorldSize is %u.", tilingData.moeDistributeCombineInfo.tpWorldSize);
    OPS_LOG_D(nodeName, "epRankId is %u.", tilingData.moeDistributeCombineInfo.epRankId);
    OPS_LOG_D(nodeName, "tpRankId is %u.", tilingData.moeDistributeCombineInfo.tpRankId);
    OPS_LOG_D(nodeName, "expertShardType is %u.", tilingData.moeDistributeCombineInfo.expertShardType);
    OPS_LOG_D(nodeName, "sharedExpertRankNum is %u.", tilingData.moeDistributeCombineInfo.sharedExpertRankNum);
    OPS_LOG_D(nodeName, "moeExpertNum is %u.", tilingData.moeDistributeCombineInfo.moeExpertNum);
    OPS_LOG_D(nodeName, "moeExpertPerRankNum is %u.", tilingData.moeDistributeCombineInfo.moeExpertPerRankNum);
    OPS_LOG_D(nodeName, "globalBs is %u.", tilingData.moeDistributeCombineInfo.globalBs);
    OPS_LOG_D(nodeName, "bs is %d.", tilingData.moeDistributeCombineInfo.bs);
    OPS_LOG_D(nodeName, "k is %d.", tilingData.moeDistributeCombineInfo.k);
    OPS_LOG_D(nodeName, "h is %d.", tilingData.moeDistributeCombineInfo.h);
    OPS_LOG_D(nodeName, "aivNum is %d.", tilingData.moeDistributeCombineInfo.aivNum);
    OPS_LOG_D(nodeName, "totalUbSize is %ld.", tilingData.moeDistributeCombineInfo.totalUbSize);
    OPS_LOG_D(nodeName, "totalWinSize is %ld.", tilingData.moeDistributeCombineInfo.totalWinSize);
}

static ge::graphStatus GetAttrAndSetTilingData(const gert::TilingContext &context,
                                               MoeCombineShmemTilingData &tilingData, const char *nodeName,
                                               uint32_t &commQuantMode)
{
    auto attrs = context.GetAttrs();
    OPS_ERR_IF(attrs == nullptr, OPS_LOG_E(nodeName, "attrs is null."), return ge::GRAPH_FAILED);

    auto epWorldSizePtr = attrs->GetAttrPointer<int64_t>(ATTR_EP_WORLD_SIZE_INDEX);
    auto tpWorldSizePtr = attrs->GetAttrPointer<int64_t>(ATTR_TP_WORLD_SIZE_INDEX);
    auto epRankIdPtr = attrs->GetAttrPointer<int64_t>(ATTR_EP_RANK_ID_INDEX);
    auto tpRankIdPtr = attrs->GetAttrPointer<int64_t>(ATTR_TP_RANK_ID_INDEX);
    auto expertShardPtr = attrs->GetAttrPointer<int64_t>(ATTR_EXPERT_SHARD_TYPE_INDEX);
    auto sharedExpertRankNumPtr = attrs->GetAttrPointer<int64_t>(ATTR_SHARED_EXPERT_RANK_NUM_INDEX);
    auto moeExpertNumPtr = attrs->GetAttrPointer<int64_t>(ATTR_MOE_EXPERT_NUM_INDEX);
    auto sharedExpertNumPtr = attrs->GetAttrPointer<int64_t>(static_cast<int>(ATTR_SHARED_EXPERT_NUM_INDEX));
    auto commQuantModePtr = attrs->GetAttrPointer<int64_t>(static_cast<int>(ATTR_COMM_QUANT_MODE_INDEX));
    auto shmemPtr = attrs->GetAttrPointer<int64_t>(ATTR_EXT_INFO_INDEX);

    OPS_ERR_IF(epWorldSizePtr == nullptr, OPS_LOG_E(nodeName, "epWorldSize is null."), return ge::GRAPH_FAILED);
    OPS_ERR_IF(tpWorldSizePtr == nullptr, OPS_LOG_E(nodeName, "tpWorldSize is null."), return ge::GRAPH_FAILED);
    OPS_ERR_IF(epRankIdPtr == nullptr, OPS_LOG_E(nodeName, "epRankId is null."), return ge::GRAPH_FAILED);
    OPS_ERR_IF(tpRankIdPtr == nullptr, OPS_LOG_E(nodeName, "tpRankId is null."), return ge::GRAPH_FAILED);
    OPS_ERR_IF(expertShardPtr == nullptr, OPS_LOG_E(nodeName, "expertShardType is null."), return ge::GRAPH_FAILED);
    OPS_ERR_IF(sharedExpertRankNumPtr == nullptr, OPS_LOG_E(nodeName, "sharedExpertRankNum is null."),
                    return ge::GRAPH_FAILED);
    OPS_ERR_IF(moeExpertNumPtr == nullptr, OPS_LOG_E(nodeName, "moeExpertNum is null."), return ge::GRAPH_FAILED);
    OPS_ERR_IF(sharedExpertNumPtr == nullptr, OPS_LOG_E(nodeName, "sharedExpertNum is null."),
                    return ge::GRAPH_FAILED);
    OPS_ERR_IF(commQuantModePtr == nullptr, OPS_LOG_E(nodeName, "commQuantMode is null."), return ge::GRAPH_FAILED);

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
    OPS_ERR_IF(
        *expertShardPtr != 0,
        OPS_LOG_E(nodeName, "expertShardType is invalid, only support 0, but got expertShardType=%ld.",
            *expertShardPtr),
        return ge::GRAPH_FAILED);
    OPS_ERR_IF(
        (*sharedExpertRankNumPtr < 0) || (*sharedExpertRankNumPtr >= *epWorldSizePtr),
        OPS_LOG_E(nodeName, "sharedExpertRankNum is invalid, only support [0, %ld), but got sharedExpertRankNum=%ld.",
                *epWorldSizePtr, *sharedExpertRankNumPtr),
        return ge::GRAPH_FAILED);
    OPS_ERR_IF(
        *sharedExpertNumPtr != 1,
        OPS_LOG_E(nodeName, "sharedExpertNum only support 1, but got sharedExpertNum=%ld.", *sharedExpertNumPtr),
        return ge::GRAPH_FAILED);
    OPS_ERR_IF((*moeExpertNumPtr <= 0) || (*moeExpertNumPtr > MOE_EXPERT_MAX_NUM),
                    OPS_LOG_E(nodeName, "moeExpertNum is invalid, only support (0, %ld], but got moeExpertNum=%ld.",
                            MOE_EXPERT_MAX_NUM, *moeExpertNumPtr),
                    return ge::GRAPH_FAILED);
    OPS_ERR_IF(
        (*commQuantModePtr != 0) && (*commQuantModePtr != 2),
        OPS_LOG_E(nodeName, "commQuantMode only support 0 or 2, but got commQuantMode=%ld.", *commQuantModePtr),
        return ge::GRAPH_FAILED);

    commQuantMode = static_cast<uint32_t>(*commQuantModePtr);
    tilingData.moeDistributeCombineInfo.epWorldSize = static_cast<uint32_t>(*epWorldSizePtr);
    tilingData.moeDistributeCombineInfo.tpWorldSize = static_cast<uint32_t>(*tpWorldSizePtr);
    tilingData.moeDistributeCombineInfo.epRankId = static_cast<uint32_t>(*epRankIdPtr);
    tilingData.moeDistributeCombineInfo.tpRankId = static_cast<uint32_t>(*tpRankIdPtr);
    tilingData.moeDistributeCombineInfo.expertShardType = static_cast<uint32_t>(*expertShardPtr);
    tilingData.moeDistributeCombineInfo.sharedExpertRankNum = static_cast<uint32_t>(*sharedExpertRankNumPtr);
    tilingData.moeDistributeCombineInfo.moeExpertNum = static_cast<uint32_t>(*moeExpertNumPtr);
    tilingData.moeDistributeCombineInfo.shmemptr = static_cast<uint64_t>(*shmemPtr);

    return ge::GRAPH_SUCCESS;
}

static bool CheckTensorDim(const gert::TilingContext &context, const char *nodeName)
{
    const gert::StorageShape *expandXStorageShape = context.GetInputShape(EXPAND_X_INDEX);
    OPS_ERR_IF(expandXStorageShape == nullptr, OPS_LOG_E(nodeName, "expandX is null."), return false);
    OPS_ERR_IF(expandXStorageShape->GetStorageShape().GetDimNum() != TWO_DIMS,
                    OPS_LOG_E(nodeName, "expandX must be 2-dimension, but got %lu dim",
                            expandXStorageShape->GetStorageShape().GetDimNum()),
                    return false);
    OPS_LOG_D(nodeName, "expandX dim0 = %ld", expandXStorageShape->GetStorageShape().GetDim(0));
    OPS_LOG_D(nodeName, "expandX dim1 = %ld", expandXStorageShape->GetStorageShape().GetDim(1));

    const gert::StorageShape *expertIdsStorageShape = context.GetInputShape(EXPERT_IDS_INDEX);
    OPS_ERR_IF(expertIdsStorageShape == nullptr, OPS_LOG_E(nodeName, "expertIds is null."), return false);
    OPS_ERR_IF(expertIdsStorageShape->GetStorageShape().GetDimNum() != TWO_DIMS,
                    OPS_LOG_E(nodeName, "expertIds must be 2-dimension, but got %lu dim",
                            expertIdsStorageShape->GetStorageShape().GetDimNum()),
                    return false);
    OPS_LOG_D(nodeName, "expertIds dim0 = %ld", expertIdsStorageShape->GetStorageShape().GetDim(0));
    OPS_LOG_D(nodeName, "expertIds dim1 = %ld", expertIdsStorageShape->GetStorageShape().GetDim(1));

    const gert::StorageShape *expandIdxStorageShape = context.GetInputShape(EXPAND_IDX_INDEX);
    OPS_ERR_IF(expandIdxStorageShape == nullptr, OPS_LOG_E(nodeName, "expandIdx is null."), return false);
    OPS_ERR_IF(expandIdxStorageShape->GetStorageShape().GetDimNum() != ONE_DIM,
                    OPS_LOG_E(nodeName, "expandIdx must be 1-dimension, but got %lu dim",
                            expandIdxStorageShape->GetStorageShape().GetDimNum()),
                    return false);
    OPS_LOG_D(nodeName, "expandIdx dim0 = %ld", expandIdxStorageShape->GetStorageShape().GetDim(0));

    const gert::StorageShape *epSendCountsStorageShape = context.GetInputShape(EP_SEND_COUNTS_INDEX);
    OPS_ERR_IF(epSendCountsStorageShape == nullptr, OPS_LOG_E(nodeName, "epSendCounts is null."), return false);
    OPS_ERR_IF(epSendCountsStorageShape->GetStorageShape().GetDimNum() != ONE_DIM,
                    OPS_LOG_E(nodeName, "epSendCounts must be 1-dimension, but got %lu dim",
                            epSendCountsStorageShape->GetStorageShape().GetDimNum()),
                    return false);
    OPS_LOG_D(nodeName, "epSendCounts dim0 = %ld", epSendCountsStorageShape->GetStorageShape().GetDim(0));

    const gert::StorageShape *tpSendCountsStorageShape = context.GetOptionalInputShape(TP_SEND_COUNTS_INDEX);
    OPS_ERR_IF(tpSendCountsStorageShape == nullptr, OPS_LOG_E(nodeName, "tpSendCounts is null."), return false);
    OPS_ERR_IF(tpSendCountsStorageShape->GetStorageShape().GetDimNum() != ONE_DIM,
                    OPS_LOG_E(nodeName, "tpSendCounts must be 1-dimension, but got %lu dim",
                            tpSendCountsStorageShape->GetStorageShape().GetDimNum()),
                    return false);
    OPS_LOG_D(nodeName, "tpSendCounts dim0 = %ld", tpSendCountsStorageShape->GetStorageShape().GetDim(0));

    // x_active_mask当前不支持传入
    const gert::StorageShape *xActiveMaskStorageShape = context.GetOptionalInputShape(X_ACTIVE_MASK_INDEX);
    OPS_ERR_IF(xActiveMaskStorageShape != nullptr, OPS_LOG_E(nodeName, "x_active_mask only support input None."),
                    return false);

    const gert::StorageShape *expertScalesStorageShape = context.GetInputShape(EXPERT_SCALES_INDEX);
    OPS_ERR_IF(expertScalesStorageShape == nullptr, OPS_LOG_E(nodeName, "expertScales is null."), return false);
    OPS_ERR_IF(expertScalesStorageShape->GetStorageShape().GetDimNum() != TWO_DIMS,
                    OPS_LOG_E(nodeName, "expertScale must be 2-dimension, but got %lu dim",
                            expertScalesStorageShape->GetStorageShape().GetDimNum()),
                    return false);
    OPS_LOG_D(nodeName, "expertScales dim0 = %ld", expertScalesStorageShape->GetStorageShape().GetDim(0));
    OPS_LOG_D(nodeName, "expertScales dim1 = %ld", expertScalesStorageShape->GetStorageShape().GetDim(1));

    const gert::StorageShape *xStorageShape = context.GetOutputShape(OUTPUT_X_INDEX);
    OPS_ERR_IF(xStorageShape == nullptr, OPS_LOG_E(nodeName, "x is null."), return false);
    OPS_ERR_IF(
        xStorageShape->GetStorageShape().GetDimNum() != TWO_DIMS,
        OPS_LOG_E(nodeName, "x must be 2-dimension, but got %lu dim", xStorageShape->GetStorageShape().GetDimNum()),
        return false);
    OPS_LOG_D(nodeName, "x dim0 = %ld", xStorageShape->GetStorageShape().GetDim(0));
    OPS_LOG_D(nodeName, "x dim1 = %ld", xStorageShape->GetStorageShape().GetDim(1));
    return true;
}

// 校验数据类型
static bool CheckTensorDataType(const gert::TilingContext &context, const char *nodeName)
{
    auto expandXDesc = context.GetInputDesc(EXPAND_X_INDEX);
    OPS_ERR_IF(expandXDesc == nullptr, OPS_LOG_E(nodeName, "expandxDesc is null."), return false);
    OPS_ERR_IF((expandXDesc->GetDataType() != ge::DT_BF16) && (expandXDesc->GetDataType() != ge::DT_FLOAT16),
                    OPS_LOG_E(nodeName, "expandX dataType is invalid, dataType should be bf16 or float16, but is %d",
                            static_cast<ge::DataType>(expandXDesc->GetDataType())),
                    return false);

    auto expertIdsDesc = context.GetInputDesc(EXPERT_IDS_INDEX);
    OPS_ERR_IF(expertIdsDesc == nullptr, OPS_LOG_E(nodeName, "expertIdsDesc is null."), return false);
    OPS_ERR_IF((expertIdsDesc->GetDataType() != ge::DT_INT32),
                    OPS_LOG_E(nodeName, "expertIds dataType is invalid, dataType should be int32, but is %d",
                            static_cast<ge::DataType>(expertIdsDesc->GetDataType())),
                    return false);

    auto expandIdxDesc = context.GetInputDesc(EXPAND_IDX_INDEX);
    OPS_ERR_IF(expandIdxDesc == nullptr, OPS_LOG_E(nodeName, "expandIdxDesc is null."), return false);
    OPS_ERR_IF((expandIdxDesc->GetDataType() != ge::DT_INT32),
                    OPS_LOG_E(nodeName, "expandIdx dataType is invalid, dataType should be int32, but is %d",
                            static_cast<ge::DataType>(expandIdxDesc->GetDataType())),
                    return false);

    auto epSendCountsDesc = context.GetInputDesc(EP_SEND_COUNTS_INDEX);
    OPS_ERR_IF(epSendCountsDesc == nullptr, OPS_LOG_E(nodeName, "epSendCountsDesc is null."), return false);
    OPS_ERR_IF((epSendCountsDesc->GetDataType() != ge::DT_INT32),
                    OPS_LOG_E(nodeName, "epSendCounts dataType is invalid, dataType should be int32, but is %d",
                            static_cast<ge::DataType>(epSendCountsDesc->GetDataType())),
                    return false);

    auto tpSendCountsDesc = context.GetOptionalInputDesc(TP_SEND_COUNTS_INDEX);
    OPS_ERR_IF(tpSendCountsDesc == nullptr, OPS_LOG_E(nodeName, "tpSendCountsDesc is null."), return false);
    OPS_ERR_IF((tpSendCountsDesc->GetDataType() != ge::DT_INT32),
                    OPS_LOG_E(nodeName, "tpSendCounts dataType is invalid, dataType should be int32, but is %d",
                            static_cast<ge::DataType>(tpSendCountsDesc->GetDataType())),
                    return false);

    auto expertScalesDesc = context.GetInputDesc(EXPERT_SCALES_INDEX);
    OPS_ERR_IF(expertScalesDesc == nullptr, OPS_LOG_E(nodeName, "expertScalesDesc is null."), return false);
    OPS_ERR_IF((expertScalesDesc->GetDataType() != ge::DT_FLOAT),
                    OPS_LOG_E(nodeName, "expertScales dataType is invalid, dataType should be float, but is %d",
                            static_cast<ge::DataType>(expertScalesDesc->GetDataType())),
                    return false);

    auto xDesc = context.GetOutputDesc(OUTPUT_X_INDEX);
    OPS_ERR_IF(xDesc == nullptr, OPS_LOG_E(nodeName, "xDesc is null."), return false);
    OPS_ERR_IF(
        (xDesc->GetDataType() != expandXDesc->GetDataType()),
        OPS_LOG_E(nodeName, "x dataType is invalid, dataType should be equal expandX dataType %d, but is %d",
                static_cast<ge::DataType>(expandXDesc->GetDataType()), static_cast<ge::DataType>(xDesc->GetDataType())),
        return false);
    return true;
}

static bool CheckTensorFormat(const gert::TilingContext &context, const char *nodeName)
{
    auto expandXDesc = context.GetInputDesc(EXPAND_X_INDEX);
    OPS_ERR_IF(expandXDesc == nullptr, OPS_LOG_E(nodeName, "expandxDesc is null."), return false);
    OPS_ERR_IF(
        static_cast<ge::Format>(ge::GetPrimaryFormat(expandXDesc->GetStorageFormat())) == ge::FORMAT_FRACTAL_NZ,
        OPS_LOG_E(nodeName, "expandXFormat is invalid"), return false);

    auto expertIdsDesc = context.GetInputDesc(EXPERT_IDS_INDEX);
    OPS_ERR_IF(expertIdsDesc == nullptr, OPS_LOG_E(nodeName, "expertIdsDesc is null."), return false);
    OPS_ERR_IF(
        static_cast<ge::Format>(ge::GetPrimaryFormat(expertIdsDesc->GetStorageFormat())) == ge::FORMAT_FRACTAL_NZ,
        OPS_LOG_E(nodeName, "expertIdsFormat is invalid"), return false);

    auto expandIdxDesc = context.GetInputDesc(EXPAND_IDX_INDEX);
    OPS_ERR_IF(expandIdxDesc == nullptr, OPS_LOG_E(nodeName, "expandIdxDesc is null."), return false);
    OPS_ERR_IF(
        static_cast<ge::Format>(ge::GetPrimaryFormat(expandIdxDesc->GetStorageFormat())) == ge::FORMAT_FRACTAL_NZ,
        OPS_LOG_E(nodeName, "expandIdxFormat is invalid"), return false);

    auto epSendCountsDesc = context.GetInputDesc(EP_SEND_COUNTS_INDEX);
    OPS_ERR_IF(epSendCountsDesc == nullptr, OPS_LOG_E(nodeName, "epSendCountsDesc is null."), return false);
    OPS_ERR_IF(
        static_cast<ge::Format>(ge::GetPrimaryFormat(epSendCountsDesc->GetStorageFormat())) == ge::FORMAT_FRACTAL_NZ,
        OPS_LOG_E(nodeName, "epSendCountsFormat is invalid"), return false);

    auto tpSendCountsDesc = context.GetOptionalInputDesc(TP_SEND_COUNTS_INDEX);
    OPS_ERR_IF(tpSendCountsDesc == nullptr, OPS_LOG_E(nodeName, "tpSendCountsDesc is null."), return false);
    OPS_ERR_IF(
        static_cast<ge::Format>(ge::GetPrimaryFormat(tpSendCountsDesc->GetStorageFormat())) == ge::FORMAT_FRACTAL_NZ,
        OPS_LOG_E(nodeName, "tpSendCountsFormat is invalid"), return false);

    auto expertScalesDesc = context.GetInputDesc(EXPERT_SCALES_INDEX);
    OPS_ERR_IF(expertScalesDesc == nullptr, OPS_LOG_E(nodeName, "expertScalesDesc is null."), return false);
    OPS_ERR_IF(
        static_cast<ge::Format>(ge::GetPrimaryFormat(expertScalesDesc->GetStorageFormat())) == ge::FORMAT_FRACTAL_NZ,
        OPS_LOG_E(nodeName, "expertScalesFormat is invalid"), return false);

    auto xDesc = context.GetOutputDesc(OUTPUT_X_INDEX);
    OPS_ERR_IF(xDesc == nullptr, OPS_LOG_E(nodeName, "xDesc is null."), return false);
    OPS_ERR_IF(static_cast<ge::Format>(ge::GetPrimaryFormat(xDesc->GetStorageFormat())) == ge::FORMAT_FRACTAL_NZ,
                    OPS_LOG_E(nodeName, "xFormat is invalid"), return false);
    return true;
}

static bool CheckTensorShape(const gert::TilingContext &context, MoeCombineShmemTilingData &tilingData,
                             const char *nodeName, bool isShared, uint32_t localExpertNum)
{
    // 校验输入expertIds的维度1并设k, bs已校验过
    const gert::StorageShape *expertIdsStorageShape = context.GetInputShape(EXPERT_IDS_INDEX);
    OPS_ERR_IF(expertIdsStorageShape == nullptr, OPS_LOG_E(nodeName, "expertIds is null."), return false);
    int64_t expertIdsDim0 = expertIdsStorageShape->GetStorageShape().GetDim(0);
    int64_t expertIdsDim1 = expertIdsStorageShape->GetStorageShape().GetDim(1);

    uint32_t A = 0;
    uint32_t globalBs = tilingData.moeDistributeCombineInfo.globalBs;
    uint32_t sharedExpertRankNum = tilingData.moeDistributeCombineInfo.sharedExpertRankNum;
    if (isShared) {  // 本卡为共享专家
        A = globalBs / sharedExpertRankNum;
    } else {  // 本卡为moe专家
        A = globalBs * std::min(static_cast<int64_t>(localExpertNum), expertIdsDim1);
    }

    // 校验expandX的维度并设h
    int64_t tpWorldSize = static_cast<int64_t>(tilingData.moeDistributeCombineInfo.tpWorldSize);
    const gert::StorageShape *expandXStorageShape = context.GetInputShape(EXPAND_X_INDEX);
    OPS_ERR_IF(expandXStorageShape == nullptr, OPS_LOG_E(nodeName, "expandXStorageShape is null."), return false);
    int64_t expandXDim0 = expandXStorageShape->GetStorageShape().GetDim(0);
    int64_t expandXDim1 = expandXStorageShape->GetStorageShape().GetDim(1);
    OPS_ERR_IF(expandXDim0 < tpWorldSize * static_cast<int64_t>(A),
                    OPS_LOG_E(nodeName,
                            "expandX's dim0 not greater than or equal to A * tpWorldSize, expandXDim0 = %ld, A = %ld, "
                            "tpWorldSize = %ld",
                            expandXDim0, static_cast<int64_t>(A), tpWorldSize),
                    return false);
    OPS_ERR_IF((expandXDim1 != 7168),
                    OPS_LOG_E(nodeName, "expandX dims1(H) only supports 7168, but got %ld.", expandXDim1),
                    return false);
    tilingData.moeDistributeCombineInfo.h = static_cast<uint32_t>(expandXDim1);

    OPS_ERR_IF(
        (expertIdsDim1 <= 0) || (expertIdsDim1 > K_MAX),
        OPS_LOG_E(nodeName, "expertIdShape's dim1(k) should be in (0, %ld], but got expertIdShape's dim1=%ld.", K_MAX,
                expertIdsDim1),
        return false);
    tilingData.moeDistributeCombineInfo.k = static_cast<uint32_t>(expertIdsDim1);

    // 校验expandIdx的维度
    const gert::StorageShape *expandIdxStorageShape = context.GetInputShape(EXPAND_IDX_INDEX);
    OPS_ERR_IF(expandIdxStorageShape == nullptr, OPS_LOG_E(nodeName, "expandIdxStorageShape is null"), return false);
    int64_t expandIdxDim0 = expandIdxStorageShape->GetStorageShape().GetDim(0);
    OPS_ERR_IF(expandIdxDim0 != expertIdsDim0 * expertIdsDim1,
                    OPS_LOG_E(nodeName, "expandIdxDim0 != bs * k, expandIdxDim0 is %ld, bs * k is %ld.", expandIdxDim0,
                            expertIdsDim0 * expertIdsDim1),
                    return false);

    // 校验epSendCount和tpSendCount的维度
    int64_t epWorldSize = static_cast<int64_t>(tilingData.moeDistributeCombineInfo.epWorldSize);
    int64_t moeExpertPerRankNum = static_cast<int64_t>(tilingData.moeDistributeCombineInfo.moeExpertPerRankNum);
    const gert::StorageShape *epSendCountStorageShape = context.GetInputShape(EP_SEND_COUNTS_INDEX);
    OPS_ERR_IF(epSendCountStorageShape == nullptr, OPS_LOG_E(nodeName, "epSendCountStorageShape is null."),
        return false);
    const gert::StorageShape *tpSendCountStorageShape = context.GetOptionalInputShape(TP_SEND_COUNTS_INDEX);
    OPS_ERR_IF(tpSendCountStorageShape == nullptr, OPS_LOG_E(nodeName, "tpSendCountStorageShape is null."),
        return false);
    const int64_t epSendCountDim0 = epSendCountStorageShape->GetStorageShape().GetDim(0);
    const int64_t tpSendCountDim0 = tpSendCountStorageShape->GetStorageShape().GetDim(0);
    int64_t epSendCount = (isShared) ? epWorldSize : epWorldSize * moeExpertPerRankNum;
    OPS_ERR_IF(epSendCountDim0 < epSendCount * tpWorldSize,
                    OPS_LOG_E(nodeName,
                            "epSendCountDim0 not greater than or equal to epSendCount * tpWorldSize, epSendCountDim0 "
                            "is %ld, epSendCount is %ld, tpWorldSize is %ld.",
                            epSendCountDim0, epSendCount, tpWorldSize),
                    return false);
    OPS_ERR_IF(
        tpSendCountDim0 != tpWorldSize,
        OPS_LOG_E(nodeName, "tpSendCountDim0 not equal to tpWorldSize, tpSendCountDim0 is %ld, tpWorldSize is %ld.",
                tpSendCountDim0, tpWorldSize),
        return false);

    // 校验expertScales的维度
    const gert::StorageShape *expertScalesStorageShape = context.GetInputShape(EXPERT_SCALES_INDEX);
    OPS_ERR_IF(expertScalesStorageShape == nullptr,
        OPS_LOG_E(nodeName, "expertScalesStorageShape is null"), return false);
    int64_t expertScalesDim0 = expertScalesStorageShape->GetStorageShape().GetDim(0);
    int64_t expertScalesDim1 = expertScalesStorageShape->GetStorageShape().GetDim(1);
    OPS_ERR_IF(expertScalesDim0 != expertIdsDim0,
                    OPS_LOG_E(nodeName, "expertScales' dim0 not equal to bs, expertScalesDim0 = %ld, bs = %ld",
                            expertScalesDim0, expertIdsDim0),
                    return false);
    OPS_ERR_IF(expertScalesDim1 != expertIdsDim1,
                    OPS_LOG_E(nodeName, "expertScales' dim1 not equal to k, expertScalesDim1 = %ld, k = %ld",
                            expertScalesDim1, expertIdsDim1),
                    return false);

    // 校验x的维度
    const gert::StorageShape *xStorageShape = context.GetOutputShape(OUTPUT_X_INDEX);
    OPS_ERR_IF(xStorageShape == nullptr, OPS_LOG_E(nodeName, "x is null."), return false);
    int64_t xDim0 = xStorageShape->GetStorageShape().GetDim(0);
    int64_t xDim1 = xStorageShape->GetStorageShape().GetDim(1);
    OPS_ERR_IF(xDim0 != expertIdsDim0,
                    OPS_LOG_E(nodeName, "xDim0 not equal to bs, bs = %ld, xDim0 = %ld", expertIdsDim0, xDim0),
                    return false);
    OPS_ERR_IF(xDim1 != expandXDim1,
                    OPS_LOG_E(nodeName, "xDim1 not equal to h, xDim1 = %ld, h = %ld", xDim1, expandXDim1),
                    return false);

    return true;
}

static bool CheckAttrs(const gert::TilingContext &context, MoeCombineShmemTilingData &tilingData, const char *nodeName,
                       uint32_t &localMoeExpertNum)
{
    uint32_t epWorldSize = tilingData.moeDistributeCombineInfo.epWorldSize;
    uint32_t tpWorldSize = tilingData.moeDistributeCombineInfo.tpWorldSize;
    uint32_t moeExpertNum = tilingData.moeDistributeCombineInfo.moeExpertNum;
    uint32_t sharedExpertRankNum = tilingData.moeDistributeCombineInfo.sharedExpertRankNum;

    // 校验ep能均分共享
    OPS_ERR_IF((sharedExpertRankNum != 0) && (epWorldSize % sharedExpertRankNum != 0),
                    OPS_LOG_E(nodeName,
                            "epWorldSize should be divisible by sharedExpertRankNum, but epWorldSize=%u, "
                            "sharedExpertRankNum=%u.",
                            epWorldSize, sharedExpertRankNum),
                    return false);

    // 校验moe专家数量能否均分给多机
    OPS_ERR_IF(moeExpertNum % (epWorldSize - sharedExpertRankNum) != 0,
                    OPS_LOG_E(nodeName,
                            "moeExpertNum should be divisible by (epWorldSize - sharedExpertRankNum), "
                            "but got moeExpertNum=%u, epWorldSize=%u, sharedExpertRankNum=%u.",
                            moeExpertNum, epWorldSize, sharedExpertRankNum),
                    return false);
    localMoeExpertNum = moeExpertNum / (epWorldSize - sharedExpertRankNum);
    OPS_ERR_IF(localMoeExpertNum <= 0,
                    OPS_LOG_E(nodeName, "localMoeExpertNum is invalid, localMoeExpertNum = %u", localMoeExpertNum),
                    return false);
    OPS_ERR_IF((localMoeExpertNum > 1) && (tpWorldSize > 1),
                    OPS_LOG_E(nodeName, "Cannot support multi-moeExpert %u in a rank when tpWorldSize = %u > 1",
                            localMoeExpertNum, tpWorldSize),
                    return false);
    tilingData.moeDistributeCombineInfo.moeExpertPerRankNum = localMoeExpertNum;

    // 检验epWorldSize是否是8的倍数
    OPS_ERR_IF(epWorldSize % 8 != 0,
                    OPS_LOG_E(nodeName, "epWorldSize should be divisible by 8, but got epWorldSize = %u.", epWorldSize),
                    return false);

    OPS_ERR_IF(
        (256 % epWorldSize != 0) && (epWorldSize % 144 != 0),
        OPS_LOG_E(nodeName,
                "epWorldSize should be in the list[8, 16, 32, 64, 128, 144, 256, 288], but got epWorldSize = %u.",
                epWorldSize),
        return false);

    // 校验输入expertIds的维度0并设bs
    const gert::StorageShape *expertIdsStorageShape = context.GetInputShape(EXPERT_IDS_INDEX);
    OPS_ERR_IF(expertIdsStorageShape == nullptr,
        OPS_LOG_E(nodeName, "expertIdsStorageShape is null"), return false);
    int64_t expertIdsDim0 = expertIdsStorageShape->GetStorageShape().GetDim(0);
    OPS_ERR_IF((expertIdsDim0 <= 0) || (expertIdsDim0 > BS_UPPER_BOUND),
                    OPS_LOG_E(nodeName, "Invalid expertIds dims0(BS) %ld. Should be between [1, %ld].", expertIdsDim0,
                            BS_UPPER_BOUND),
                    return false);
    tilingData.moeDistributeCombineInfo.bs = static_cast<uint32_t>(expertIdsDim0);

    // 校验globalBS
    auto attrs = context.GetAttrs();
    OPS_ERR_IF(attrs == nullptr, OPS_LOG_E(nodeName, "attrs is null."), return false);
    auto globalBsPtr = attrs->GetAttrPointer<int64_t>(ATTR_GLOBAL_BS_INDEX);
    OPS_ERR_IF(globalBsPtr == nullptr, OPS_LOG_E(nodeName, "globalBs is null."), return false);
    OPS_LOG_D(nodeName, "MoeDistributeCombine *globalBsPtr = %ld, bs = %ld, epWorldSize = %u\n", *globalBsPtr,
              expertIdsDim0, epWorldSize);
    OPS_ERR_IF(
        (*globalBsPtr != 0) && ((*globalBsPtr < static_cast<int64_t>(epWorldSize) * expertIdsDim0) ||
                                ((*globalBsPtr) % (static_cast<int64_t>(epWorldSize)) != 0)),
        OPS_LOG_E(nodeName,
                "globalBS is invalid, only "
                "support 0 or maxBs(maxBs is the largest bs on all ranks) * epWorldSize, but got globalBS=%ld, "
                "bs=%ld, epWorldSize=%u.",
                *globalBsPtr, expertIdsDim0, epWorldSize),
        return false);
    if (*globalBsPtr == 0) {
        tilingData.moeDistributeCombineInfo.globalBs = static_cast<uint32_t>(expertIdsDim0) * epWorldSize;
    } else {
        tilingData.moeDistributeCombineInfo.globalBs = static_cast<uint32_t>(*globalBsPtr);
    }

    return true;
}

static ge::graphStatus TilingCheckMoeDistributeCombine(gert::TilingContext &context, const char *nodeName)
{
    // 检查参数shape信息
    OPS_ERR_IF(!CheckTensorDim(context, nodeName), OPS_LOG_E(nodeName, "param shape is invalid"),
                    return ge::GRAPH_FAILED);
    // 检查参数dataType信息
    OPS_ERR_IF(!CheckTensorDataType(context, nodeName), OPS_LOG_E(nodeName, "param dataType is invalid"),
                    return ge::GRAPH_FAILED);
    // 检查参数format信息
    OPS_ERR_IF(!CheckTensorFormat(context, nodeName), OPS_LOG_E(nodeName, "param Format is invalid"),
                    return ge::GRAPH_FAILED);
    return ge::GRAPH_SUCCESS;
}

static ge::graphStatus SetWorkspace(gert::TilingContext &context, const char *nodeName)
{
    size_t *workspace = context.GetWorkspaceSizes(1);
    OPS_ERR_IF(workspace == nullptr, OPS_REPORT_VECTOR_INNER_ERR(nodeName, "get workspace failed"),
                    return ge::GRAPH_FAILED);
    workspace[0] = SYSTEM_NEED_WORKSPACE;
    OPS_LOG_D(nodeName, "workspace[0] size is %ld", workspace[0]);
    return ge::GRAPH_SUCCESS;
}

static void SetHCommCfg(const gert::TilingContext &context, MoeCombineShmemTilingData &tiling,
                        const std::string groupEp, const std::string groupTp)
{
    const char *nodeName = context.GetNodeName();
    OPS_LOG_D(nodeName, "MoeDispatchShmem groupEp = %s, groupTp = %s", groupEp.c_str(), groupTp.c_str());
    uint32_t opType1 = OP_TYPE_ALL_TO_ALL;
    uint32_t opType2 = OP_TYPE_REDUCE_SCATTER;
    std::string algConfigAllToAllStr = "AlltoAll=level0:fullmesh;level1:pairwise";
    std::string algConfigReduceScatterStr = "ReduceScatter=level0:ring";

    AscendC::Mc2CcTilingConfig mc2CcTilingConfig(groupEp, opType1, algConfigAllToAllStr);
    mc2CcTilingConfig.GetTiling(tiling.mc2InitTiling);
    mc2CcTilingConfig.GetTiling(tiling.mc2CcTiling1);

    mc2CcTilingConfig.SetGroupName(groupTp);
    mc2CcTilingConfig.SetOpType(opType2);
    mc2CcTilingConfig.SetAlgConfig(algConfigReduceScatterStr);
    mc2CcTilingConfig.GetTiling(tiling.mc2CcTiling2);
}

static ge::graphStatus MoeDistributeCombineA3TilingFuncImpl(gert::TilingContext &context)
{
    const char *nodeName = context.GetNodeName();
    OPS_LOG_D(nodeName, "Enter MoeCombineShmem Tiling func");
    MoeCombineShmemTilingData *tilingData = context.GetTilingData<MoeCombineShmemTilingData>();
    OPS_ERR_IF(tilingData == nullptr, OPS_LOG_E(nodeName, "tilingData is nullptr."), return ge::GRAPH_FAILED);
    std::string groupEp = "";
    std::string groupTp = "";
    bool isShared = true;
    uint32_t localMoeExpertNum = 1;
    uint32_t commQuantMode = 0U;

    // 获取入参属性
    OPS_ERR_IF(GetAttrAndSetTilingData(context, *tilingData, nodeName, commQuantMode) == ge::GRAPH_FAILED,
                    OPS_LOG_E(nodeName, "Getting attr failed."), return ge::GRAPH_FAILED);

    // 检查输入输出的dim、format、dataType
    OPS_ERR_IF(TilingCheckMoeDistributeCombine(context, nodeName) != ge::GRAPH_SUCCESS,
                    OPS_LOG_E(nodeName, "Tiling check params failed"), return ge::GRAPH_FAILED);

    // 检查属性的取值是否合法
    OPS_ERR_IF(!CheckAttrs(context, *tilingData, nodeName, localMoeExpertNum),
                    OPS_LOG_E(nodeName, "attr check failed."), return ge::GRAPH_FAILED);

    uint32_t sharedExpertRankNum = tilingData->moeDistributeCombineInfo.sharedExpertRankNum;
    uint32_t epRankId = tilingData->moeDistributeCombineInfo.epRankId;
    if (epRankId >= sharedExpertRankNum) {  // 本卡为moe专家
        isShared = false;
    }

    // 检查shape各维度并赋值h,k
    OPS_ERR_IF(!CheckTensorShape(context, *tilingData, nodeName, isShared, localMoeExpertNum),
                    OPS_LOG_E(nodeName, "param dim check failed."), return ge::GRAPH_FAILED);

    // 校验win区大小
    uint16_t defaultWindowSize = 200;
    const uint64_t maxWindowSize = static_cast<uint64_t>(defaultWindowSize) * 1024UL * 1024UL;
    uint64_t h = static_cast<uint64_t>(tilingData->moeDistributeCombineInfo.h);
    uint64_t epWorldSize = static_cast<uint64_t>(tilingData->moeDistributeCombineInfo.epWorldSize);
    uint64_t maxBs = static_cast<uint64_t>(tilingData->moeDistributeCombineInfo.globalBs) / epWorldSize;
    uint64_t actualSize = epWorldSize * maxBs * h * 2UL * 2UL * static_cast<uint64_t>(localMoeExpertNum);
    tilingData->moeDistributeCombineInfo.totalWinSize = maxWindowSize;

    OPS_ERR_IF(SetWorkspace(context, nodeName) != ge::GRAPH_SUCCESS,
                    OPS_REPORT_VECTOR_INNER_ERR(context.GetNodeName(), "Tiling set workspace Failed"),
                    return ge::GRAPH_FAILED);

    SetHCommCfg(context, *tilingData, groupEp, groupTp);

    uint32_t tpWorldSize = tilingData->moeDistributeCombineInfo.tpWorldSize;
    uint64_t tilingKey = INIT_TILINGKEY_TP_2;
    if (tpWorldSize != MAX_TP_WORLD_SIZE) {
        tilingKey = INIT_TILINGKEY_TP_1;
    }
    if (commQuantMode == INT8_COMM_QUANT) {
        tilingKey += TILINGKEY_INT8_COMM_QUANT;
    }
    OPS_LOG_D(nodeName, "tilingKey is %lu", tilingKey);
    context.SetTilingKey(tilingKey);
    uint32_t blockDim = 1U;

    auto ascendcPlatform = platform_ascendc::PlatformAscendC(context.GetPlatformInfo());
    uint64_t aivNum = ascendcPlatform.GetCoreNumAiv();
    uint64_t ubSize = 0UL;
    ascendcPlatform.GetCoreMemSize(platform_ascendc::CoreMemType::UB, ubSize);
    blockDim = ascendcPlatform.CalcTschBlockDim(aivNum, 0, aivNum);
    context.SetBlockDim(blockDim);
    tilingData->moeDistributeCombineInfo.aivNum = aivNum;
    tilingData->moeDistributeCombineInfo.totalUbSize = ubSize;
    OPS_LOG_D(nodeName, "blockdim = %u, aivNum = %lu, ubsize = %lu", blockDim, aivNum, ubSize);
    PrintTilingDataInfo(nodeName, *tilingData);
    return ge::GRAPH_SUCCESS;
}

static ge::graphStatus MoeDistributeCombineTilingFunc(gert::TilingContext *context)
{
    // 不支持 expandX数据类型为int32 type
    auto expandXDesc = context->GetInputDesc(EXPAND_X_INDEX);
    const char *nodeName = context->GetNodeName();
    OPS_ERR_IF(expandXDesc == nullptr, OPS_LOG_E(nodeName, "expandxDesc is null."), return ge::GRAPH_FAILED);
    // 检查expandX数据类型为DT_INT32
    OPS_ERR_IF((expandXDesc->GetDataType() == ge::DT_INT32),
                    OPS_LOG_E(nodeName, "expandX dataType is invalid, dataType should be bf16 or float16, but is %d",
                            static_cast<ge::DataType>(expandXDesc->GetDataType())),
                    return ge::GRAPH_FAILED);

    ge::graphStatus ret = MoeDistributeCombineA3TilingFuncImpl(*context);
    return ret;
}

struct MoeDistributeCombineCompileInfo {};
ge::graphStatus TilingParseForMoeDistributeCombine(gert::TilingParseContext *context)
{
    (void)context;
    return ge::GRAPH_SUCCESS;
}

IMPL_OP_OPTILING(MoeCombineShmem)
    .Tiling(MoeDistributeCombineTilingFunc)
    .TilingParse<MoeDistributeCombineCompileInfo>(TilingParseForMoeDistributeCombine);
}  // namespace optiling
