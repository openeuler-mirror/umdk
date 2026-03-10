/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2025-2025. All rights reserved.
 * Description: Normal combine tiling function implementation file
 * Create: 2025-11-25
 * Note:
 * History: 2025-11-25 create normal combine tiling function file
 */

#include <cmath>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <dlfcn.h>
#include <fcntl.h>
#include <queue>
#include <string>
#include <sys/types.h>
#include <type_traits>
#include <unistd.h>
#include <vector>

#include "ops_log.h"
#include "ops_error.h"
#include "graph/utils/type_utils.h"
#include "mc2_tiling_utils.h"
#include "register/op_def_registry.h"
#include "register/tilingdata_base.h"
#include "tiling/tiling_api.h"
#include "tiling_args.h"
#include "../op_kernel/moe_combine_normal_tiling.h"

using namespace AscendC;
using namespace ge;
using namespace Moe;
using namespace Util;
namespace {
constexpr const char *OPS_UTILS_LOG_SUB_MOD_NAME = "MOE_COMBINE_NORMAL";
constexpr const char *OPS_UTILS_LOG_PACKAGE_TYPE = "CAM_OPS";
constexpr uint32_t RECV_X_INDEX = 0;
constexpr uint32_t TOKEN_SRC_INFO_INDEX = 1;
constexpr uint32_t EP_RECV_COUNTS_INDEX = 2;
constexpr uint32_t TOPK_WEIGHTS_INDEX = 3;
constexpr uint32_t TP_RECV_COUNTS_INDEX = 4;
constexpr uint32_t OUTPUT_X_INDEX = 0;
constexpr uint32_t OUTPUT_SEND_COST_INDEX = 1;

constexpr uint32_t ATTR_GROUP_EP_INDEX = 0;
constexpr uint32_t ATTR_EP_WORLD_SIZE_INDEX = 1;
constexpr uint32_t ATTR_EP_RANK_ID_INDEX = 2;
constexpr uint32_t ATTR_GROUP_TP_INDEX = 3;
constexpr uint32_t ATTR_TP_WORLD_SIZE_INDEX = 4;
constexpr uint32_t ATTR_TP_RANK_ID_INDEX = 5;
constexpr uint32_t ATTR_MOE_EXPERT_NUM_INDEX = 6;
constexpr uint32_t ATTR_GLOBAL_BS_INDEX = 7;

constexpr uint32_t TWO_DIMS = 2U;
constexpr uint32_t ONE_DIM = 1U;
constexpr uint32_t OP_TYPE_ALL_TO_ALL = 8U;     // numeric representation of AlltoAll
constexpr uint32_t OP_TYPE_REDUCE_SCATTER = 7U; // numeric representation of ReduceScatter

constexpr size_t MAX_GROUP_NAME_LENGTH = 128UL;
constexpr int64_t MAX_EP_WORLD_SIZE = 384;
constexpr int64_t MIN_EP_WORLD_SIZE = 2;
constexpr int64_t MAX_TP_WORLD_SIZE = 2;
constexpr int64_t BS_UPPER_BOUND = 8000;

constexpr uint32_t SYSTEM_NEED_WORKSPACE = 16 * 1024 * 1024;
constexpr int32_t HCCL_BUFFER_SIZE_DEFAULT = 200 * 1024 * 1024; // Bytes
constexpr int64_t MOE_EXPERT_MAX_NUM = 512;
constexpr int64_t K_MAX = 16;
constexpr int64_t H_MIN = 1024;
constexpr int64_t H_MAX = 7168;
constexpr uint64_t MB_SIZE = 1024UL * 1024UL;
constexpr uint64_t TRIPLE = 3;
constexpr uint64_t WIN_ADDR_ALIGN = 512UL;
constexpr uint64_t SCALE_RECV_IDX_BUFFER = 44UL; // scale32B + 3*4 src info
constexpr uint64_t DOUBLE_DATA_BUFFER = 2UL;
constexpr uint64_t MAX_OUT_DTYPE_SIZE = 2UL;
constexpr uint64_t UB_ALIGN = 32UL;
constexpr int64_t DISPATCH_STATUS_MAX_SUPPORT_NUM = 1280UL;

enum class CommQuantMode : int32_t {
    NON_QUANT = 0,
    INT12_QUANT = 1,
    INT8_QUANT = 2
};
using CommQuantModeType = std::underlying_type<CommQuantMode>;
} // namespace

namespace optiling {

// a3专有
static void PrintTilingDataInfo(const char *nodeName, const MoeCombineNormalTilingData &tilingData)
{
    OPS_LOG_D(nodeName, "epWorldSize is %u.", tilingData.moeCombineNormalInfo.epWorldSize);
    OPS_LOG_D(nodeName, "tpWorldSize is %u.", tilingData.moeCombineNormalInfo.tpWorldSize);
    OPS_LOG_D(nodeName, "epRankId is %u.", tilingData.moeCombineNormalInfo.epRankId);
    OPS_LOG_D(nodeName, "tpRankId is %u.", tilingData.moeCombineNormalInfo.tpRankId);
    OPS_LOG_D(nodeName, "expertShardType is %u.", tilingData.moeCombineNormalInfo.expertShardType);
    OPS_LOG_D(nodeName, "moeExpertNum is %u.", tilingData.moeCombineNormalInfo.moeExpertNum);
    OPS_LOG_D(nodeName, "moeExpertPerRankNum is %u.", tilingData.moeCombineNormalInfo.moeExpertPerRankNum);
    OPS_LOG_D(nodeName, "globalBs is %u.", tilingData.moeCombineNormalInfo.globalBs);
    OPS_LOG_D(nodeName, "bs is %u.", tilingData.moeCombineNormalInfo.bs);
    OPS_LOG_D(nodeName, "k is %u.", tilingData.moeCombineNormalInfo.k);
    OPS_LOG_D(nodeName, "h is %u.", tilingData.moeCombineNormalInfo.h);
    OPS_LOG_D(nodeName, "aivNum is %u.", tilingData.moeCombineNormalInfo.aivNum);
    OPS_LOG_D(nodeName, "totalUbSize is %lu.", tilingData.moeCombineNormalInfo.totalUbSize);
    OPS_LOG_D(nodeName, "totalWinSize is %lu.", tilingData.moeCombineNormalInfo.totalWinSize);
}

static ge::graphStatus GetAttrAndSetTilingData(const gert::TilingContext &context,
    MoeCombineNormalTilingData &tilingData, const char *nodeName, std::string &groupEp, std::string &groupTp)
{
    auto attrs = context.GetAttrs();
    OPS_ERR_IF(attrs == nullptr, OPS_LOG_E(nodeName, "attrs is null."), return ge::GRAPH_FAILED);

    auto groupEpPtr = attrs->GetAttrPointer<char>(static_cast<int>(ATTR_GROUP_EP_INDEX));
    auto groupTpPtr = attrs->GetAttrPointer<char>(static_cast<int>(ATTR_GROUP_TP_INDEX));
    auto epWorldSizePtr = attrs->GetAttrPointer<int64_t>(ATTR_EP_WORLD_SIZE_INDEX);
    auto tpWorldSizePtr = attrs->GetAttrPointer<int64_t>(ATTR_TP_WORLD_SIZE_INDEX);
    auto epRankIdPtr = attrs->GetAttrPointer<int64_t>(ATTR_EP_RANK_ID_INDEX);
    auto tpRankIdPtr = attrs->GetAttrPointer<int64_t>(ATTR_TP_RANK_ID_INDEX);
    auto moeExpertNumPtr = attrs->GetAttrPointer<int64_t>(ATTR_MOE_EXPERT_NUM_INDEX);

    // 判空
    OPS_ERR_IF((groupEpPtr == nullptr) || (strnlen(groupEpPtr, MAX_GROUP_NAME_LENGTH) == 0) ||
                        (strnlen(groupEpPtr, MAX_GROUP_NAME_LENGTH) == MAX_GROUP_NAME_LENGTH),
                    OPS_LOG_E(nodeName, "groupEp is invalid."), return ge::GRAPH_FAILED);
    OPS_ERR_IF(epWorldSizePtr == nullptr, OPS_LOG_E(nodeName, "epWorldSize is null."), return ge::GRAPH_FAILED);
    OPS_ERR_IF(tpWorldSizePtr == nullptr, OPS_LOG_E(nodeName, "tpWorldSize is null."), return ge::GRAPH_FAILED);
    OPS_ERR_IF(epRankIdPtr == nullptr, OPS_LOG_E(nodeName, "epRankId is null."), return ge::GRAPH_FAILED);
    OPS_ERR_IF(tpRankIdPtr == nullptr, OPS_LOG_E(nodeName, "tpRankId is null."), return ge::GRAPH_FAILED);
    OPS_ERR_IF(moeExpertNumPtr == nullptr, OPS_LOG_E(nodeName, "moeExpertNum is null."), return ge::GRAPH_FAILED);

    // 判断是否满足uint32_t及其他限制
    int64_t moeExpertNum = *moeExpertNumPtr;
    int64_t epWorldSize = *epWorldSizePtr;
    OPS_ERR_IF((epWorldSize < MIN_EP_WORLD_SIZE) || (epWorldSize > MAX_EP_WORLD_SIZE),
                    OPS_LOG_E(nodeName, "epWorldSize is invalid, only support [%ld, %ld], but got epWorldSize=%ld.",
                            MIN_EP_WORLD_SIZE, MAX_EP_WORLD_SIZE, epWorldSize),
                    return ge::GRAPH_FAILED);
    OPS_ERR_IF((*tpWorldSizePtr < 0) || (*tpWorldSizePtr > MAX_TP_WORLD_SIZE),
                    OPS_LOG_E(nodeName, "tpWorldSize is invalid, only support [0, %ld], but got tpWorldSize=%ld.",
                            MAX_TP_WORLD_SIZE, *tpWorldSizePtr),
                    return ge::GRAPH_FAILED);
    OPS_ERR_IF((*epRankIdPtr < 0) || (*epRankIdPtr >= epWorldSize),
                    OPS_LOG_E(nodeName, "epRankId is invalid, only support [0, %ld), but got epRankId=%ld.",
                            epWorldSize,
                            *epRankIdPtr),
                    return ge::GRAPH_FAILED);

    if (*tpWorldSizePtr > 1) {
        OPS_ERR_IF((*tpRankIdPtr < 0) || (*tpRankIdPtr >= *tpWorldSizePtr),
                        OPS_LOG_E(nodeName, "tpRankId is invalid, only support [0, %ld), but got tpRankId=%ld.",
                                *tpWorldSizePtr, *tpRankIdPtr),
                        return ge::GRAPH_FAILED);
        OPS_ERR_IF((groupTpPtr == nullptr) || (strnlen(groupTpPtr, MAX_GROUP_NAME_LENGTH) == 0) ||
                            (strnlen(groupTpPtr, MAX_GROUP_NAME_LENGTH) == MAX_GROUP_NAME_LENGTH),
                        OPS_LOG_E(nodeName, "groupTpPtr is null."), return ge::GRAPH_FAILED);
        groupTp = std::string(groupTpPtr);
    } else {
        OPS_ERR_IF(
            *tpRankIdPtr != 0,
            OPS_LOG_E(nodeName, "tpRankId is invalid, NoTp mode only support 0, but got tpRankId=%ld.", *tpRankIdPtr),
            return ge::GRAPH_FAILED);
    }
    OPS_ERR_IF((moeExpertNum <= 0) || (moeExpertNum > MOE_EXPERT_MAX_NUM),
                    OPS_LOG_E(nodeName, "moeExpertNum is invalid, only support (0, %ld], but got moeExpertNum=%ld.",
                            MOE_EXPERT_MAX_NUM, moeExpertNum),
                    return ge::GRAPH_FAILED);
    int64_t moePerRankNum = moeExpertNum / epWorldSize;
    int64_t curDispatchStatusNum = moePerRankNum * epWorldSize;
    OPS_ERR_IF((curDispatchStatusNum > DISPATCH_STATUS_MAX_SUPPORT_NUM),
                    OPS_LOG_E(nodeName,
                            "The moe experts num must meet the conditions,"
                            " (moeExpertNum / epWorldSize) * epWorldSize <= 1280, but cur is %ld.",
                            curDispatchStatusNum),
                    return ge::GRAPH_FAILED);

    groupEp = std::string(groupEpPtr);
    tilingData.moeCombineNormalInfo.epWorldSize = static_cast<uint32_t>(epWorldSize);
    tilingData.moeCombineNormalInfo.tpWorldSize = static_cast<uint32_t>(*tpWorldSizePtr);
    tilingData.moeCombineNormalInfo.epRankId = static_cast<uint32_t>(*epRankIdPtr);
    tilingData.moeCombineNormalInfo.tpRankId = static_cast<uint32_t>(*tpRankIdPtr);
    tilingData.moeCombineNormalInfo.moeExpertNum = static_cast<uint32_t>(moeExpertNum);

    return ge::GRAPH_SUCCESS;
}

static bool CheckInputTensorDim(const gert::TilingContext &context, const char *nodeName)
{
    const gert::StorageShape *recvXStorageShape = context.GetInputShape(RECV_X_INDEX);
    OPS_ERR_IF(recvXStorageShape == nullptr, OPS_LOG_E(nodeName, "recvX is null."), return false);
    OPS_ERR_IF(recvXStorageShape->GetStorageShape().GetDimNum() != TWO_DIMS,
                    OPS_LOG_E(nodeName, "recvX must be 2-dimension, but got %lu dim",
                            recvXStorageShape->GetStorageShape().GetDimNum()),
                    return false);
    OPS_LOG_D(nodeName, "recvX dim0 = %ld", recvXStorageShape->GetStorageShape().GetDim(0));
    OPS_LOG_D(nodeName, "recvX dim1 = %ld", recvXStorageShape->GetStorageShape().GetDim(1));

    const gert::StorageShape *tokenSrcInfoStorageShape = context.GetInputShape(TOKEN_SRC_INFO_INDEX);
    OPS_ERR_IF(tokenSrcInfoStorageShape == nullptr, OPS_LOG_E(nodeName, "tokenSrcInfoForCombine is null."),
                    return false);
    OPS_ERR_IF(tokenSrcInfoStorageShape->GetStorageShape().GetDimNum() != ONE_DIM,
                    OPS_LOG_E(nodeName, "tokenSrcInfoForCombine must be 1-dimension, but got %lu dim",
                            tokenSrcInfoStorageShape->GetStorageShape().GetDimNum()),
                    return false);
    OPS_LOG_D(nodeName, "tokenSrcInfoForCombine dim0 = %ld", tokenSrcInfoStorageShape->GetStorageShape().GetDim(0));

    const gert::StorageShape *topkWeightsStorageShape = context.GetInputShape(TOPK_WEIGHTS_INDEX);
    OPS_ERR_IF(topkWeightsStorageShape == nullptr, OPS_LOG_E(nodeName, "topkWeights is null."), return false);
    OPS_ERR_IF(topkWeightsStorageShape->GetStorageShape().GetDimNum() != TWO_DIMS,
                    OPS_LOG_E(nodeName, "topkWeights must be 2-dimension, but got %lu dim",
                            topkWeightsStorageShape->GetStorageShape().GetDimNum()),
                    return false);
    OPS_LOG_D(nodeName, "topkWeights dim0 = %ld", topkWeightsStorageShape->GetStorageShape().GetDim(0));
    OPS_LOG_D(nodeName, "topkWeights dim1 = %ld", topkWeightsStorageShape->GetStorageShape().GetDim(1));

    return true;
}

static bool CheckOptionalInputTensorDim(const gert::TilingContext &context, const char *nodeName)
{
    const gert::StorageShape *tpRecvCountsStorageShape = context.GetOptionalInputShape(TP_RECV_COUNTS_INDEX);
    OPS_ERR_IF(tpRecvCountsStorageShape == nullptr, OPS_LOG_E(nodeName, "tpRecvCounts is null."), return false);
    OPS_ERR_IF(tpRecvCountsStorageShape->GetStorageShape().GetDimNum() != ONE_DIM,
                    OPS_LOG_E(nodeName, "tpRecvCounts must be 1-dimension, but got %lu dim",
                            tpRecvCountsStorageShape->GetStorageShape().GetDimNum()),
                    return false);
    OPS_LOG_D(nodeName, "tpRecvCounts dim0 = %ld", tpRecvCountsStorageShape->GetStorageShape().GetDim(0));

    return true;
}

static bool CheckOutputTensorDim(const gert::TilingContext &context, const char *nodeName, const bool isEnableDiagnose)
{
    const gert::StorageShape *xStorageShape = context.GetOutputShape(OUTPUT_X_INDEX);
    OPS_ERR_IF(xStorageShape == nullptr, OPS_LOG_E(nodeName, "x is null."), return false);
    OPS_ERR_IF(
        xStorageShape->GetStorageShape().GetDimNum() != TWO_DIMS,
        OPS_LOG_E(nodeName, "x must be 2-dimension, but got %lu dim", xStorageShape->GetStorageShape().GetDimNum()),
        return false);
    OPS_LOG_D(nodeName, "x dim0 = %ld", xStorageShape->GetStorageShape().GetDim(0));
    OPS_LOG_D(nodeName, "x dim1 = %ld", xStorageShape->GetStorageShape().GetDim(1));

    if (isEnableDiagnose) {
        const gert::StorageShape *sendCostStatsStorageShape = context.GetOutputShape(OUTPUT_SEND_COST_INDEX);
        OPS_ERR_IF(sendCostStatsStorageShape == nullptr, OPS_LOG_E(nodeName, "combine sendCostStatsShape is null."),
                        return false);
        OPS_ERR_IF(sendCostStatsStorageShape->GetStorageShape().GetDimNum() != ONE_DIM,
                        OPS_LOG_E(nodeName, "combine sendCostStatsShape must be 1-dimension, but got %lu dim",
                                sendCostStatsStorageShape->GetStorageShape().GetDimNum()),
                        return false);
    }
    return true;
}

static bool CheckTensorDim(const gert::TilingContext &context, const char *nodeName, const bool isEnableDiagnose)
{
    OPS_ERR_IF(!CheckInputTensorDim(context, nodeName),
                    OPS_LOG_E(nodeName, "param shape of input tensor is invalid"), return false);

    OPS_ERR_IF(!CheckOptionalInputTensorDim(context, nodeName),
                    OPS_LOG_E(nodeName, "param shape of optional input tensor is invalid"), return false);

    OPS_ERR_IF(!CheckOutputTensorDim(context, nodeName, isEnableDiagnose),
                    OPS_LOG_E(nodeName, "param shape of output tensor is invalid"), return false);

    return true;
}

// 校验数据类型
static bool CheckTensorDataType(const gert::TilingContext &context, const char *nodeName, const bool isEnableDiagnose)
{
    auto recvXDesc = context.GetInputDesc(RECV_X_INDEX);
    OPS_ERR_IF(recvXDesc == nullptr, OPS_LOG_E(nodeName, "recvXDesc is null."), return false);
    OPS_ERR_IF((recvXDesc->GetDataType() != ge::DT_BF16) && (recvXDesc->GetDataType() != ge::DT_FLOAT16),
                    OPS_LOG_E(nodeName, "recvX dataType is invalid, dataType should be bf16 or float16, but is "),
                    return false);
    auto tokenSrcInfoDesc = context.GetInputDesc(TOKEN_SRC_INFO_INDEX);
    OPS_ERR_IF(tokenSrcInfoDesc == nullptr, OPS_LOG_E(nodeName, "tokenSrcInfoDesc is null."), return false);
    OPS_ERR_IF((tokenSrcInfoDesc->GetDataType() != ge::DT_INT32),
                    OPS_LOG_E(nodeName, "tokenSrcInfoForCombine dataType is invalid,"
                                      " dataType should be int32, but is"),
                    return false);
    auto tpRecvCountsDesc = context.GetOptionalInputDesc(TP_RECV_COUNTS_INDEX);
    OPS_ERR_IF(tpRecvCountsDesc == nullptr, OPS_LOG_E(nodeName, "tpRecvCountsDesc is null."), return false);
    OPS_ERR_IF((tpRecvCountsDesc->GetDataType() != ge::DT_INT32),
                    OPS_LOG_E(nodeName, "tpRecvCounts dataType is invalid, dataType should be int32, but is "),
                    return false);
    auto topkWeightsDesc = context.GetInputDesc(TOPK_WEIGHTS_INDEX);
    OPS_ERR_IF(topkWeightsDesc == nullptr, OPS_LOG_E(nodeName, "topkWeightsDesc is null."), return false);
    OPS_ERR_IF((topkWeightsDesc->GetDataType() != ge::DT_FLOAT),
                    OPS_LOG_E(nodeName, "topkWeights dataType is invalid, dataType should be float, but is "),
                    return false);
    auto xDesc = context.GetOutputDesc(OUTPUT_X_INDEX);
    OPS_ERR_IF(xDesc == nullptr, OPS_LOG_E(nodeName, "xDesc is null."), return false);
    OPS_ERR_IF((xDesc->GetDataType() != recvXDesc->GetDataType()),
                    OPS_LOG_E(nodeName, "x dataType is invalid, dataType should be equal to recvX dataType , but is "),
                    return false);

    if (isEnableDiagnose) {
        auto sendCostStatsDesc = context.GetOutputDesc(OUTPUT_SEND_COST_INDEX);
        OPS_ERR_IF(sendCostStatsDesc == nullptr, OPS_LOG_E(nodeName, "combine sendCostStatsDesc is null."),
                        return false);
        OPS_ERR_IF(
            sendCostStatsDesc->GetDataType() != ge::DT_INT32,
            OPS_LOG_E(nodeName, "combine sendCostStatsDesc dataType is invalid, dataType should be int32, but is ."),
            return false);
    }
    return true;
}

static bool CheckTensorFormat(const gert::TilingContext &context, const char *nodeName, const bool isEnableDiagnose)
{
    auto recvXDesc = context.GetInputDesc(RECV_X_INDEX);
    OPS_ERR_IF(recvXDesc == nullptr, OPS_LOG_E(nodeName, "recvXDesc is null."), return false);
    OPS_ERR_IF(static_cast<ge::Format>(ge::GetPrimaryFormat(recvXDesc->GetStorageFormat())) ==
                        ge::FORMAT_FRACTAL_NZ,
                    OPS_LOG_E(nodeName, "recvXFormat is invalid"), return false);

    auto tokenSrcInfoDesc = context.GetInputDesc(TOKEN_SRC_INFO_INDEX);
    OPS_ERR_IF(tokenSrcInfoDesc == nullptr, OPS_LOG_E(nodeName, "tokenSrcInfoDesc is null."), return false);
    OPS_ERR_IF(static_cast<ge::Format>(ge::GetPrimaryFormat(tokenSrcInfoDesc->GetStorageFormat())) ==
                        ge::FORMAT_FRACTAL_NZ,
                    OPS_LOG_E(nodeName, "tokenSrcInfoFormat is invalid"), return false);

    auto tpRecvCountsDesc = context.GetOptionalInputDesc(TP_RECV_COUNTS_INDEX);
    OPS_ERR_IF(tpRecvCountsDesc == nullptr, OPS_LOG_E(nodeName, "tpRecvCountsDesc is null."), return false);
    OPS_ERR_IF(static_cast<ge::Format>(ge::GetPrimaryFormat(tpRecvCountsDesc->GetStorageFormat())) ==
                        ge::FORMAT_FRACTAL_NZ,
                    OPS_LOG_E(nodeName, "tpRecvCountsFormat is invalid"), return false);

    auto topkWeightsDesc = context.GetInputDesc(TOPK_WEIGHTS_INDEX);
    OPS_ERR_IF(topkWeightsDesc == nullptr, OPS_LOG_E(nodeName, "topkWeightsDesc is null."), return false);
    OPS_ERR_IF(static_cast<ge::Format>(ge::GetPrimaryFormat(topkWeightsDesc->GetStorageFormat())) ==
                        ge::FORMAT_FRACTAL_NZ,
                    OPS_LOG_E(nodeName, "topkWeightsFormat is invalid"), return false);

    auto xDesc = context.GetOutputDesc(OUTPUT_X_INDEX);
    OPS_ERR_IF(xDesc == nullptr, OPS_LOG_E(nodeName, "xDesc is null."), return false);
    OPS_ERR_IF(static_cast<ge::Format>(ge::GetPrimaryFormat(xDesc->GetStorageFormat())) == ge::FORMAT_FRACTAL_NZ,
                    OPS_LOG_E(nodeName, "xFormat is invalid"), return false);

    if (isEnableDiagnose) {
        auto sendCostStatsDesc = context.GetOutputDesc(OUTPUT_SEND_COST_INDEX);
        OPS_ERR_IF(sendCostStatsDesc == nullptr, OPS_LOG_E(nodeName, "combine sendCostStatsDesc is null."),
                        return false);
        OPS_ERR_IF(static_cast<ge::Format>(ge::GetPrimaryFormat(sendCostStatsDesc->GetStorageFormat())) ==
                            ge::FORMAT_FRACTAL_NZ,
                        OPS_LOG_E(nodeName, "combine sendCostStatsDesc format is invalid"), return false);
    }
    return true;
}

static bool CheckTensorShape(const gert::TilingContext &context, MoeCombineNormalTilingData &tilingData,
                             const char *nodeName)
{
    const gert::StorageShape *topkWeightsStorageShape = context.GetInputShape(TOPK_WEIGHTS_INDEX);
    OPS_ERR_IF(topkWeightsStorageShape == nullptr, OPS_LOG_E(nodeName, "topkWeights is null."), return false);
    int64_t topkWeightsDim0 = topkWeightsStorageShape->GetStorageShape().GetDim(0);
    int64_t topkWeightsDim1 = topkWeightsStorageShape->GetStorageShape().GetDim(1);
    int64_t moeExpertNum = static_cast<int64_t>(tilingData.moeCombineNormalInfo.moeExpertNum);
    OPS_ERR_IF((topkWeightsDim1 <= 0) || (topkWeightsDim1 > K_MAX || (topkWeightsDim1 > moeExpertNum)),
                    OPS_LOG_E(nodeName,
                            "topkWeights's dim1(K) should be in (0, min(%ld, moeExpertNum %ld)], "
                            "but got topkWeights's dim1=%ld.",
                            K_MAX, moeExpertNum, topkWeightsDim1),
                    return false);
    tilingData.moeCombineNormalInfo.k = static_cast<uint32_t>(topkWeightsDim1);

    // 校验recvX的维度并设h
    const gert::StorageShape *recvXStorageShape = context.GetInputShape(RECV_X_INDEX);
    OPS_ERR_IF(recvXStorageShape == nullptr, OPS_LOG_E(nodeName, "recvX is null."), return false);
    int64_t recvXDim1 = recvXStorageShape->GetStorageShape().GetDim(1);
    OPS_ERR_IF((recvXDim1 < H_MIN) || (recvXDim1 > H_MAX),
                    OPS_LOG_E(nodeName, "recvX's dim1(H) should be in [%ld, %ld], but got %ld.",
                        H_MIN, H_MAX, recvXDim1),
                    return false); // 32对齐
    tilingData.moeCombineNormalInfo.h = static_cast<uint32_t>(recvXDim1);

    // 校验x的维度
    const gert::StorageShape *xStorageShape = context.GetOutputShape(OUTPUT_X_INDEX);
    OPS_ERR_IF(xStorageShape == nullptr, OPS_LOG_E(nodeName, "xStorageShape is null."), return false);
    int64_t xDim0 = xStorageShape->GetStorageShape().GetDim(0);
    int64_t xDim1 = xStorageShape->GetStorageShape().GetDim(1);
    OPS_ERR_IF(xDim0 != topkWeightsDim0,
                    OPS_LOG_E(nodeName, "x's dim0 not equal to bs, bs = %ld, x's dim0 = %ld", topkWeightsDim0, xDim0),
                    return false);
    OPS_ERR_IF(xDim1 != recvXDim1,
                    OPS_LOG_E(nodeName, "x's dim1 not equal to h, x's dim1 = %ld, h = %ld", xDim1, recvXDim1),
                    return false);

    return true;
}

static bool CheckAttrs(const gert::TilingContext &context, MoeCombineNormalTilingData &tilingData, const char *nodeName,
                       uint32_t &localMoeExpertNum)
{
    uint32_t epWorldSize = tilingData.moeCombineNormalInfo.epWorldSize;
    uint32_t tpWorldSize = tilingData.moeCombineNormalInfo.tpWorldSize;
    uint32_t moeExpertNum = tilingData.moeCombineNormalInfo.moeExpertNum;

    // 校验moe专家数量能否均分给多机
    OPS_ERR_IF(moeExpertNum % epWorldSize != 0,
                    OPS_LOG_E(nodeName,
                            "moeExpertNum should be divisible by epWorldSize, "
                            "but got moeExpertNum=%u, epWorldSize=%u.",
                            moeExpertNum, epWorldSize),
                    return false);
    localMoeExpertNum = moeExpertNum / epWorldSize;
    OPS_ERR_IF(localMoeExpertNum <= 0,
                    OPS_LOG_E(nodeName, "localMoeExpertNum is invalid, localMoeExpertNum = %u", localMoeExpertNum),
                    return false);
    // 校验tp=2时单个moe卡上专家数是否等于1
    OPS_ERR_IF((localMoeExpertNum > 1) && (tpWorldSize > 1),
                    OPS_LOG_E(nodeName, "Cannot support multi-moeExpert %u in a rank when tpWorldSize = %u > 1",
                            localMoeExpertNum, tpWorldSize),
                    return false);
    tilingData.moeCombineNormalInfo.moeExpertPerRankNum = localMoeExpertNum;

    // 校验输入topkWeights的维度0并设bs
    const gert::StorageShape *topkWeightsStorageShape = context.GetInputShape(TOPK_WEIGHTS_INDEX);
    OPS_ERR_IF(topkWeightsStorageShape == nullptr, OPS_LOG_E(nodeName, "topkWeights is null."), return false);
    int64_t topkWeightsDim0 = topkWeightsStorageShape->GetStorageShape().GetDim(0);
    OPS_ERR_IF((topkWeightsDim0 <= 0) || (topkWeightsDim0 > BS_UPPER_BOUND),
                    OPS_LOG_E(nodeName, "Invalid topkWeights dims0(BS) %ld. Should be between [1, %ld].",
                        topkWeightsDim0, BS_UPPER_BOUND),
                    return false);
    tilingData.moeCombineNormalInfo.bs = static_cast<uint32_t>(topkWeightsDim0);

    // 校验globalBS
    auto attrs = context.GetAttrs();
    OPS_ERR_IF(attrs == nullptr, OPS_LOG_E(nodeName, "attrs is null."), return false);
    auto globalBsPtr = attrs->GetAttrPointer<int64_t>(ATTR_GLOBAL_BS_INDEX);
    OPS_ERR_IF(globalBsPtr == nullptr, OPS_LOG_E(nodeName, "globalBs is null."), return false);
    OPS_LOG_D(nodeName, "MoeCombineNormal *globalBsPtr = %ld, bs = %ld, epWorldSize = %u\n", *globalBsPtr,
              topkWeightsDim0, epWorldSize);

    OPS_ERR_IF(
        (*globalBsPtr != 0) && ((*globalBsPtr < static_cast<int64_t>(epWorldSize) * topkWeightsDim0) ||
                                ((*globalBsPtr) % (static_cast<int64_t>(epWorldSize)) != 0)),
        OPS_LOG_E(nodeName,
                "globalBS is invalid, only "
                "support 0 or maxBs(maxBs is the largest bs on all ranks) * epWorldSize, but got globalBS=%ld, "
                "bs=%ld, epWorldSize=%u.",
                *globalBsPtr, topkWeightsDim0, epWorldSize),
        return false);

    tilingData.moeCombineNormalInfo.globalBs = static_cast<uint32_t>(*globalBsPtr);
    if (*globalBsPtr == 0) {
        tilingData.moeCombineNormalInfo.globalBs = static_cast<uint32_t>(topkWeightsDim0) * epWorldSize;
    }

    return true;
}

static ge::graphStatus TilingCheckMoeCombineNormal(const gert::TilingContext &context, const char *nodeName,
                                                   const bool isEnableDiagnose)
{
    // 检查参数shape信息
    OPS_ERR_IF(!CheckTensorDim(context, nodeName, isEnableDiagnose), OPS_LOG_E(nodeName, "param shape is invalid"),
                    return ge::GRAPH_FAILED);
    // 检查参数dataType信息
    OPS_ERR_IF(!CheckTensorDataType(context, nodeName, isEnableDiagnose),
                    OPS_LOG_E(nodeName, "param dataType is invalid"), return ge::GRAPH_FAILED);
    // 检查参数format信息
    OPS_ERR_IF(!CheckTensorFormat(context, nodeName, isEnableDiagnose),
                    OPS_LOG_E(nodeName, "param Format is invalid"), return ge::GRAPH_FAILED);
    return ge::GRAPH_SUCCESS;
}

static ge::graphStatus SetWorkspace(gert::TilingContext &context, const char *nodeName)
{
    size_t *workspace = context.GetWorkspaceSizes(1);
    OPS_ERR_IF(workspace == nullptr, VECTOR_INNER_ERR_REPORT_TILIING(nodeName, "get workspace failed"),
                    return ge::GRAPH_FAILED);
    workspace[0] = SYSTEM_NEED_WORKSPACE;
    OPS_LOG_D(nodeName, "workspace[0] size is %ld", workspace[0]);
    return ge::GRAPH_SUCCESS;
}

static void SetHCommCfg(const gert::TilingContext &context, MoeCombineNormalTilingData &tiling,
    const std::string groupEp, const std::string groupTp)
{
    const char *nodeName = context.GetNodeName();
    OPS_LOG_D(nodeName, "MoeCombineNormal groupEp = %s, groupTp = %s", groupEp.c_str(), groupTp.c_str());
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

static ge::graphStatus MoeCombineNormalA3TilingFuncImpl(gert::TilingContext &context)
{
    const char *nodeName = context.GetNodeName();
    OPS_ERR_IF(nodeName == nullptr, OPS_LOG_E("unKnownNodeName", "nodeName is nullptr."), return ge::GRAPH_FAILED);
    OPS_LOG_D(nodeName, "Enter MoeCombineNormal Tiling func");
    MoeCombineNormalTilingData *tilingData = context.GetTilingData<MoeCombineNormalTilingData>();
    OPS_ERR_IF(tilingData == nullptr, OPS_LOG_E(nodeName, "tilingData is nullptr."), return ge::GRAPH_FAILED);
    std::string groupEp = "";
    std::string groupTp = "";
    uint32_t localMoeExpertNum = 1;

    // 获取入参属性
    OPS_ERR_IF(GetAttrAndSetTilingData(context, *tilingData, nodeName, groupEp, groupTp) == ge::GRAPH_FAILED,
                    OPS_LOG_E(nodeName, "Getting attr failed."), return ge::GRAPH_FAILED);

    auto sendCostStatsStorageShape = context.GetOutputShape(OUTPUT_SEND_COST_INDEX);
    bool isEnableDiagnose = (sendCostStatsStorageShape != nullptr);
    tilingData->moeCombineNormalInfo.isEnableDiagnose = isEnableDiagnose;
    // 检查输入输出的dim、format、dataType
    OPS_ERR_IF(TilingCheckMoeCombineNormal(context, nodeName, isEnableDiagnose) != ge::GRAPH_SUCCESS,
                    OPS_LOG_E(nodeName, "Tiling check params failed"), return ge::GRAPH_FAILED);

    // 检查属性的取值是否合法
    OPS_ERR_IF(!CheckAttrs(context, *tilingData, nodeName, localMoeExpertNum),
                    OPS_LOG_E(nodeName, "attr check failed."), return ge::GRAPH_FAILED);

    uint32_t epRankId = tilingData->moeCombineNormalInfo.epRankId;

    // 检查shape各维度并赋值h,k
    OPS_ERR_IF(!CheckTensorShape(context, *tilingData, nodeName),
                    OPS_LOG_E(nodeName, "param dim check failed."), return ge::GRAPH_FAILED);

    // 校验win区大小
    uint64_t maxWindowSize = Mc2TilingUtils::GetMaxWindowSize();
    uint64_t h = static_cast<uint64_t>(tilingData->moeCombineNormalInfo.h);
    uint64_t epWorldSize = static_cast<uint64_t>(tilingData->moeCombineNormalInfo.epWorldSize);
    uint64_t k = static_cast<uint64_t>(tilingData->moeCombineNormalInfo.k);
    uint64_t maxBs = static_cast<uint64_t>(tilingData->moeCombineNormalInfo.globalBs) / epWorldSize;
    // combine数据区 token首地址对齐512
    uint64_t tokenNeedSizeCombine = ((h * MAX_OUT_DTYPE_SIZE + WIN_ADDR_ALIGN - 1UL) / WIN_ADDR_ALIGN) * WIN_ADDR_ALIGN;
    uint64_t actualSize =
        (maxBs * k * tokenNeedSizeCombine + COMBINE_STATE_WIN_OFFSET + NOTIFY_DISPATCH_WIN_OFFSET) * DOUBLE_DATA_BUFFER;
    OPS_ERR_IF(
        (actualSize > maxWindowSize),
        OPS_LOG_E(nodeName,
                "HCCL_BUFFSIZE is too SMALL, maxBs = %lu, h = %lu, epWorldSize = %lu, localMoeExpertNum = %u,"
                " tokenNeedSizeCombine = %lu, k = %lu, NEEDED_HCCL_BUFFSIZE("
                "((maxBs * k * tokenNeedSizeCombine)) + 3MB + 204MB) * 2) = %luMB, "
                "HCCL_BUFFSIZE=%luMB.",
                maxBs, h, epWorldSize, localMoeExpertNum, tokenNeedSizeCombine, k, actualSize / MB_SIZE + 1UL,
                maxWindowSize / MB_SIZE),
        return ge::GRAPH_FAILED);
    tilingData->moeCombineNormalInfo.totalWinSize = maxWindowSize;

    OPS_ERR_IF(SetWorkspace(context, nodeName) != ge::GRAPH_SUCCESS,
                    VECTOR_INNER_ERR_REPORT_TILIING(context.GetNodeName(), "Tiling set workspace Failed"),
                    return ge::GRAPH_FAILED);

    SetHCommCfg(context, *tilingData, groupEp, groupTp);

    uint32_t blockDim = 1U;
    auto ascendcPlatform = platform_ascendc::PlatformAscendC(context.GetPlatformInfo());
    uint64_t aivNum = ascendcPlatform.GetCoreNumAiv();
    uint64_t ubSize = 0UL;
    ascendcPlatform.GetCoreMemSize(platform_ascendc::CoreMemType::UB, ubSize);
    blockDim = ascendcPlatform.CalcTschBlockDim(aivNum, 0, aivNum);
    context.SetBlockDim(blockDim);
    tilingData->moeCombineNormalInfo.aivNum = aivNum;
    tilingData->moeCombineNormalInfo.totalUbSize = ubSize;
    context.SetScheduleMode(1);  // Set to batch mode, all cores start simultaneously
    OPS_LOG_D(nodeName, "blockdim = %u, aivNum = %lu, ubsize = %lu", blockDim, aivNum, ubSize);
    PrintTilingDataInfo(nodeName, *tilingData);

    return ge::GRAPH_SUCCESS;
}

static ge::graphStatus MoeCombineNormalTilingFunc(gert::TilingContext *context)
{
    // 不支持 recvX数据类型为int32 type
    auto recvXDesc = context->GetInputDesc(RECV_X_INDEX);
    const char *nodeName = context->GetNodeName();
    OPS_ERR_IF(recvXDesc == nullptr, OPS_LOG_E(nodeName, "recvXDesc is null."), return ge::GRAPH_FAILED);
    // 检查recvX数据类型为DT_INT32
    OPS_ERR_IF((recvXDesc->GetDataType() == ge::DT_INT32),
                    OPS_LOG_E(nodeName, "recvX dataType is invalid, dataType should be bf16 or float16, but is "),
                    return ge::GRAPH_FAILED);

    ge::graphStatus ret = MoeCombineNormalA3TilingFuncImpl(*context);
    return ret;
}

struct MoeCombineNormalCompileInfo {};
ge::graphStatus TilingParseForMoeCombineNormal(gert::TilingParseContext *context)
{
    (void)context;
    return ge::GRAPH_SUCCESS;
}

IMPL_OP_OPTILING(MoeCombineNormal)
    .Tiling(MoeCombineNormalTilingFunc)
    .TilingParse<MoeCombineNormalCompileInfo>(TilingParseForMoeCombineNormal);
} // namespace optiling