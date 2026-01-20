/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2025-2025. All rights reserved.
 * Description: FusedDeepMoe tiling function implementation file
 * Create: 2025-07-19
 * Note:
 * History: 2025-07-19 create FusedDeepMoe tiling function implementation file
 */
#include <cstdio>
#include <cstdint>
#include <string>

#include "error_log.h"
#include "graph/utils/type_utils.h"
#include "register/op_def_registry.h"
#include "../op_kernel/fused_deep_moe_tiling.h"
#include "tiling/platform/platform_ascendc.h"
#include "tiling/hccl/hccl_tiling.h"


using namespace ge;
namespace {
constexpr uint32_t OP_TYPE_ALL_TO_ALL = 8;
constexpr uint32_t SYSTEM_NEED_WORKSPACE = 16 * 1024 * 1024;
constexpr uint32_t GM_ALIGN_SIZE = 512;
constexpr uint32_t TOKEN_DTYPE_BYTE_SIZE = 2;
constexpr uint32_t L1_TILE_BYTE_SIZE = 32 * 1024;
constexpr uint32_t CUBE_WORKSPACE_STAGE = 4;
constexpr uint32_t RESERVED_WORKSPACE_SIZE = 256 * 1024;

constexpr uint32_t INPUT_X_INDEX = 0;
constexpr uint32_t INPUT_EXPERT_IDS_INDEX = 1;
constexpr uint32_t INPUT_GMM1_WEIGHT_INDEX = 2;
constexpr uint32_t INPUT_GMM1_WEIGHT_SCALE_INDEX = 3;
constexpr uint32_t INPUT_GMM2_WEIGHT_INDEX = 4;
constexpr uint32_t INPUT_GMM2_WEIGHT_SCALE_INDEX = 5;
constexpr uint32_t INPUT_SMOOTH_SCALE_INDEX = 6;
constexpr uint32_t INPUT_EXPERT_SCALE_INDEX = 7;

constexpr uint32_t ATTR_GROUP_EP_INDEX = 0;
constexpr uint32_t ATTR_EP_RANK_SIZE_INDEX = 1;
constexpr uint32_t ATTR_EP_RANK_ID_INDEX = 2;
constexpr uint32_t ATTR_MOE_EXPERT_NUM_INDEX = 3;
constexpr uint32_t ATTR_SHARE_EXPERT_NUM_INDEX = 4;
constexpr uint32_t ATTR_SHARE_EXPERT_RANK_NUM_INDEX = 5;
constexpr uint32_t ATTR_QUANT_MODE_INDEX = 6;
constexpr uint32_t ATTR_GLOBAL_BS_INDEX = 7;

constexpr uint32_t MIN_BATCH_SIZE = 0;
constexpr uint32_t MAX_BATCH_SIZE = 256;
constexpr uint32_t MAX_MOE_EXERT_NUM = 512;
constexpr uint32_t SUPPORT_TOP_K = 12;
constexpr uint32_t TWO_DIMS = 2;
constexpr uint32_t MIN_TOKEN_LENGTH = 1024;
constexpr uint32_t MAX_TOKEN_LENGTH = 7168;
constexpr uint32_t MIN_GMM1_HIDDEN = 1024;
constexpr uint32_t MAX_GMM1_HIDDEN = 6144;
constexpr uint32_t TENSOR_HIDDEN_INDEX = 1;
constexpr uint32_t SINGLE_HIDDEN_INDEX = 2;
constexpr uint32_t MAX_TENSOR_COUNT = 256;
}  // namespace

namespace optiling {
static size_t CeilUp(size_t x, size_t y)
{
    return (x + y - 1) / y * y;
}

static uint32_t CountTensorListLen(gert::TilingContext *context, int descIndex)
{
    int count = 0;
    for (uint32_t i = 0; i < MAX_TENSOR_COUNT; i++) {
        auto tensorElement = context->GetDynamicInputTensor(descIndex, i);
        if (tensorElement == nullptr) {
            break;
        }
        count++;
    }
    return count;
}

static ge::graphStatus CheckGmm1Shape(gert::TilingContext *context, FusedDeepMoeTilingData &tilingData)
{
    const char *nodeName = context->GetNodeName();
    uint32_t moeExpertNumPerRank = tilingData.disGmmDeqSwigluQuantGmmDeqComInfo.moeExpertNumPerRank;
    uint32_t h = tilingData.disGmmDeqSwigluQuantGmmDeqComInfo.h;
    uint32_t gmm1ListLen = CountTensorListLen(context, INPUT_GMM1_WEIGHT_INDEX);
    auto gmm1FirstTensorElement = context->GetDynamicInputTensor(INPUT_GMM1_WEIGHT_INDEX, 0);
    auto gmm1FirstTensorElementShape = gmm1FirstTensorElement->GetOriginShape();
    uint32_t elementDims = gmm1FirstTensorElementShape.GetDimNum();
    uint32_t epRankId = tilingData.disGmmDeqSwigluQuantGmmDeqComInfo.epRankId;
    uint32_t sharedExpertRankNum = tilingData.disGmmDeqSwigluQuantGmmDeqComInfo.sharedExpertRankNum;
    uint32_t localExpertNum = epRankId < sharedExpertRankNum ? 1 : moeExpertNumPerRank;

    OP_TILING_CHECK(elementDims != 2 && elementDims != 3, OP_LOGE(nodeName, "gmm1Weight shape is invalid."),
            return ge::GRAPH_FAILED);
    if (gmm1ListLen > 1) { // List
        OP_TILING_CHECK(gmm1ListLen != localExpertNum,
                OP_LOGE(nodeName, "gmm1 listlen does not equals to localExpertNum."), return ge::GRAPH_FAILED);
        OP_TILING_CHECK(h != gmm1FirstTensorElementShape.GetDim(0),
                OP_LOGE(nodeName, "gmm1Weight input length does not equals to token hidden size."),
                return ge::GRAPH_FAILED);
        OP_TILING_CHECK(gmm1ListLen != localExpertNum,
                OP_LOGE(nodeName, "gmm1Weight does not match local expert number perRank."),
                return ge::GRAPH_FAILED);
        tilingData.disGmmDeqSwigluQuantGmmDeqComInfo.gmm1HLen = 
                                                gmm1FirstTensorElementShape.GetDim(TENSOR_HIDDEN_INDEX);
        tilingData.disGmmDeqSwigluQuantGmmDeqComInfo.isTensorList = true;
    } else { // Single
        if (elementDims == 2) {  // one localExpert perRank
            OP_TILING_CHECK(h != gmm1FirstTensorElementShape.GetDim(0),
                OP_LOGE(nodeName, "gmm1Weight input length does not equals to token hidden size."),
                return ge::GRAPH_FAILED);
            tilingData.disGmmDeqSwigluQuantGmmDeqComInfo.gmm1HLen = 
                                                gmm1FirstTensorElementShape.GetDim(SINGLE_HIDDEN_INDEX - 1);
        } else {    // multi localExperts perRank
            OP_TILING_CHECK(localExpertNum != gmm1FirstTensorElementShape.GetDim(0),
                OP_LOGE(nodeName, "gmm1Weight does not match local expert number per rank."),
                return ge::GRAPH_FAILED);
            OP_TILING_CHECK(h != gmm1FirstTensorElementShape.GetDim(1),
                OP_LOGE(nodeName, "gmm1Weight input length does not equals to token hidden size."),
                return ge::GRAPH_FAILED);
            tilingData.disGmmDeqSwigluQuantGmmDeqComInfo.gmm1HLen = 
                                                gmm1FirstTensorElementShape.GetDim(SINGLE_HIDDEN_INDEX);
        }
        tilingData.disGmmDeqSwigluQuantGmmDeqComInfo.isTensorList = false;
    }
    return ge::GRAPH_SUCCESS;
}

static ge::graphStatus CheckGmm1ScaleShape(gert::TilingContext *context,
                                                FusedDeepMoeTilingData &tilingData)
{
    const char *nodeName = context->GetNodeName();
    uint32_t moeExpertNumPerRank = tilingData.disGmmDeqSwigluQuantGmmDeqComInfo.moeExpertNumPerRank;
    uint32_t n = tilingData.disGmmDeqSwigluQuantGmmDeqComInfo.gmm1HLen;
    uint32_t epRankId = tilingData.disGmmDeqSwigluQuantGmmDeqComInfo.epRankId;
    uint32_t sharedExpertRankNum = tilingData.disGmmDeqSwigluQuantGmmDeqComInfo.sharedExpertRankNum;
    uint32_t localExpertNum = epRankId < sharedExpertRankNum ? 1 : moeExpertNumPerRank;

    uint32_t gmm1ScaleListLen = CountTensorListLen(context, INPUT_GMM1_WEIGHT_SCALE_INDEX);
    auto gmm1ScaleFirstTensorElement = context->GetDynamicInputTensor(INPUT_GMM1_WEIGHT_SCALE_INDEX, 0);
    auto gmm1ScaleFirstTensorElementShape = gmm1ScaleFirstTensorElement->GetOriginShape();
    uint32_t elementDims = gmm1ScaleFirstTensorElementShape.GetDimNum();
    OP_TILING_CHECK(elementDims != 1 && elementDims != 2, OP_LOGE(nodeName, "gmm1WeightScale shape is invalid."),
            return ge::GRAPH_FAILED);
    if (gmm1ScaleListLen > 1) { // List
        OP_TILING_CHECK(gmm1ScaleListLen != localExpertNum,
                OP_LOGE(nodeName, "gmm1scale listlen does not equals to localExpertNum."), return ge::GRAPH_FAILED);
        OP_TILING_CHECK(n != gmm1ScaleFirstTensorElementShape.GetDim(0),
                OP_LOGE(nodeName, "gmm1Scale length does not equals to gmm1 hidden size."), return ge::GRAPH_FAILED);
    } else { // Single
        if (elementDims == 1) { // one localExpert perRank
            OP_TILING_CHECK(n != gmm1ScaleFirstTensorElementShape.GetDim(0),
                OP_LOGE(nodeName, "gmm1Scale length does not equals to gmm1 hidden size."), return ge::GRAPH_FAILED);
        } else { // multi localExperts perRank
            OP_TILING_CHECK(localExpertNum != gmm1ScaleFirstTensorElementShape.GetDim(0),
                OP_LOGE(nodeName, "gmm1Scale does not match local expert number perRank."), return ge::GRAPH_FAILED);
            OP_TILING_CHECK(n != gmm1ScaleFirstTensorElementShape.GetDim(1),
                OP_LOGE(nodeName, "gmm1Scale length does not equals to gmm1 hidden size."), return ge::GRAPH_FAILED);
        }
    }
    return ge::GRAPH_SUCCESS;
}

static ge::graphStatus CheckGmm2Shape(gert::TilingContext *context, FusedDeepMoeTilingData &tilingData)
{
    const char *nodeName = context->GetNodeName();
    uint32_t moeExpertNumPerRank = tilingData.disGmmDeqSwigluQuantGmmDeqComInfo.moeExpertNumPerRank;
    uint32_t h = tilingData.disGmmDeqSwigluQuantGmmDeqComInfo.h;
    uint32_t n = tilingData.disGmmDeqSwigluQuantGmmDeqComInfo.gmm1HLen;
    uint32_t epRankId = tilingData.disGmmDeqSwigluQuantGmmDeqComInfo.epRankId;
    uint32_t sharedExpertRankNum = tilingData.disGmmDeqSwigluQuantGmmDeqComInfo.sharedExpertRankNum;
    uint32_t localExpertNum = epRankId < sharedExpertRankNum ? 1 : moeExpertNumPerRank;
    
    uint32_t gmm2ListLen = CountTensorListLen(context, INPUT_GMM2_WEIGHT_INDEX);
    auto gmm2FirstTensorElement = context->GetDynamicInputTensor(INPUT_GMM2_WEIGHT_INDEX, 0);
    auto gmm2FirstTensorElementShape = gmm2FirstTensorElement->GetOriginShape();
    uint32_t elementDims = gmm2FirstTensorElementShape.GetDimNum();
    OP_TILING_CHECK(elementDims != 2 && elementDims != 3, OP_LOGE(nodeName, "gmm2Weight shape is invalid."),
            return ge::GRAPH_FAILED);
    if (gmm2ListLen > 1) { // List
        OP_TILING_CHECK(gmm2ListLen != localExpertNum,
                OP_LOGE(nodeName, "gmm2 does not match local expert number perRank."), return ge::GRAPH_FAILED);
        OP_TILING_CHECK(n / 2 != gmm2FirstTensorElementShape.GetDim(1),
                OP_LOGE(nodeName, "gmm2 does not match half of gmm1 hidden size."), return ge::GRAPH_FAILED);
        OP_TILING_CHECK(h != gmm2FirstTensorElementShape.GetDim(0),
                OP_LOGE(nodeName, "gmm2 does not match token hidden size."), return ge::GRAPH_FAILED);
    } else { // Single
        if (elementDims == 2) { // one localExpert perRank
            OP_TILING_CHECK(n / 2 != gmm2FirstTensorElementShape.GetDim(1),
                OP_LOGE(nodeName, "gmm2 does not match half of gmm1 hidden size."), return ge::GRAPH_FAILED);
            OP_TILING_CHECK(h != gmm2FirstTensorElementShape.GetDim(0),
                OP_LOGE(nodeName, "gmm2 does not match token hidden size."), return ge::GRAPH_FAILED);
        } else { // multi localExperts perRank
            OP_TILING_CHECK(localExpertNum != gmm2FirstTensorElementShape.GetDim(0),
                OP_LOGE(nodeName, "gmm2 does not match local expert num perRank."), return ge::GRAPH_FAILED);
            OP_TILING_CHECK(n / 2 != gmm2FirstTensorElementShape.GetDim(2),
                OP_LOGE(nodeName, "gmm2 does not match half of gmm1 hidden size."), return ge::GRAPH_FAILED);
            OP_TILING_CHECK(h != gmm2FirstTensorElementShape.GetDim(1),
                OP_LOGE(nodeName, "gmm2 does not match token hidden size."), return ge::GRAPH_FAILED);
        }
    }
    return ge::GRAPH_SUCCESS;
}

static ge::graphStatus CheckGmm2ScaleShape(gert::TilingContext *context,
                                                FusedDeepMoeTilingData &tilingData)
{
    const char *nodeName = context->GetNodeName();
    uint32_t moeExpertNumPerRank = tilingData.disGmmDeqSwigluQuantGmmDeqComInfo.moeExpertNumPerRank;
    uint32_t h = tilingData.disGmmDeqSwigluQuantGmmDeqComInfo.h;
    uint32_t epRankId = tilingData.disGmmDeqSwigluQuantGmmDeqComInfo.epRankId;
    uint32_t sharedExpertRankNum = tilingData.disGmmDeqSwigluQuantGmmDeqComInfo.sharedExpertRankNum;
    uint32_t localExpertNum = epRankId < sharedExpertRankNum ? 1 : moeExpertNumPerRank;

    uint32_t gmm2ScaleListLen = CountTensorListLen(context, INPUT_GMM2_WEIGHT_SCALE_INDEX);
    auto gmm2ScaleFirstTensorElement = context->GetDynamicInputTensor(INPUT_GMM2_WEIGHT_SCALE_INDEX, 0);
    auto gmm2ScaleFirstTensorElementShape = gmm2ScaleFirstTensorElement->GetOriginShape();
    uint32_t elementDims = gmm2ScaleFirstTensorElementShape.GetDimNum();
    OP_TILING_CHECK(elementDims != 1 && elementDims != 2, OP_LOGE(nodeName, "gmm2WeightScale shape is invalid."),
            return ge::GRAPH_FAILED);
    if (gmm2ScaleListLen > 1) { // List
        OP_TILING_CHECK(gmm2ScaleListLen != localExpertNum,
                OP_LOGE(nodeName, "gmm2scale listlen does not equals to localExpertNum."), return ge::GRAPH_FAILED);
        OP_TILING_CHECK(h != gmm2ScaleFirstTensorElementShape.GetDim(0),
                OP_LOGE(nodeName, "gmm2Scale does not match token hidden size."), return ge::GRAPH_FAILED);
    } else { // Single
        if (elementDims == 1) { // one localExpert perRank
            OP_TILING_CHECK(h != gmm2ScaleFirstTensorElementShape.GetDim(0),
                OP_LOGE(nodeName, "gmm2Scale does not match token hidden size."), return ge::GRAPH_FAILED);
        } else { // multi localExperts perRank
            OP_TILING_CHECK(localExpertNum != gmm2ScaleFirstTensorElementShape.GetDim(0),
                OP_LOGE(nodeName, "gmm2Scale does not match local expert number perRank."), return ge::GRAPH_FAILED);
            OP_TILING_CHECK(h != gmm2ScaleFirstTensorElementShape.GetDim(1),
                OP_LOGE(nodeName, "gmm2Scale does not match token hidden size."), return ge::GRAPH_FAILED);
        }
    }
    return ge::GRAPH_SUCCESS;
}

static ge::graphStatus CheckWeightTensorList(gert::TilingContext *context,
                                                FusedDeepMoeTilingData &tilingData)
{
    if (CheckGmm1Shape(context, tilingData) == ge::GRAPH_SUCCESS &&
        CheckGmm1ScaleShape(context, tilingData) == ge::GRAPH_SUCCESS &&
        CheckGmm2Shape(context, tilingData) == ge::GRAPH_SUCCESS &&
        CheckGmm2ScaleShape(context, tilingData) == ge::GRAPH_SUCCESS) {
        return ge::GRAPH_SUCCESS;
    }
    return ge::GRAPH_FAILED;
}

static ge::graphStatus CheckData(const char *nodeName, FusedDeepMoeTilingData &tilingData)
{
    uint32_t batchSize = tilingData.disGmmDeqSwigluQuantGmmDeqComInfo.bs;
    OP_TILING_CHECK(batchSize < MIN_BATCH_SIZE, OP_LOGE(nodeName, "batchSize(bs) must >= %d.", MIN_BATCH_SIZE),
                    return ge::GRAPH_FAILED);
    OP_TILING_CHECK(batchSize > MAX_BATCH_SIZE, OP_LOGE(nodeName, "batchSize(bs) must <= %d.", MAX_BATCH_SIZE),
                    return ge::GRAPH_FAILED);
    uint32_t tokenLength = tilingData.disGmmDeqSwigluQuantGmmDeqComInfo.h;
    OP_TILING_CHECK(
        tokenLength < MIN_TOKEN_LENGTH || tokenLength > MAX_TOKEN_LENGTH,
        OP_LOGE(nodeName, "tokenLength(h) is invalid. Only support [%u, %u].", MIN_TOKEN_LENGTH, MAX_TOKEN_LENGTH),
        return ge::GRAPH_FAILED);
    uint32_t gmm1HLen = tilingData.disGmmDeqSwigluQuantGmmDeqComInfo.gmm1HLen;
    OP_TILING_CHECK(
        gmm1HLen < MIN_GMM1_HIDDEN || gmm1HLen > MAX_GMM1_HIDDEN,
        OP_LOGE(nodeName, "gmm1 hidden size is invalid. Only support [%u, %u].", MIN_GMM1_HIDDEN, MAX_GMM1_HIDDEN),
        return ge::GRAPH_FAILED);
    uint32_t topK = tilingData.disGmmDeqSwigluQuantGmmDeqComInfo.k;
    OP_TILING_CHECK(topK > SUPPORT_TOP_K, OP_LOGE(nodeName, "topK(k) must <= %d.", SUPPORT_TOP_K),
                    return ge::GRAPH_FAILED);
    uint32_t globalBatchSize = tilingData.disGmmDeqSwigluQuantGmmDeqComInfo.globalBs;
    uint32_t epRankSize = tilingData.disGmmDeqSwigluQuantGmmDeqComInfo.epRankSize;
    if (globalBatchSize == 0) {
        globalBatchSize = epRankSize * batchSize;
        tilingData.disGmmDeqSwigluQuantGmmDeqComInfo.globalBs = globalBatchSize;
    } else {
        OP_TILING_CHECK(globalBatchSize < 0, OP_LOGE(nodeName, "globalBatchSize must >= 0."), return ge::GRAPH_FAILED);
        OP_TILING_CHECK(globalBatchSize % epRankSize > 0,
                        OP_LOGE(nodeName, "globalBatchSize must be divisible by epRankSize."),
                        return ge::GRAPH_FAILED);
    }
    uint32_t moeExpertNumPerRank = tilingData.disGmmDeqSwigluQuantGmmDeqComInfo.moeExpertNumPerRank;
    uint32_t recvAivNum = tilingData.disGmmDeqSwigluQuantGmmDeqComInfo.aivNum / 2;
    OP_TILING_CHECK(
        moeExpertNumPerRank > recvAivNum,
        OP_LOGE(nodeName, "moeExpertNumPerRank must <= (aivNum/2)(%u), but got %u", recvAivNum, moeExpertNumPerRank),
        return ge::GRAPH_FAILED);
    return ge::GRAPH_SUCCESS;
}

static ge::graphStatus GetAttrAndSetTilingData(gert::TilingContext *context, const char *nodeName,
                                               FusedDeepMoeTilingData &tilingData, std::string &groupEp)
{
    auto attrs = context->GetAttrs();
    OP_TILING_CHECK(attrs == nullptr, OP_LOGE(nodeName, "attrs is nullptr."), return ge::GRAPH_FAILED);

    auto groupEpPtr = attrs->GetAttrPointer<char>(static_cast<int>(ATTR_GROUP_EP_INDEX));
    auto epRankSizePtr = attrs->GetAttrPointer<int64_t>(ATTR_EP_RANK_SIZE_INDEX);
    auto epRankIdPtr = attrs->GetAttrPointer<int64_t>(ATTR_EP_RANK_ID_INDEX);
    auto moeExpertNumPtr = attrs->GetAttrPointer<int64_t>(ATTR_MOE_EXPERT_NUM_INDEX);
    auto sharedExpertNumPtr = attrs->GetAttrPointer<int64_t>(ATTR_SHARE_EXPERT_NUM_INDEX);
    auto sharedExpertRankNumPtr = attrs->GetAttrPointer<int64_t>(ATTR_SHARE_EXPERT_RANK_NUM_INDEX);
    auto quantModePtr = attrs->GetAttrPointer<int64_t>(ATTR_QUANT_MODE_INDEX);
    auto globalBsPtr = attrs->GetAttrPointer<int64_t>(ATTR_GLOBAL_BS_INDEX);

    uint32_t epRankSize = static_cast<uint32_t>(*epRankSizePtr);
    uint32_t epRankId = static_cast<uint32_t>(*epRankIdPtr);
    uint32_t moeExpertNum = static_cast<uint32_t>(*moeExpertNumPtr);
    uint32_t sharedExpertNum = static_cast<uint32_t>(*sharedExpertNumPtr);
    uint32_t sharedExpertRankNum = static_cast<uint32_t>(*sharedExpertRankNumPtr);
    uint32_t moeExpertNumPerRank = moeExpertNum / (epRankSize - sharedExpertRankNum);

    OP_TILING_CHECK(epRankId < 0, OP_LOGE(nodeName, "epRankId must >= 0."), return ge::GRAPH_FAILED);
    OP_TILING_CHECK(epRankId >= epRankSize, OP_LOGE(nodeName, "epRankId must < epRankSize."), return ge::GRAPH_FAILED);
    OP_TILING_CHECK(moeExpertNum > MAX_MOE_EXERT_NUM, OP_LOGE(nodeName, "moeExpertNum must <= %d.", MAX_MOE_EXERT_NUM),
                    return ge::GRAPH_FAILED);
    OP_TILING_CHECK(moeExpertNum <= 0, OP_LOGE(nodeName, "moeExpertNum must > 0."), return ge::GRAPH_FAILED);
    OP_TILING_CHECK(sharedExpertNum != 1, OP_LOGE(nodeName, "sharedExpertNum must be 1."), return ge::GRAPH_FAILED);
    OP_TILING_CHECK(moeExpertNum % (epRankSize - sharedExpertRankNum) != 0,
                    OP_LOGE(nodeName, "moeExpertNum must be divisible by (epRankSize - sharedExpertRankNum)."),
                    return ge::GRAPH_FAILED);

    groupEp = std::string(groupEpPtr);
    tilingData.disGmmDeqSwigluQuantGmmDeqComInfo.epRankSize = epRankSize;
    tilingData.disGmmDeqSwigluQuantGmmDeqComInfo.epRankId = epRankId;
    tilingData.disGmmDeqSwigluQuantGmmDeqComInfo.moeExpertNum = moeExpertNum;
    tilingData.disGmmDeqSwigluQuantGmmDeqComInfo.sharedExpertNum = sharedExpertNum;
    tilingData.disGmmDeqSwigluQuantGmmDeqComInfo.sharedExpertRankNum = sharedExpertRankNum;
    tilingData.disGmmDeqSwigluQuantGmmDeqComInfo.quantMode = static_cast<uint32_t>(*quantModePtr);
    tilingData.disGmmDeqSwigluQuantGmmDeqComInfo.globalBs = static_cast<uint32_t>(*globalBsPtr);
    tilingData.disGmmDeqSwigluQuantGmmDeqComInfo.moeExpertNumPerRank = moeExpertNumPerRank;
    return ge::GRAPH_SUCCESS;
}

static void SetHcommCfg(const gert::TilingContext *context, FusedDeepMoeTilingData *tiling, const std::string groupEp)
{
    const char *nodeName = context->GetNodeName();
    OP_LOGD(nodeName, "FusedDeepMoe groupEp = %s", groupEp.c_str());
    uint32_t opType = OP_TYPE_ALL_TO_ALL;
    std::string algConfigAllToAllStr = "AlltoAll=level0:fullmesh;level1:pairwise";
    std::string algConfigAllGatherStr = "AllGather=level0:ring";

    AscendC::Mc2CcTilingConfig mc2CcTilingConfig(groupEp, opType, algConfigAllToAllStr);
    mc2CcTilingConfig.GetTiling(tiling->mc2InitTiling);
    mc2CcTilingConfig.GetTiling(tiling->mc2CcTiling);
}

static ge::graphStatus SetWorkSpace(gert::TilingContext *context, const char *nodeName,
                                    FusedDeepMoeTilingData &tilingData)
{
    size_t *workSpaces = context->GetWorkspaceSizes(1);
    OP_TILING_CHECK(workSpaces == nullptr, OP_LOGE(nodeName, "workSpaces is nullptr."), return ge::GRAPH_FAILED);
    size_t maxTokenNum;
    uint32_t epRankSize = tilingData.disGmmDeqSwigluQuantGmmDeqComInfo.epRankSize;
    uint32_t epRankId = tilingData.disGmmDeqSwigluQuantGmmDeqComInfo.epRankId;
    uint32_t sharedExpertRankNum = tilingData.disGmmDeqSwigluQuantGmmDeqComInfo.sharedExpertRankNum;
    uint32_t batchSize = tilingData.disGmmDeqSwigluQuantGmmDeqComInfo.bs;
    uint32_t globalBs = tilingData.disGmmDeqSwigluQuantGmmDeqComInfo.globalBs;
    uint32_t maxBatchSize = globalBs / epRankSize;
    uint32_t topK = tilingData.disGmmDeqSwigluQuantGmmDeqComInfo.k;
    uint32_t moeExpertNumPerRank = tilingData.disGmmDeqSwigluQuantGmmDeqComInfo.moeExpertNumPerRank;
    uint32_t h = tilingData.disGmmDeqSwigluQuantGmmDeqComInfo.h;
    uint32_t aicNum = tilingData.disGmmDeqSwigluQuantGmmDeqComInfo.aicNum;
    uint64_t gmm2HLen = tilingData.disGmmDeqSwigluQuantGmmDeqComInfo.gmm1HLen / 2;
    if (epRankId < sharedExpertRankNum) {
        maxTokenNum = maxBatchSize * epRankSize / sharedExpertRankNum;
    } else {
        maxTokenNum = maxBatchSize * epRankSize * std::min(topK, moeExpertNumPerRank);
    }

    size_t x2TokenSize = CeilUp(maxTokenNum * gmm2HLen * sizeof(int8_t), GM_ALIGN_SIZE);
    size_t x2ScaleSize = CeilUp(maxTokenNum * sizeof(float), GM_ALIGN_SIZE);
    size_t CVSwapBufferSize =
        CeilUp(aicNum * L1_TILE_BYTE_SIZE * CUBE_WORKSPACE_STAGE * sizeof(int32_t), GM_ALIGN_SIZE);
    size_t swigluOutSize = CeilUp(maxTokenNum * gmm2HLen * sizeof(float), GM_ALIGN_SIZE);
    size_t groupListSize = CeilUp(moeExpertNumPerRank * sizeof(int64_t), GM_ALIGN_SIZE);
    size_t expandIdxSize = CeilUp(batchSize * topK * sizeof(int32_t), GM_ALIGN_SIZE);
    size_t epSendCountSize = CeilUp(epRankSize * moeExpertNumPerRank * sizeof(int32_t), GM_ALIGN_SIZE);
    size_t x1TokenSize = CeilUp(maxTokenNum * h * sizeof(int8_t), GM_ALIGN_SIZE);
    size_t x1ScaleSize = CeilUp(maxTokenNum * sizeof(float), GM_ALIGN_SIZE);
    size_t gmm2DepOutSize = CeilUp(maxTokenNum * h * TOKEN_DTYPE_BYTE_SIZE, GM_ALIGN_SIZE);
    size_t resveredSize = CeilUp(RESERVED_WORKSPACE_SIZE, GM_ALIGN_SIZE);
    size_t usrSize = x2TokenSize + x2ScaleSize + CVSwapBufferSize + swigluOutSize + groupListSize + expandIdxSize +
                     epSendCountSize + x1TokenSize + x1ScaleSize + gmm2DepOutSize + resveredSize;

    workSpaces[0] = SYSTEM_NEED_WORKSPACE + usrSize;
    return ge::GRAPH_SUCCESS;
}

static ge::graphStatus FusedDeepMoeTilingFuncImpl(gert::TilingContext *context)
{
    const char *nodeName = context->GetNodeName();
    FusedDeepMoeTilingData *tilingData = context->GetTilingData<FusedDeepMoeTilingData>();
    OP_TILING_CHECK(tilingData == nullptr, OP_LOGE(nodeName, "tilingData is nullptr."), return ge::GRAPH_FAILED);
    std::string groupEp = "";

    const gert::StorageShape *xStorageShape = context->GetInputShape(INPUT_X_INDEX);
    OP_TILING_CHECK(xStorageShape == nullptr, OP_LOGE(nodeName, "x shape is null."), return ge::GRAPH_FAILED);
    OP_TILING_CHECK(xStorageShape->GetStorageShape().GetDimNum() != TWO_DIMS,
                    OP_LOGE(nodeName, "x shape dims must be 2, but current dim num is %lu.",
                            xStorageShape->GetStorageShape().GetDimNum()),
                    return ge::GRAPH_FAILED);
    const int64_t batchSize = xStorageShape->GetStorageShape().GetDim(0);
    tilingData->disGmmDeqSwigluQuantGmmDeqComInfo.bs = batchSize;
    const int64_t hiddenSize = xStorageShape->GetStorageShape().GetDim(1);
    tilingData->disGmmDeqSwigluQuantGmmDeqComInfo.h = hiddenSize;

    const gert::StorageShape *expertIdsStorageShape = context->GetInputShape(INPUT_EXPERT_IDS_INDEX);
    OP_TILING_CHECK(expertIdsStorageShape == nullptr, OP_LOGE(nodeName, "expertIds shape is null."),
                    return ge::GRAPH_FAILED);
    OP_TILING_CHECK(expertIdsStorageShape->GetStorageShape().GetDimNum() != TWO_DIMS,
                    OP_LOGE(nodeName, "expertIds shape dims must be 2, but current dim num is %lu.",
                            expertIdsStorageShape->GetStorageShape().GetDimNum()),
                    return ge::GRAPH_FAILED);
    OP_TILING_CHECK(expertIdsStorageShape->GetStorageShape().GetDim(0) != batchSize,
                    OP_LOGE(nodeName, "expertIds dim 0 must be batchSize(%lu), but get %lu.",
                            batchSize, expertIdsStorageShape->GetStorageShape().GetDim(0)),
                    return ge::GRAPH_FAILED);
    const int64_t topK = expertIdsStorageShape->GetStorageShape().GetDim(1);
    tilingData->disGmmDeqSwigluQuantGmmDeqComInfo.k = topK;
    OP_TILING_CHECK(GetAttrAndSetTilingData(context, nodeName, *tilingData, groupEp) != ge::GRAPH_SUCCESS,
                    OP_LOGE(nodeName, "Get attr and set tiling data failed."), return ge::GRAPH_FAILED);
    OP_TILING_CHECK(CheckWeightTensorList(context, *tilingData) != ge::GRAPH_SUCCESS,
           OP_LOGE(nodeName, "CheckWeightTensorList failed."), return ge::GRAPH_FAILED);
    auto ascendcPlatform = platform_ascendc::PlatformAscendC(context->GetPlatformInfo());
    uint32_t aicNum = ascendcPlatform.GetCoreNumAic();
    uint32_t aivNum = ascendcPlatform.GetCoreNumAiv();
    tilingData->disGmmDeqSwigluQuantGmmDeqComInfo.aicNum = aicNum;
    tilingData->disGmmDeqSwigluQuantGmmDeqComInfo.aivNum = aivNum;
    OP_TILING_CHECK(CheckData(nodeName, *tilingData) != ge::GRAPH_SUCCESS, OP_LOGE(nodeName, "CheckData failed."),
                    return ge::GRAPH_FAILED);
    OP_TILING_CHECK(SetWorkSpace(context, nodeName, *tilingData) != ge::GRAPH_SUCCESS,
                    OP_LOGE(nodeName, "Tiling set workspace failed."), return ge::GRAPH_FAILED);
    SetHcommCfg(context, tilingData, groupEp);
    uint64_t tilingKey = 0;
    if (tilingData->disGmmDeqSwigluQuantGmmDeqComInfo.moeExpertNumPerRank != 1) {
        tilingKey |= EXEC_FLAG_DEEP_FUSE;
    }
    if (tilingData->disGmmDeqSwigluQuantGmmDeqComInfo.isTensorList) {
        tilingKey |= EXEC_FLAG_TENSOR_LIST;
    }
    context->SetTilingKey(tilingKey);
    context->SetBlockDim(aicNum);
    return ge::GRAPH_SUCCESS;
}

static ge::graphStatus FusedDeepMoeTilingFunc(gert::TilingContext *context)
{
    ge::graphStatus ret = FusedDeepMoeTilingFuncImpl(context);
    return ret;
}

struct FusedDeepMoeCompileInfo {};
ge::graphStatus TilingParseForFusedDeepMoe(gert::TilingParseContext *context)
{
    (void)context;
    return ge::GRAPH_SUCCESS;
}

IMPL_OP_OPTILING(FusedDeepMoe)
    .Tiling(FusedDeepMoeTilingFunc)
    .TilingParse<FusedDeepMoeCompileInfo>(TilingParseForFusedDeepMoe);
}  // namespace optiling
