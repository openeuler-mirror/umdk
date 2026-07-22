/**
 * Copyright (c) 2025 Huawei Technologies Co., Ltd.
 * This program is free software, you can redistribute it and/or modify it under the terms and conditions of
 * CANN Open Software License Agreement Version 2.0 (the "License").
 * Please refer to the License for details. You may not use this file except in compliance with the License.
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR IMPLIED,
 * INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY, OR FITNESS FOR A PARTICULAR PURPOSE.
 * See LICENSE in the root of the software repository for the full text of the License.
 */

/*!
 * \file swiglu_clip_quant_tiling.cpp
 * \brief
 */

#include <sstream>
#include "swiglu_clip_quant_tiling.h"

using namespace ge;
namespace optiling {
constexpr int64_t ATTR_ACTIVATE_LEFT_INDEX = 0;
constexpr int64_t ATTR_QUANT_MODE_INDEX = 1;
constexpr int64_t X_INDEX = 0;
constexpr int64_t INPUT_GROUP_INDEX = 1;
constexpr int64_t INPUT_GROUP_ALPHA = 2;
constexpr int64_t Y_INDEX = 0;
constexpr int64_t CLAMP_MODE_INDEX = 2;

constexpr int64_t BLOCK_SIZE = 32;
constexpr int64_t BLOCK_ELEM = BLOCK_SIZE / static_cast<int64_t>(sizeof(float));
constexpr uint64_t WORKSPACE_SIZE = 32;
// define tiling key offset
constexpr uint64_t TILING_KEY_HAS_GROUP = 100000000;
constexpr uint64_t TILING_KEY_NO_GROUP = 200000000;
// define cut by group
constexpr uint64_t TILING_KEY_CUT_GROUP = 10000000;
constexpr int64_t CUT_GROUP_LARGE_THAN = 64;
constexpr int64_t EACH_GROUP_TOKEN_LESS_THAN = 16;

// quant_scale tiling offset
constexpr uint64_t TILING_KEY_QS_DTYPE = 100;
// bias tiling offset
constexpr uint64_t TILING_KEY_BIAS_DTYPE = 1000;

constexpr int64_t UB_RESERVE = 1024;
constexpr int64_t SWI_FACTOR = 2;
constexpr int64_t QUANT_MODE_DYNAMIC = 1;
constexpr int64_t PERFORMANCE_H_2048 = 2048;
constexpr int64_t PERFORMANCE_H_4096 = 4096;
constexpr int64_t PERFORMANCE_CORE_NUM = 36;
constexpr int64_t PERFORMANCE_UB_FACTOR = static_cast<int64_t>(4096) * 4;

constexpr int DIM_SIZE_2 = 2;

static const std::set<ge::DataType> SUPPORT_DTYPE = {ge::DT_BF16};
static const std::map<std::string, int64_t> SUPPORT_QUANT_MODE = {{"dynamic", 1}};

bool SwigluClipQuantAllTiling::CheckOptionalShapeExisting(const gert::StorageShape* storageShape)
{
    if (storageShape == nullptr) {
        return false;
    }
    int64_t shapeSize = storageShape->GetOriginShape().GetShapeSize();
    if (shapeSize <= 0) {
        return false;
    }
    return true;
}

ge::graphStatus SwigluClipQuantAllTiling::GetPlatformInfo()
{
    auto platformInfo = context_->GetPlatformInfo();
    if (platformInfo == nullptr) {
        auto compileInfoPtr = context_->GetCompileInfo<SwigluClipQuantCompileInfo>();
        OPS_ERR_IF(compileInfoPtr == nullptr, OPS_LOG_E(context_, "compile info is null"),
                      return ge::GRAPH_FAILED);
        coreNum_ = compileInfoPtr->coreNum;
        ubSize_ = compileInfoPtr->ubSize;
    } else {
        auto ascendcPlatform = platform_ascendc::PlatformAscendC(platformInfo);
        coreNum_ = ascendcPlatform.GetCoreNumAiv();
        uint64_t ubSizePlatForm;
        ascendcPlatform.GetCoreMemSize(platform_ascendc::CoreMemType::UB, ubSizePlatForm);
        ubSize_ = ubSizePlatForm;
        socVersion = ascendcPlatform.GetSocVersion();
    }

    maxPreCore_ = static_cast<int64_t>(coreNum_);
    return ge::GRAPH_SUCCESS;
}

ge::graphStatus SwigluClipQuantAllTiling::CheckXAndGroupIndexDtype()
{
    auto xPtr = context_->GetInputDesc(X_INDEX);
    OPS_LOG_E_IF_NULL(context_, xPtr, return ge::GRAPH_FAILED);
    auto xDtype = xPtr->GetDataType();
    OPS_ERR_IF((SUPPORT_DTYPE.find(xDtype) == SUPPORT_DTYPE.end()),
                    OPS_LOG_E(context_->GetNodeName(), "x dtype only support bfloat16, please check."),
                    return ge::GRAPH_FAILED);
    tilingData_.set_groupIndexDtype(-1);
    if (hasGroupIndex_) {
        auto groupIndexPtr = context_->GetOptionalInputDesc(INPUT_GROUP_INDEX);
        OPS_LOG_E_IF_NULL(context_, groupIndexPtr, return ge::GRAPH_FAILED);
        auto groupIndexDtype = groupIndexPtr->GetDataType();
        bool dtypeInValid = groupIndexDtype != ge::DT_INT64;
        OPS_ERR_IF(
            dtypeInValid,
            OPS_LOG_E(context_->GetNodeName(), "group_index dtype only support int64, please check!"),
            return ge::GRAPH_FAILED);
        tilingData_.set_groupIndexDtype(1);
    }
    return ge::GRAPH_SUCCESS;
}

ge::graphStatus SwigluClipQuantAllTiling::GetAttr()
{
    auto* attrs = context_->GetAttrs();
    OPS_LOG_E_IF_NULL(context_, attrs, return ge::GRAPH_FAILED);

    auto* attrActivateLeft = attrs->GetAttrPointer<bool>(ATTR_ACTIVATE_LEFT_INDEX);
    actRight_ = (attrActivateLeft == nullptr || *attrActivateLeft == false) ? 1 : 0;
    std::string quantMode = attrs->GetAttrPointer<char>(ATTR_QUANT_MODE_INDEX);
    auto it = SUPPORT_QUANT_MODE.find(quantMode);
    OPS_ERR_IF(it == SUPPORT_QUANT_MODE.end(),
                    OPS_LOG_E(context_->GetNodeName(),
                                                    "attr quant_mode only support dynamic(1) currently, please check."),
                    return ge::GRAPH_FAILED);
    quantMode_ = it->second;

    auto* clampMode = attrs->GetAttrPointer<int>(CLAMP_MODE_INDEX);
    clampMode_ = clampMode == nullptr ? 0 : *clampMode;

    OPS_ERR_IF(clampMode_ != 1,
                    OPS_LOG_E(context_->GetNodeName(),
                    "clampMode only support 1, value is %ld, please check!", clampMode_),
                    return ge::GRAPH_FAILED);

    hasBias_ = false;
    tilingData_.set_biasDtype(0);
    tilingData_.set_activationScaleIsEmpty(1);
    tilingData_.set_quantIsOne(0);
    tilingData_.set_quantScaleDtype(0);
    tilingData_.set_needSmoothScale(0);

    return ge::GRAPH_SUCCESS;
}

ge::graphStatus SwigluClipQuantAllTiling::GetShapeAttrsInfoInner()
{
    // get 2H from x, get H from y, check if 2H can be divided by 64
    auto shapeX = context_->GetInputShape(0);
    OPS_LOG_E_IF_NULL(context_, shapeX, return ge::GRAPH_FAILED);
    const gert::Shape& inputShapeX = shapeX->GetStorageShape();
    int64_t inputShapeXTotalNum = inputShapeX.GetShapeSize();
    int64_t inputShapeXRank = inputShapeX.GetDimNum();
    inDimy_ = inputShapeX.GetDim(inputShapeXRank - 1);
    inDimx_ = inputShapeXTotalNum / inDimy_;
    auto shapeY = context_->GetOutputShape(0);
    OPS_LOG_E_IF_NULL(context_, shapeY, return ge::GRAPH_FAILED);
    const gert::Shape& outputShapeY = shapeY->GetStorageShape();
    outDimy_ = outputShapeY.GetDim(inputShapeXRank - 1);
    OPS_ERR_IF(inDimy_ % (BLOCK_SIZE * SWI_FACTOR) != 0,
                    OPS_LOG_E(context_->GetNodeName(),
                             "only support lastdimSize being divided by 64, but is %ld", inDimy_),
                    return ge::GRAPH_FAILED);

    // set the relevant param of group, hasGroupIndex_, groupNum_ and speGroupType_
    auto shapeGroupIndex = context_->GetOptionalInputShape(INPUT_GROUP_INDEX);
    hasGroupIndex_ = shapeGroupIndex != nullptr;
    auto shapeGroupAlpha = context_->GetOptionalInputShape(INPUT_GROUP_ALPHA);
    hasGroupAlpha_ = shapeGroupAlpha != nullptr;
    groupNum_ = 0;
    speGroupType_ = false;
    OPS_ERR_IF(!hasGroupIndex_ || !hasGroupAlpha_,
                    OPS_LOG_E(context_->GetNodeName(),
                                                    "group_index or group_alpha must be not None!"),
                    return ge::GRAPH_FAILED);
    if (hasGroupIndex_ && hasGroupAlpha_) {
        const gert::Shape& inputShapeGroupIndex = shapeGroupIndex->GetStorageShape();
        groupNum_ = inputShapeGroupIndex.GetDimNum() == 0 ? 1 : inputShapeGroupIndex.GetDim(0);
        speGroupType_ = inputShapeGroupIndex.GetDimNum() == DIM_SIZE_2;
        int64_t groupIndexShapeXRank = inputShapeGroupIndex.GetDimNum();

        const gert::Shape& inputShapeGroupAlpha = shapeGroupAlpha->GetStorageShape();
        int64_t groupAlphaShapeXRank = inputShapeGroupAlpha.GetDimNum();
        OPS_ERR_IF(groupIndexShapeXRank != 1 || groupAlphaShapeXRank != 1,
                      OPS_LOG_E(context_->GetNodeName(),
                                "The dimension of group_index or group_alpha must be 1"),
                      return ge::GRAPH_FAILED);

        auto groupAlphaPtr = context_->GetOptionalInputDesc(INPUT_GROUP_ALPHA);
        OPS_LOG_E_IF_NULL(context_, groupAlphaPtr, return ge::GRAPH_FAILED);
        auto groupAlphaDtype = groupAlphaPtr->GetDataType();
        bool dtypeInValid = groupAlphaDtype != ge::DT_FLOAT;
        OPS_ERR_IF(
            dtypeInValid,
            OPS_LOG_E(context_->GetNodeName(), "group_alpha dtype only support float, please check!"),
            return ge::GRAPH_FAILED);
        auto groupAlphaNum = inputShapeGroupAlpha.GetDim(0);
        OPS_ERR_IF(groupNum_ != groupAlphaNum,
                      OPS_LOG_E(context_->GetNodeName(),
                                "The first dimension of group_index:%ld needs tobe consistent with group_alpha:%ld",
                                groupNum_, groupAlphaNum),
                      return ge::GRAPH_FAILED);
    } else {
        return ge::GRAPH_FAILED;
    }

    OPS_ERR_IF(CheckXAndGroupIndexDtype() != ge::GRAPH_SUCCESS,
                  OPS_LOG_E(context_->GetNodeName(), "dtype check failed."),
                  return ge::GRAPH_FAILED);

    OPS_ERR_IF(GetAttr() != ge::GRAPH_SUCCESS,
                  OPS_LOG_E(context_->GetNodeName(), "get attr failed."),
                  return ge::GRAPH_FAILED);

    return ge::GRAPH_SUCCESS;
}

void SwigluClipQuantAllTiling::CountTilingKey()
{
    tilingKey_ = hasGroupIndex_ ? TILING_KEY_HAS_GROUP : TILING_KEY_NO_GROUP;
    // add quant scale offet to tilingKey_
    tilingKey_ += TILING_KEY_QS_DTYPE * tilingData_.get_quantScaleDtype();
    // add bias offset to tilingKey_
    tilingKey_ += TILING_KEY_BIAS_DTYPE * tilingData_.get_biasDtype();
    // tiling based on groupnum, pre cut num by coreNum_ and total tokens
    if (speGroupType_ && (groupNum_ >= CUT_GROUP_LARGE_THAN && inDimx_ / groupNum_ <= EACH_GROUP_TOKEN_LESS_THAN)) {
        tilingKey_ += TILING_KEY_CUT_GROUP;
        maxPreCore_ = std::min(static_cast<int64_t>(coreNum_), static_cast<int64_t>(inDimx_));
    }
}

ge::graphStatus SwigluClipQuantAllTiling::CountMaxDim(int64_t& ubFactorDimx)
{
    /*
    x used mem: [UbFactorDimx, outDimy_ * 2] dtype: float
    activation_scale used mem: [UbFactorDimx, 8] dtype: float
    weight_scale used mem: [1, outDimy_ * 2] dtype: float
    quant_scale used mem: [1, outDimy_] dtype: float
    y used mem: [UbFactorDimx, outDimy_] dtype: int8_t
    scale used mem: [UbFactorDimx,] dtype: float
    tmp used mem: [UbFactorDimx, outDimy_ * 2] dtype: float
    x, activation_scale enable db
    ub reserve 1024B

    optional buffer：
    bias used mem: [1, outDimy_ * 2] dtype: float

    clamp tmp buffer: [UbFactorDimx, outDimy_] dtype: uint8

    gather offset buffer: [UbFactorDimx, outDimy_] dtype: uint32

    */
    int64_t db = 2;
    int64_t maxOutDimy = 0;
    int64_t biasBufferY = !hasBias_ ? 0 : static_cast<int64_t>(SWI_FACTOR * sizeof(float));
    int64_t biasBufferX = !hasBias_ ? 0 : outDimy_ * SWI_FACTOR * static_cast<int64_t>(sizeof(float));

    int64_t sWeiGluBufferY = clampMode_ == 0 ? 0 : static_cast<int64_t>(sizeof(int8_t) + sizeof(int32_t));
    int64_t sWeiGluBufferX = clampMode_ == 0
        ? 0
        : outDimy_ * static_cast<int64_t>(sizeof(int8_t)) + outDimy_ * static_cast<int64_t>(sizeof(int32_t));

    int64_t quantOffsetSpace = quantMode_ == QUANT_MODE_DYNAMIC ? 0 : static_cast<int64_t>(sizeof(float));

    // UbFactorDimx is 1,compute maxOutDimy
    int64_t numerator =
            static_cast<int64_t>(ubSize_) - UB_RESERVE - BLOCK_SIZE -
            db * BLOCK_SIZE - static_cast<int64_t>(sizeof(float));
    int64_t denominator =
        5 * static_cast<int64_t>(sizeof(float)) +
        db * SWI_FACTOR * static_cast<int64_t>(sizeof(float)) +
        static_cast<int64_t>(sizeof(int8_t)) +
        biasBufferY +
        sWeiGluBufferY +
        quantOffsetSpace;

    maxOutDimy = static_cast<int64_t>(numerator / denominator);
    maxOutDimy = maxOutDimy / BLOCK_SIZE * BLOCK_SIZE;
    int64_t maxInDimy = static_cast<int64_t>(maxOutDimy * SWI_FACTOR);
    OPS_LOG_I(context_->GetNodeName(), "Get maxInDimy[%ld]", maxInDimy);
    OPS_ERR_IF(inDimy_ > maxInDimy,
                    OPS_LOG_E(context_->GetNodeName(),
                              "only support lastdimSize <= %ld, but is %ld", maxInDimy, inDimy_),
                    return ge::GRAPH_FAILED);

    // compute ubFactorDimx
    quantOffsetSpace = quantMode_ == QUANT_MODE_DYNAMIC ? 0 : outDimy_ * sizeof(float);
    numerator =
        static_cast<int64_t>(ubSize_) -
        UB_RESERVE - outDimy_ * static_cast<int64_t>(sizeof(float)) -
        BLOCK_SIZE - SWI_FACTOR * outDimy_ * static_cast<int64_t>(sizeof(float)) -
        biasBufferX - quantOffsetSpace;

    denominator =
        db * (outDimy_ * SWI_FACTOR + BLOCK_ELEM) * static_cast<int64_t>(sizeof(float)) +
        outDimy_ * static_cast<int64_t>(sizeof(int8_t)) +
        static_cast<int64_t>(sizeof(float)) +
        outDimy_ * SWI_FACTOR * static_cast<int64_t>(sizeof(float)) +
        sWeiGluBufferX;
    ubFactorDimx  = static_cast<int64_t>(numerator / denominator);
    ubFactorDimx = std::min(ubFactorDimx, inDimx_);
    OPS_LOG_I(context_->GetNodeName(), "Get ubFactorDimx[%ld]", ubFactorDimx);

    // special ub cut for 2048 4096
    if (clampMode_ == 0 && !hasBias_) {
        ubFactorDimx =
        (inDimy_ == PERFORMANCE_H_2048 || inDimy_ == PERFORMANCE_H_4096)
        ? PERFORMANCE_UB_FACTOR / inDimy_
        : ubFactorDimx;
    }

    return ge::GRAPH_SUCCESS;
}

ge::graphStatus SwigluClipQuantAllTiling::DoOpTiling()
{
    if (GetPlatformInfo() == ge::GRAPH_FAILED) {
        return ge::GRAPH_FAILED;
    }

    if (GetShapeAttrsInfoInner() == ge::GRAPH_FAILED) {
        return ge::GRAPH_FAILED;
    }

    auto inputShapeX = context_->GetInputShape(0);
    OPS_LOG_E_IF_NULL(context_, inputShapeX, return ge::GRAPH_FAILED);

    int64_t ubFactorDimx = 0;
    OPS_ERR_IF(CountMaxDim(ubFactorDimx) != ge::GRAPH_SUCCESS,
                  OPS_LOG_E(context_->GetNodeName(), "Count MaxDim failed."),
                  return ge::GRAPH_FAILED);

    maxPreCore_ = (inDimx_ + ubFactorDimx - 1) / ubFactorDimx;
    maxPreCore_ = std::min(maxPreCore_, static_cast<int64_t>(PERFORMANCE_CORE_NUM));
    maxPreCore_ = std::min(maxPreCore_, static_cast<int64_t>(coreNum_));

    CountTilingKey();

    tilingData_.set_inDimx(inDimx_);
    tilingData_.set_inDimy(inDimy_);
    tilingData_.set_outDimy(outDimy_);
    tilingData_.set_UbFactorDimx(ubFactorDimx);
    tilingData_.set_UbFactorDimy(outDimy_);
    tilingData_.set_usedCoreNum(maxPreCore_);
    tilingData_.set_maxCoreNum(maxPreCore_);
    tilingData_.set_inGroupNum(groupNum_);
    tilingData_.set_quantMode(quantMode_);
    tilingData_.set_actRight(actRight_);
    tilingData_.set_speGroupType(static_cast<int64_t>(speGroupType_));
    tilingData_.set_hasBias(hasBias_);
    tilingData_.set_clampMode(clampMode_);
    tilingData_.set_hasGroupAlpha(hasGroupAlpha_);

    if (GetWorkspaceSize() == ge::GRAPH_FAILED) {
        return ge::GRAPH_FAILED;
    }

    if (PostTiling() == ge::GRAPH_FAILED) {
        return ge::GRAPH_FAILED;
    }

    context_->SetTilingKey(GetTilingKey());
    DumpTilingInfo();

    return ge::GRAPH_SUCCESS;
}

void SwigluClipQuantAllTiling::DumpTilingInfo()
{
    std::ostringstream info;
    info << "inDimx_: " << tilingData_.get_inDimx();
    info << ", inDimy_: " << tilingData_.get_inDimy();
    info << ", outDimy: " << tilingData_.get_outDimy();
    info << ", UbFactorDimx: " << tilingData_.get_UbFactorDimx();
    info << ", UbFactorDimy: " << tilingData_.get_UbFactorDimy();
    info << ", usedCoreNum: " << tilingData_.get_usedCoreNum();
    info << ", maxCoreNum: " << tilingData_.get_maxCoreNum();
    info << ", inGroupNum: " << tilingData_.get_inGroupNum();
    info << ", quantMode: " << tilingData_.get_quantMode();
    info << ", actRight: " << tilingData_.get_actRight();
    info << ", tilingKey: " << tilingKey_;
    info << ", hasBias: " << hasBias_;
    info << ", clampMode: " << tilingData_.get_clampMode();

    OPS_LOG_I(context_->GetNodeName(), "%s", info.str().c_str());
}

uint64_t SwigluClipQuantAllTiling::GetTilingKey() const
{
    return tilingKey_;
}

ge::graphStatus SwigluClipQuantAllTiling::GetWorkspaceSize()
{
    workspaceSize_ = WORKSPACE_SIZE;
    return ge::GRAPH_SUCCESS;
}

ge::graphStatus SwigluClipQuantAllTiling::PostTiling()
{
    context_->SetTilingKey(GetTilingKey());
    context_->SetBlockDim(maxPreCore_);
    size_t* workspaces = context_->GetWorkspaceSizes(1);
    workspaces[0] = workspaceSize_;
    tilingData_.SaveToBuffer(context_->GetRawTilingData()->GetData(), context_->GetRawTilingData()->GetCapacity());
    context_->GetRawTilingData()->SetDataSize(tilingData_.GetDataSize());
    return ge::GRAPH_SUCCESS;
}

ge::graphStatus TilingPrepareForSwigluClipQuant(gert::TilingParseContext *context)
{
    (void)context;
    return ge::GRAPH_SUCCESS;
}

ge::graphStatus TilingForSwigluClipQuant(gert::TilingContext *context)
{
    OPS_ERR_IF(context == nullptr, OPS_REPORT_VECTOR_INNER_ERR("SwigluClipQuant", "Tiling context is null"),
               return ge::GRAPH_FAILED);
    SwigluClipQuantAllTiling SwigluClipQuantInfoParser(context);
    return SwigluClipQuantInfoParser.DoOpTiling();
}

IMPL_OP_OPTILING(SwigluClipQuant)
    .Tiling(TilingForSwigluClipQuant)
    .TilingParse<SwigluClipQuantCompileInfo>(TilingPrepareForSwigluClipQuant);

}  // namespace optiling
