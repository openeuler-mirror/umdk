/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2026-2026. All rights reserved.
 * Description: add swiglu clip quant kernel
 * Create: 2026-07-25
 * Note:
 * History: 2026-07-25 create file
 */

/*!
 * \file swiglu_clip_quant_proto.cpp
 * \brief
 */
#include <graph/utils/type_utils.h>
#include <register/op_impl_registry.h>

#define OPS_UTILS_LOG_SUB_MOD_NAME "SWIGLU_CLIP_QUANT"
#define OPS_UTILS_LOG_PACKAGE_TYPE "[CAM]"

#include "ops_error.h"

using namespace ge;
namespace ops {
constexpr size_t INPUT_IDX_X = 0;
constexpr size_t OUTPUT_IDX_Y = 0;
constexpr size_t OUTPUT_IDX_SCALE = 1;
constexpr int64_t NUM_TWO = 2;
constexpr int64_t ACTIVATE_DIM = -1;

graphStatus InferShape4SwigluClipQuant(gert::InferShapeContext* context)
{
    OPS_LOG_D(context->GetNodeName(), "Begin to do InferShape4SwigluClipQuant.");

    const gert::Shape* xShape = context->GetInputShape(INPUT_IDX_X);
    OPS_LOG_E_IF_NULL(context, xShape, ge::GRAPH_FAILED);
    gert::Shape* yShape = context->GetOutputShape(OUTPUT_IDX_Y);
    OPS_LOG_E_IF_NULL(context, yShape, ge::GRAPH_FAILED);
    gert::Shape* scaleShape = context->GetOutputShape(OUTPUT_IDX_SCALE);
    OPS_LOG_E_IF_NULL(context, scaleShape, ge::GRAPH_FAILED);

    *yShape = *xShape;
    *scaleShape = *xShape;

    auto attrsPtr = context->GetAttrs();
    OPS_LOG_E_IF_NULL(context, attrsPtr, ge::GRAPH_FAILED);
    const int32_t activateDimNum = ACTIVATE_DIM;

    // 将切分轴转换为正数
    int64_t xShapeRank = static_cast<int64_t>(xShape->GetDimNum());
    size_t selectDim = (activateDimNum >= 0)
        ? static_cast<size_t>(activateDimNum)
        : static_cast<size_t>(activateDimNum + xShapeRank);

    // 设置Y的shape
    yShape->SetDim(selectDim, xShape->GetDim(selectDim) / NUM_TWO);
    // 设置Scale的shape
    scaleShape->SetDimNum(xShapeRank - 1);
    scaleShape->SetDim(selectDim, xShape->GetDim(selectDim) / NUM_TWO);

    OPS_LOG_D(context->GetNodeName(), "End to do InferShape4SwigluClipQuant");
    return ge::GRAPH_SUCCESS;
}

graphStatus InferDtype4SwigluClipQuant(gert::InferDataTypeContext* context)
{
    OPS_LOG_D(context->GetNodeName(), "InferDtype4SwigluClipQuant enter");

    context->SetOutputDataType(OUTPUT_IDX_Y, DT_INT8);
    context->SetOutputDataType(OUTPUT_IDX_SCALE, DT_FLOAT);
    OPS_LOG_D(context->GetNodeName(), "InferDtype4SwigluClipQuant end");

    return GRAPH_SUCCESS;
}

IMPL_OP_INFERSHAPE(SwigluClipQuant)
    .InferShape(InferShape4SwigluClipQuant)
    .InferDataType(InferDtype4SwigluClipQuant);
}  // namespace ops
