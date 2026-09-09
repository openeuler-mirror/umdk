/**
 * Copyright (c) 2026 Huawei Technologies Co., Ltd.
 * This program is free software, you can redistribute it and/or modify it under the terms and conditions of
 * CANN Open Software License Agreement Version 2.0 (the "License").
 * See LICENSE in the root of the software repository for the full text of the License.
 */

#include <string>
#include <register/op_impl_registry.h>
#include "err/ops_err.h"

namespace ops {
namespace {
constexpr size_t QUERY = 0;
constexpr size_t SELECTION_KEY = 1;
constexpr size_t SELECTION_BLOCK_TABLE = 6;
constexpr size_t SELECTION_BLOCK_STATUS = 10;
constexpr size_t ATTENTION_OUT = 0;
constexpr size_t SELECTION_CACHE_OUT = 1;
constexpr size_t SELECTION_BLOCK_TABLE_OUT = 2;
constexpr size_t SELECTION_BLOCK_STATUS_OUT = 3;
constexpr size_t SELECTION_ACTUAL_SEQ_OUT = 4;
constexpr uint32_t LAYOUT_QUERY_ATTR = 4;
constexpr uint32_t ROPE_HEAD_DIM_ATTR = 12;
} // namespace

ge::graphStatus InferShapeGatherSelectionSparseFlashAttention(gert::InferShapeContext *context)
{
    OP_CHECK(context == nullptr,
                OPS_LOG_E("GatherSelectionSparseFlashAttention", "InferShapeContext is nullptr"),
                return ge::GRAPH_FAILED);
    const gert::Shape *query = context->GetInputShape(QUERY);
    const gert::Shape *selectionKey = context->GetInputShape(SELECTION_KEY);
    const gert::Shape *selectionBlockTable = context->GetInputShape(SELECTION_BLOCK_TABLE);
    const gert::Shape *selectionBlockStatus = context->GetInputShape(SELECTION_BLOCK_STATUS);
    OPS_LOG_E_IF_NULL(context, query, return ge::GRAPH_FAILED);
    OPS_LOG_E_IF_NULL(context, selectionKey, return ge::GRAPH_FAILED);
    OPS_LOG_E_IF_NULL(context, selectionBlockTable, return ge::GRAPH_FAILED);
    OPS_LOG_E_IF_NULL(context, selectionBlockStatus, return ge::GRAPH_FAILED);

    gert::Shape *attentionOut = context->GetOutputShape(ATTENTION_OUT);
    gert::Shape *selectionCacheOut = context->GetOutputShape(SELECTION_CACHE_OUT);
    gert::Shape *selectionBlockTableOut = context->GetOutputShape(SELECTION_BLOCK_TABLE_OUT);
    gert::Shape *selectionBlockStatusOut = context->GetOutputShape(SELECTION_BLOCK_STATUS_OUT);
    gert::Shape *selectionActualSeqOut = context->GetOutputShape(SELECTION_ACTUAL_SEQ_OUT);
    OPS_LOG_E_IF_NULL(context, attentionOut, return ge::GRAPH_FAILED);
    OPS_LOG_E_IF_NULL(context, selectionCacheOut, return ge::GRAPH_FAILED);
    OPS_LOG_E_IF_NULL(context, selectionBlockTableOut, return ge::GRAPH_FAILED);
    OPS_LOG_E_IF_NULL(context, selectionBlockStatusOut, return ge::GRAPH_FAILED);
    OPS_LOG_E_IF_NULL(context, selectionActualSeqOut, return ge::GRAPH_FAILED);

    auto attrs = context->GetAttrs();
    OPS_LOG_E_IF_NULL(context, attrs, return ge::GRAPH_FAILED);
    const char *layout = attrs->GetAttrPointer<char>(LAYOUT_QUERY_ATTR);
    const int64_t *ropeHeadDim = attrs->GetAttrPointer<int64_t>(ROPE_HEAD_DIM_ATTR);
    OPS_LOG_E_IF_NULL(context, layout, return ge::GRAPH_FAILED);
    OPS_LOG_E_IF_NULL(context, ropeHeadDim, return ge::GRAPH_FAILED);
    OP_CHECK(std::string(layout) != "TND",
                OPS_LOG_E("GatherSelectionSparseFlashAttention", "layout_query must be TND"),
                return ge::GRAPH_FAILED);
    OP_CHECK(*ropeHeadDim < 0,
                OPS_LOG_E("GatherSelectionSparseFlashAttention", "rope_head_dim must be non-negative"),
                return ge::GRAPH_FAILED);

    *attentionOut = *query;
    const size_t dimNum = query->GetDimNum();
    constexpr size_t dAxis = 2;
    OP_CHECK(dimNum <= dAxis,
                OPS_LOG_E("GatherSelectionSparseFlashAttention", "query rank is incompatible with layout"),
                return ge::GRAPH_FAILED);
    if (query->GetDim(dAxis) != -1) {
        OP_CHECK(*ropeHeadDim > query->GetDim(dAxis),
                    OPS_LOG_E("GatherSelectionSparseFlashAttention", "rope_head_dim must not exceed query D"),
                    return ge::GRAPH_FAILED);
        attentionOut->SetDim(dAxis, query->GetDim(dAxis) - *ropeHeadDim);
    }

    *selectionCacheOut = *selectionKey;
    *selectionBlockTableOut = *selectionBlockTable;
    *selectionBlockStatusOut = *selectionBlockStatus;
    *selectionActualSeqOut = *selectionBlockTable;
    OP_CHECK(selectionActualSeqOut->GetDimNum() == 0,
                OPS_LOG_E("GatherSelectionSparseFlashAttention", "selection block table must have rank >= 1"),
                return ge::GRAPH_FAILED);
    selectionActualSeqOut->SetDimNum(selectionActualSeqOut->GetDimNum() - 1);
    return ge::GRAPH_SUCCESS;
}

ge::graphStatus InferDataTypeGatherSelectionSparseFlashAttention(gert::InferDataTypeContext *context)
{
    OP_CHECK(context == nullptr,
                OPS_LOG_E("GatherSelectionSparseFlashAttention", "InferDataTypeContext is nullptr"),
                return ge::GRAPH_FAILED);
    context->SetOutputDataType(ATTENTION_OUT, context->GetInputDataType(QUERY));
    context->SetOutputDataType(SELECTION_CACHE_OUT, context->GetInputDataType(SELECTION_KEY));
    context->SetOutputDataType(SELECTION_BLOCK_TABLE_OUT, context->GetInputDataType(SELECTION_BLOCK_TABLE));
    context->SetOutputDataType(SELECTION_BLOCK_STATUS_OUT, context->GetInputDataType(SELECTION_BLOCK_STATUS));
    context->SetOutputDataType(SELECTION_ACTUAL_SEQ_OUT, ge::DT_INT32);
    return ge::GRAPH_SUCCESS;
}

IMPL_OP_INFERSHAPE(GatherSelectionSparseFlashAttention)
    .InferShape(InferShapeGatherSelectionSparseFlashAttention)
    .InferDataType(InferDataTypeGatherSelectionSparseFlashAttention);
} // namespace ops
