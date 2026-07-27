/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2026-2026. All rights reserved.
 * Description: GatherSelectionKvCacheCustom infer shape/dtype implementation
 * Create: 2026-07-25
 * Note:
 * History: 2026-07-25 create GatherSelectionKvCacheCustom infer shape/dtype implementation
 */

#include <register/op_impl_registry.h>

#define OPS_UTILS_LOG_SUB_MOD_NAME "GATHER_SELECTION_KV_CACHE_CUSTOM"
#define OPS_UTILS_LOG_PACKAGE_TYPE "[CAM]"
#include "ops_error.h"

namespace ops {
namespace {
constexpr int32_t SEL_K_ROPE_INPUT = 0;
constexpr int32_t SEL_KV_CACHE_INPUT = 1;
constexpr int32_t SEL_BLOCK_TABLE_INPUT = 2;
constexpr int32_t SEL_BLOCK_STATUS_INPUT = 3;
constexpr int32_t SEL_K_ROPE_OUTPUT = 0;
constexpr int32_t SEL_KV_CACHE_OUTPUT = 1;
constexpr int32_t SEL_BLOCK_TABLE_OUTPUT = 2;
constexpr int32_t SEL_BLOCK_STATUS_OUTPUT = 3;
constexpr int32_t ACTUAL_SEQ_OUTPUT = 4;
} // namespace

static ge::graphStatus InferShape4GatherSelectionKvCacheCustom(gert::InferShapeContext* context)
{
    const gert::Shape* rope = context->GetInputShape(SEL_K_ROPE_INPUT);
    const gert::Shape* cache = context->GetInputShape(SEL_KV_CACHE_INPUT);
    const gert::Shape* table = context->GetInputShape(SEL_BLOCK_TABLE_INPUT);
    const gert::Shape* status = context->GetInputShape(SEL_BLOCK_STATUS_INPUT);
    OPS_LOG_E_IF_NULL(context, rope, return ge::GRAPH_FAILED);
    OPS_LOG_E_IF_NULL(context, cache, return ge::GRAPH_FAILED);
    OPS_LOG_E_IF_NULL(context, table, return ge::GRAPH_FAILED);
    OPS_LOG_E_IF_NULL(context, status, return ge::GRAPH_FAILED);
    *context->GetOutputShape(SEL_K_ROPE_OUTPUT) = *rope;
    *context->GetOutputShape(SEL_KV_CACHE_OUTPUT) = *cache;
    *context->GetOutputShape(SEL_BLOCK_TABLE_OUTPUT) = *table;
    *context->GetOutputShape(SEL_BLOCK_STATUS_OUTPUT) = *status;
    gert::Shape* actual = context->GetOutputShape(ACTUAL_SEQ_OUTPUT);
    OPS_LOG_E_IF_NULL(context, actual, return ge::GRAPH_FAILED);
    *actual = *table;
    actual->SetDimNum(table->GetDimNum() - 1);
    return ge::GRAPH_SUCCESS;
}

static ge::graphStatus InferDtype4GatherSelectionKvCacheCustom(gert::InferDataTypeContext* context)
{
    context->SetOutputDataType(SEL_K_ROPE_OUTPUT, context->GetInputDataType(SEL_K_ROPE_INPUT));
    context->SetOutputDataType(SEL_KV_CACHE_OUTPUT, context->GetInputDataType(SEL_KV_CACHE_INPUT));
    context->SetOutputDataType(SEL_BLOCK_TABLE_OUTPUT, context->GetInputDataType(SEL_BLOCK_TABLE_INPUT));
    context->SetOutputDataType(SEL_BLOCK_STATUS_OUTPUT, context->GetInputDataType(SEL_BLOCK_STATUS_INPUT));
    context->SetOutputDataType(ACTUAL_SEQ_OUTPUT, ge::DT_INT32);
    return ge::GRAPH_SUCCESS;
}

IMPL_OP_INFERSHAPE(GatherSelectionKvCacheCustom)
    .InferShape(InferShape4GatherSelectionKvCacheCustom)
    .InferDataType(InferDtype4GatherSelectionKvCacheCustom);

} // namespace ops
