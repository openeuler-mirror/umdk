/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2026-2026. All rights reserved.
 * Description: ReduceScatter operator definition file
 * Create: 2026-01-22
 * Note:
 * History: 2026-01-22 create a ReduceScatter operator definition file
 */
#include "register/op_def_registry.h"
namespace {
constexpr uint32_t ATTR_RANK_SIZE_INDEX = 1;
}

namespace ge {
static ge::graphStatus InferShape(gert::InferShapeContext *context)
{
    const gert::Shape *inputShape = context->GetInputShape(0);
    gert::Shape *outputShape = context->GetOutputShape(0);
    if (inputShape == nullptr || outputShape == nullptr) {
        return ge::GRAPH_FAILED;
    }
    if (context->GetAttrs() == nullptr || context->GetAttrs()->GetInt(ATTR_RANK_SIZE_INDEX) == nullptr) {
        return ge::GRAPH_FAILED;
    }
    int64_t rankSize = *(context->GetAttrs()->GetInt(ATTR_RANK_SIZE_INDEX));
    size_t dimNum = inputShape->GetDimNum();
    outputShape->SetDimNum(dimNum);

    outputShape->SetDim(0, inputShape->GetDim(0) / rankSize);

    for (size_t i = 1; i < dimNum; i++) {
        outputShape->SetDim(i, inputShape->GetDim(i));
    }
    return GRAPH_SUCCESS;
}

static ge::graphStatus InferDataType(gert::InferDataTypeContext *context)
{
    const auto inputDataType = context->GetInputDataType(0);
    context->SetOutputDataType(0, inputDataType);
    return ge::GRAPH_SUCCESS;
}
}

namespace ops {
class ReduceScatterDetour : public OpDef {
public:
    explicit ReduceScatterDetour(const char *name) : OpDef(name)
    {
        this->Input("input")
            .ParamType(REQUIRED)
            .DataType({ge::DT_FLOAT16})
            .Format({ge::FORMAT_ND})
            .UnknownShapeFormat({ge::FORMAT_ND});
        this->Input("commRankIds")
            .ParamType(REQUIRED)
            .DataType({ge::DT_INT32})
            .Format({ge::FORMAT_ND})
            .UnknownShapeFormat({ge::FORMAT_ND});
        this->Input("commArgs")
            .ParamType(REQUIRED)
            .DataType({ge::DT_FLOAT16})
            .Format({ge::FORMAT_ND})
            .UnknownShapeFormat({ge::FORMAT_ND});
        this->Output("output")
            .ParamType(REQUIRED)
            .DataType({ge::DT_FLOAT16})
            .Format({ge::FORMAT_ND})
            .UnknownShapeFormat({ge::FORMAT_ND});
        this->Attr("magic").Int();
        this->Attr("rank_size").Int();
        this->Attr("op").Int();

        this->SetInferShape(ge::InferShape).SetInferDataType(ge::InferDataType);
        this->AICore().AddConfig("ascend910b");
    }
};

OP_ADD(ReduceScatterDetour);
}