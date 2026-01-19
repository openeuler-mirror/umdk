/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2026-2026. All rights reserved.
 * Description: all2all with detour function implementation file
 * Create: 2026-01-22
 * Note:
 * History: 2026-01-22 create all2all with detour function file
 */

#include "all2_all_detour_tiling.h"
#include "register/op_def_registry.h"

constexpr static int TILING_KEY_FLOAT16 = 20;
constexpr static int TILING_KEY_BFLOAT16 = 21;
constexpr static int TILING_KEY_FLOAT = 22;
constexpr static int TILING_KEY_INT = 23;

namespace optiling {
static ge::graphStatus TilingFunc(gert::TilingContext *context)
{
    All2AllDetourTilingData tiling;
    const gert::StorageShape* input_shape = context->GetInputShape(0);
    if (input_shape == nullptr) {
        return ge::GRAPH_FAILED;
    }
    int32_t sendCount = 1;
    for (size_t i = 0; i < input_shape->GetStorageShape().GetDimNum(); i++) {
        sendCount *= input_shape->GetStorageShape().GetDim(i);
    }
    tiling.set_sendCount(sendCount);
    const gert::StorageShape* commRankIdsShape = context->GetInputShape(1);
    if (commRankIdsShape == nullptr) {
        return ge::GRAPH_FAILED;
    }
    int32_t commRankCount = 1;
    for (size_t i = 0; i < commRankIdsShape->GetStorageShape().GetDimNum(); i++) {
        commRankCount *= commRankIdsShape->GetStorageShape().GetDim(i);
    }
    tiling.set_commRankCount(commRankCount);
    
    int tilingKey = TILING_KEY_INT;
    if (!context->GetInputDesc(0)) {
        return ge::GRAPH_FAILED;
    }
    auto sendDtype = context->GetInputDesc(0)->GetDataType();
    if (sendDtype == ge::DT_FLOAT16) {
        tilingKey = TILING_KEY_FLOAT16;
    } else if (sendDtype == ge::DT_BF16) {
        tilingKey = TILING_KEY_BFLOAT16;
    } else if (sendDtype == ge::DT_FLOAT) {
        tilingKey = TILING_KEY_FLOAT;
    }

    auto attrPointers = context->GetAttrs();
    if (!attrPointers) {
        return ge::GRAPH_FAILED;
    }
    int32_t magic = *(attrPointers->GetInt(0));
    tiling.set_magic(magic);

    uint32_t blockDim = 48;

    context->SetTilingKey(tilingKey);
    context->SetBlockDim(blockDim);
    tiling.SaveToBuffer(context->GetRawTilingData()->GetData(), context->GetRawTilingData()->GetCapacity());
    context->GetRawTilingData()->SetDataSize(tiling.GetDataSize());
    return ge::GRAPH_SUCCESS;
}
}

namespace ge {
static ge::graphStatus InferShape(gert::InferShapeContext *context)
{
    const gert::Shape* input_shape = context->GetInputShape(0);
    gert::Shape* output_shape = context->GetOutputShape(0);

    if (input_shape == nullptr || output_shape == nullptr) {
        return ge::GRAPH_FAILED;
    }
    output_shape->SetDimNum(input_shape->GetDimNum());
    for (size_t i = 0; i < input_shape->GetDimNum(); i++) {
        output_shape->SetDim(i, input_shape->GetDim(i));
    }
    return GRAPH_SUCCESS;
}

static ge::graphStatus InferDataType(gert::InferDataTypeContext *context)
{
    const auto send_data_type = context->GetInputDataType(0);
    context->SetOutputDataType(0, send_data_type);

    return ge::GRAPH_SUCCESS;
}
}

namespace ops {
class All2AllDetour : public OpDef {
public:
    explicit All2AllDetour(const char* name) : OpDef(name)
    {
        this->Input("sendData")
            .ParamType(REQUIRED)
            .DataType({ge::DT_FLOAT16, ge::DT_BF16, ge::DT_FLOAT, ge::DT_INT32, ge::DT_BF16})
            .Format({ge::FORMAT_ND, ge::FORMAT_ND, ge::FORMAT_ND, ge::FORMAT_ND, ge::FORMAT_NC1HWC0})
            .UnknownShapeFormat({ge::FORMAT_ND, ge::FORMAT_ND, ge::FORMAT_ND, ge::FORMAT_ND, ge::FORMAT_NC1HWC0});
        this->Input("commRankIds")
            .ParamType(REQUIRED)
            .DataType({ge::DT_INT32, ge::DT_INT32, ge::DT_INT32, ge::DT_INT32, ge::DT_INT32})
            .Format({ge::FORMAT_ND, ge::FORMAT_ND, ge::FORMAT_ND, ge::FORMAT_ND, ge::FORMAT_ND})
            .UnknownShapeFormat({ge::FORMAT_ND, ge::FORMAT_ND, ge::FORMAT_ND, ge::FORMAT_ND, ge::FORMAT_ND});
        this->Input("commArgs")
            .ParamType(REQUIRED)
            .DataType({ge::DT_FLOAT16, ge::DT_FLOAT16, ge::DT_FLOAT16, ge::DT_FLOAT16, ge::DT_FLOAT16})
            .Format({ge::FORMAT_ND, ge::FORMAT_ND, ge::FORMAT_ND, ge::FORMAT_ND, ge::FORMAT_ND})
            .UnknownShapeFormat({ge::FORMAT_ND, ge::FORMAT_ND, ge::FORMAT_ND, ge::FORMAT_ND, ge::FORMAT_ND});
        this->Output("recvData")
            .ParamType(REQUIRED)
            .DataType({ge::DT_FLOAT16, ge::DT_BF16, ge::DT_FLOAT, ge::DT_INT32, ge::DT_BF16})
            .Format({ge::FORMAT_ND, ge::FORMAT_ND, ge::FORMAT_ND, ge::FORMAT_ND, ge::FORMAT_NC1HWC0})
            .UnknownShapeFormat({ge::FORMAT_ND, ge::FORMAT_ND, ge::FORMAT_ND, ge::FORMAT_ND, ge::FORMAT_NC1HWC0});
        this->Attr("magic").Int();

        this->SetInferShape(ge::InferShape).SetInferDataType(ge::InferDataType);

        this->AICore()
            .SetTiling(optiling::TilingFunc);
        this->AICore().AddConfig("ascend910_93");
        this->AICore().AddConfig("ascend910b");
    }
};

OP_ADD(All2AllDetour);
}