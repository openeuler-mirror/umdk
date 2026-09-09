/**
 * Copyright (c) 2026 Huawei Technologies Co., Ltd.
 * This program is free software, you can redistribute it and/or modify it under the terms and conditions of
 * CANN Open Software License Agreement Version 2.0 (the "License").
 * See LICENSE in the root of the software repository for the full text of the License.
 */

#include <cstdint>
#include "register/op_def_registry.h"

namespace ops {
namespace {
constexpr int64_t kDefaultSparseMode = 3;
constexpr int64_t kDefaultTileSize = 128;
constexpr int64_t kDefaultRopeHeadDim = 64;
} // namespace

class GatherSelectionSparseFlashAttention : public OpDef {
public:
    explicit GatherSelectionSparseFlashAttention(const char *name) : OpDef(name)
    {
        this->Input("query")
            .ParamType(REQUIRED)
            .DataType({ge::DT_FLOAT16, ge::DT_BF16})
            .Format({ge::FORMAT_ND, ge::FORMAT_ND})
            .AutoContiguous();
        this->Input("selection_key")
            .ParamType(REQUIRED)
            .DataType({ge::DT_INT8, ge::DT_INT8})
            .Format({ge::FORMAT_ND, ge::FORMAT_ND})
            .AutoContiguous();
        this->Input("selection_value")
            .ParamType(REQUIRED)
            .Follow("selection_key")
            .AutoContiguous();
        this->Input("selection_topk_indices")
            .ParamType(REQUIRED)
            .DataType({ge::DT_INT32, ge::DT_INT32})
            .Format({ge::FORMAT_ND, ge::FORMAT_ND})
            .AutoContiguous();
        this->Input("key_dequant_scale")
            .ParamType(OPTIONAL)
            .DataType({ge::DT_FLOAT, ge::DT_FLOAT})
            .Format({ge::FORMAT_ND, ge::FORMAT_ND})
            .AutoContiguous();
        this->Input("value_dequant_scale")
            .ParamType(OPTIONAL)
            .DataType({ge::DT_FLOAT, ge::DT_FLOAT})
            .Format({ge::FORMAT_ND, ge::FORMAT_ND})
            .AutoContiguous();
        this->Input("selection_kv_block_table")
            .ParamType(REQUIRED)
            .DataType({ge::DT_INT32, ge::DT_INT32})
            .Format({ge::FORMAT_ND, ge::FORMAT_ND})
            .AutoContiguous();
        this->Input("actual_seq_lengths_query")
            .ParamType(REQUIRED)
            .DataType({ge::DT_INT32, ge::DT_INT32})
            .Format({ge::FORMAT_ND, ge::FORMAT_ND})
            .AutoContiguous();
        this->Input("full_kv_actual_seq")
            .ParamType(REQUIRED)
            .DataType({ge::DT_INT32, ge::DT_INT32})
            .Format({ge::FORMAT_ND, ge::FORMAT_ND})
            .AutoContiguous();
        this->Input("sinks")
            .ParamType(OPTIONAL)
            .DataType({ge::DT_FLOAT, ge::DT_FLOAT})
            .Format({ge::FORMAT_ND, ge::FORMAT_ND})
            .AutoContiguous();
        this->Input("selection_kv_block_status")
            .ParamType(REQUIRED)
            .DataType({ge::DT_INT32, ge::DT_INT32})
            .Format({ge::FORMAT_ND, ge::FORMAT_ND})
            .AutoContiguous();
        this->Input("full_kv_cache")
            .ParamType(REQUIRED)
            .Follow("selection_key")
            .AutoContiguous();
        this->Input("full_kv_block_table")
            .ParamType(REQUIRED)
            .DataType({ge::DT_INT32, ge::DT_INT32})
            .Format({ge::FORMAT_ND, ge::FORMAT_ND})
            .AutoContiguous();

        this->Output("attention_out")
            .ParamType(REQUIRED)
            .DataType({ge::DT_FLOAT16, ge::DT_BF16})
            .Format({ge::FORMAT_ND, ge::FORMAT_ND});
        this->Output("selection_key")
            .ParamType(REQUIRED)
            .Follow("selection_key");
        this->Output("selection_kv_block_table")
            .ParamType(REQUIRED)
            .Follow("selection_kv_block_table");
        this->Output("selection_kv_block_status")
            .ParamType(REQUIRED)
            .Follow("selection_kv_block_status");
        this->Output("selection_kv_actual_seq")
            .ParamType(REQUIRED)
            .DataType({ge::DT_INT32, ge::DT_INT32})
            .Format({ge::FORMAT_ND, ge::FORMAT_ND});

        // Attribute order intentionally matches KvQuantSparseFlashAttention through rope_head_dim.
        this->Attr("scale_value").AttrType(REQUIRED).Float(1.0);
        this->Attr("key_quant_mode").AttrType(REQUIRED).Int(1);
        this->Attr("value_quant_mode").AttrType(REQUIRED).Int(1);
        this->Attr("sparse_block_size").AttrType(OPTIONAL).Int(1);
        this->Attr("layout_query").AttrType(OPTIONAL).String("TND");
        this->Attr("layout_kv").AttrType(OPTIONAL).String("PA_BSND");
        this->Attr("sparse_mode").AttrType(OPTIONAL).Int(kDefaultSparseMode);
        this->Attr("pre_tokens").AttrType(OPTIONAL).Int(INT64_MAX);
        this->Attr("next_tokens").AttrType(OPTIONAL).Int(INT64_MAX);
        this->Attr("attention_mode").AttrType(OPTIONAL).Int(0);
        this->Attr("quant_scale_repo_mode").AttrType(OPTIONAL).Int(1);
        this->Attr("tile_size").AttrType(OPTIONAL).Int(kDefaultTileSize);
        this->Attr("rope_head_dim").AttrType(OPTIONAL).Int(kDefaultRopeHeadDim);
        this->Attr("selection_topk_block_size").AttrType(OPTIONAL).Int(1);

        OpAICoreConfig a3Config;
        a3Config.DynamicCompileStaticFlag(true)
            .DynamicFormatFlag(true)
            .DynamicRankSupportFlag(true)
            .DynamicShapeSupportFlag(true)
            .NeedCheckSupportFlag(false)
            .PrecisionReduceFlag(true);
        this->AICore().AddConfig("ascend910_93", a3Config);
    }
};
OP_ADD(GatherSelectionSparseFlashAttention);
} // namespace ops
