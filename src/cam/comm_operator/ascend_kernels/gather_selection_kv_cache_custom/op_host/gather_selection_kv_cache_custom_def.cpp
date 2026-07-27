/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2026-2026. All rights reserved.
 * Description: GatherSelectionKvCacheCustom operator definition file
 * Create: 2026-07-25
 * Note:
 * History: 2026-07-25 create GatherSelectionKvCacheCustom operator definition file
 */

#include "register/op_def_registry.h"

namespace ops {

class GatherSelectionKvCacheCustom : public OpDef {
public:
    explicit GatherSelectionKvCacheCustom(const char* name) : OpDef(name)
    {
        AddCacheInput("selection_k_rope");
        AddCacheInput("selection_kv_cache");
        AddIntInput("selection_kv_block_table");
        AddIntInput("selection_kv_block_status");
        AddIntInput("selection_topk_indices");
        AddCacheInput("full_k_rope");
        AddCacheInput("full_kv_cache");
        AddIntInput("full_kv_block_table");
        AddIntInput("full_kv_actual_seq");
        AddIntInput("full_q_actual_seq");

        AddCacheOutput("selection_k_rope");
        AddCacheOutput("selection_kv_cache");
        AddIntOutput("selection_kv_block_table");
        AddIntOutput("selection_kv_block_status");
        AddIntOutput("selection_kv_actual_seq");

        this->Attr("selection_topk_block_size").AttrType(OPTIONAL).Int(1);
        this->AICore().AddConfig("ascend910_93").AddConfig("ascend910b");
    }

private:
    void AddCacheInput(const char* name)
    {
        this->Input(name)
            .ParamType(REQUIRED)
            .DataType({ge::DT_FLOAT16, ge::DT_BF16, ge::DT_INT8})
            .Format({ge::FORMAT_ND, ge::FORMAT_ND, ge::FORMAT_ND})
            .UnknownShapeFormat({ge::FORMAT_ND, ge::FORMAT_ND, ge::FORMAT_ND});
    }

    void AddIntInput(const char* name)
    {
        this->Input(name)
            .ParamType(REQUIRED)
            .DataType({ge::DT_INT32, ge::DT_INT32, ge::DT_INT32})
            .Format({ge::FORMAT_ND, ge::FORMAT_ND, ge::FORMAT_ND})
            .UnknownShapeFormat({ge::FORMAT_ND, ge::FORMAT_ND, ge::FORMAT_ND});
    }

    void AddCacheOutput(const char* name)
    {
        this->Output(name)
            .ParamType(REQUIRED)
            .DataType({ge::DT_FLOAT16, ge::DT_BF16, ge::DT_INT8})
            .Format({ge::FORMAT_ND, ge::FORMAT_ND, ge::FORMAT_ND})
            .UnknownShapeFormat({ge::FORMAT_ND, ge::FORMAT_ND, ge::FORMAT_ND});
    }

    void AddIntOutput(const char* name)
    {
        this->Output(name)
            .ParamType(REQUIRED)
            .DataType({ge::DT_INT32, ge::DT_INT32, ge::DT_INT32})
            .Format({ge::FORMAT_ND, ge::FORMAT_ND, ge::FORMAT_ND})
            .UnknownShapeFormat({ge::FORMAT_ND, ge::FORMAT_ND, ge::FORMAT_ND});
    }
};

OP_ADD(GatherSelectionKvCacheCustom);

} // namespace ops
