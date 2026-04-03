/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2026-2026. All rights reserved.
 * Description: e2a tiling function implementation file
 * Create: 2026-02-06
 * Note:
 * History: 2026-02-06 create e2a tiling function file
 */

#include "../op_kernel/e2a_tiling.h"
#include "register/op_def_registry.h"
#include "tiling/platform/platform_ascendc.h"

#include "tiling/hccl/hccl_tiling.h"

using namespace Cam;
namespace {
constexpr int TILING_KEY_FP16 = 20;
constexpr int TILING_KEY_BF16 = 21;
constexpr int TILING_KEY_FP32 = 22;
constexpr int TILING_KEY_ELSE = 23;

constexpr int ATTR_ENUM_BATCH_SIZE = 0;
constexpr int ATTR_ENUM_HIDDEN_SIZE = 1;
constexpr int ATTR_ENUM_TOPK = 2;
constexpr int ATTR_ENUM_EP_RANK_SIZE = 3;
constexpr int ATTR_ENUM_ATTN_RANK_SIZE = 4;
constexpr int ATTR_ENUM_RANK = 5;
constexpr int ATTR_ENUM_GROUP_EP = 6;
constexpr int ATTR_AIV_NUM = 7;

constexpr int MAX_TOPK = 8;
constexpr int TWO_DIMS = 2;
constexpr uint32_t OP_TYPE_ALL_TO_ALL = 8; // numeric representation of AlltoAll
} // namespace

namespace optiling {
    static ge::graphStatus TilingFunc(gert::TilingContext* context)
    {
        E2ATilingData *tiling = context->GetTilingData<E2ATilingData>();

        auto xDtype = context->GetInputDesc(0)->GetDataType();
        if (xDtype == ge::DT_FLOAT16) {
            context->SetTilingKey(TILING_KEY_FP16);
        } else if (xDtype == ge::DT_BF16) {
            context->SetTilingKey(TILING_KEY_BF16);
        } else if (xDtype == ge::DT_FLOAT) {
            context->SetTilingKey(TILING_KEY_FP32);
        } else {
            context->SetTilingKey(TILING_KEY_ELSE);
        }

        auto attrPointers = context->GetAttrs();
        int batchSize = *(attrPointers->GetInt(ATTR_ENUM_BATCH_SIZE));
        int hiddenSize = *(attrPointers->GetInt(ATTR_ENUM_HIDDEN_SIZE));
        int topk = *(attrPointers->GetInt(ATTR_ENUM_TOPK));
        int expertRankSize = *(attrPointers->GetInt(ATTR_ENUM_EP_RANK_SIZE));
        int attentionRankSize = *(attrPointers->GetInt(ATTR_ENUM_ATTN_RANK_SIZE));
        int rank = *(attrPointers->GetInt(ATTR_ENUM_RANK));
        int aivAlgNum = *(attrPointers->GetInt(ATTR_AIV_NUM));

        uint32_t blockNum = 1U;
        auto ascendcPlatform = platform_ascendc::PlatformAscendC(context->GetPlatformInfo());
        uint32_t aivNum = ascendcPlatform.GetCoreNumAiv();
        blockNum = ascendcPlatform.CalcTschBlockDim(aivNum, 0, aivNum);

        if (rank < 0 || rank >= expertRankSize + attentionRankSize) {
            printf("[ERROR] CAM E2A PARAMETER INVALID: rank must >= 0 and < expertRankSize + attentionRankSize, "
                    "but rank = %d, expertRankSize = %d, attentionRankSize = %d\n", rank, expertRankSize, attentionRankSize);
            return ge::GRAPH_FAILED;
        }

        tiling->batchSize = batchSize;
        tiling->hiddenSize = hiddenSize;
        tiling->topk = topk;
        tiling->expertRankSize = expertRankSize;
        tiling->attentionRankSize = attentionRankSize;
        tiling->rank = rank;

        context->SetBlockDim(aivAlgNum);

        auto groupEpPtr = attrPointers->GetAttrPointer<char>(static_cast<int>(ATTR_ENUM_GROUP_EP));
        std::string groupEp = std::string(groupEpPtr);
        uint32_t opType1 = OP_TYPE_ALL_TO_ALL;
        std::string algConfigAllToAllStr = "AlltoAll=level0:fullmesh;level1:pairwise";

        AscendC::Mc2CcTilingConfig mc2CcTilingConfig(groupEp, opType1, algConfigAllToAllStr);
        mc2CcTilingConfig.GetTiling(tiling->mc2InitTiling);
        mc2CcTilingConfig.GetTiling(tiling->mc2CcTiling1);

        return ge::GRAPH_SUCCESS;
    }
}

namespace ge {
    static ge::graphStatus InferShape(gert::InferShapeContext* context)
    {
        auto attrPointers = context->GetAttrs();
        int batchSize = *(attrPointers->GetInt(ATTR_ENUM_BATCH_SIZE));
        int hiddenSize = *(attrPointers->GetInt(ATTR_ENUM_HIDDEN_SIZE));
        int expertRankSize = *(attrPointers->GetInt(ATTR_ENUM_EP_RANK_SIZE));
        int rank = *(attrPointers->GetInt(ATTR_ENUM_RANK));

        int attentionRankSize = *(attrPointers->GetInt(ATTR_ENUM_ATTN_RANK_SIZE));

        gert::Shape* xShape = context->GetOutputShape(0);
        xShape->SetDimNum(TWO_DIMS);
        if (rank < expertRankSize) {
            xShape->SetDim(0, 1);
            xShape->SetDim(1, 1);
        } else if (attentionRankSize <= expertRankSize) {
            xShape->SetDim(0, batchSize);
            xShape->SetDim(1, hiddenSize);
        } else {
            xShape->SetDim(0, batchSize / (attentionRankSize / expertRankSize));
            xShape->SetDim(1, hiddenSize);
        }

        return GRAPH_SUCCESS;
    }

    static ge::graphStatus InferDataType(gert::InferDataTypeContext *context)
    {
        const auto expandXType = context->GetInputDataType(0);

        context->SetOutputDataType(0, expandXType);
        return ge::GRAPH_SUCCESS;
    }
}

namespace ops {
class E2a : public OpDef {
public:
    explicit E2a(const char* name) : OpDef(name)
    {
        this->Input("expand_x")
            .ParamType(REQUIRED)
            .DataType({ge::DT_BF16, ge::DT_BF16, ge::DT_FLOAT16, ge::DT_FLOAT16})
            .Format({ge::FORMAT_ND, ge::FORMAT_ND, ge::FORMAT_ND, ge::FORMAT_ND})
            .UnknownShapeFormat({ge::FORMAT_ND, ge::FORMAT_ND, ge::FORMAT_ND, ge::FORMAT_ND})
            .AutoContiguous();
        this->Input("atten_batch_size")
            .ParamType(REQUIRED)
            .DataType({ge::DT_INT32, ge::DT_INT32, ge::DT_INT32, ge::DT_INT32})
            .Format({ge::FORMAT_ND, ge::FORMAT_ND, ge::FORMAT_ND, ge::FORMAT_ND})
            .UnknownShapeFormat({ge::FORMAT_ND, ge::FORMAT_ND, ge::FORMAT_ND, ge::FORMAT_ND})
            .AutoContiguous();

        this->Output("x")
            .ParamType(REQUIRED)
            .DataType({ge::DT_BF16, ge::DT_INT8, ge::DT_FLOAT16, ge::DT_INT8})
            .Format({ge::FORMAT_ND, ge::FORMAT_ND, ge::FORMAT_ND, ge::FORMAT_ND})
            .UnknownShapeFormat({ge::FORMAT_ND, ge::FORMAT_ND, ge::FORMAT_ND, ge::FORMAT_ND});

        this->Attr("batch_size").Int();
        this->Attr("hidden_size").Int();
        this->Attr("topk").Int();
        this->Attr("expert_rank_size").Int();
        this->Attr("attention_rank_size").Int();
        this->Attr("rank").Int();
        this->Attr("group_ep").String();
        this->Attr("aiv_num").Int();

        this->SetInferShape(ge::InferShape).SetInferDataType(ge::InferDataType);

        OpAICoreConfig aicore_config;
        aicore_config.DynamicCompileStaticFlag(true)
            .DynamicFormatFlag(true)
            .DynamicRankSupportFlag(true)
            .DynamicShapeSupportFlag(true)
            .NeedCheckSupportFlag(false)
            .PrecisionReduceFlag(true)
            .ExtendCfgInfo("aclnnSupport.value", "support_aclnn")
            .ExtendCfgInfo("jitCompile.flag", "static_true")
            .ExtendCfgInfo("multiKernelSupportDynamicGraph.value", "multi_kernel");

        this->AICore().SetTiling(optiling::TilingFunc);
        this->AICore().AddConfig("ascend910_93", aicore_config);
        this->MC2().HcclGroup({"group_ep"});
    }
};

OP_ADD(E2a);
}