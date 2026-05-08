/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2026-2026. All rights reserved.
 * Description: a2e tiling function implementation file
 * Create: 2026-02-06
 * Note:
 * History: 2026-02-06 create a2e tiling function file
 */

#include "../op_kernel/a2e_tiling.h"
#include "register/op_def_registry.h"
#include "tiling/platform/platform_ascendc.h"

#include "tiling/hccl/hccl_tiling.h"
#include "error_log.h"

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
constexpr int ATTR_COMPUTE_GATE = 8;

constexpr int INPUT_EXPANDX_IDX = 0;
constexpr int INPUT_EXPERT_SCALES_IDX = 2;
constexpr int INPUT_EXPERT_IDS_IDX = 1;

constexpr int MAX_TOPK = 8;
constexpr uint32_t OP_TYPE_ALL_TO_ALL = 8; // numeric representation of AlltoAll
constexpr int MAX_BATCH_SIZE = 1024;
constexpr int MIN_HIDDEN_SIZE = 1024;
constexpr int MAX_HIDDEN_SIZE = 7168;
constexpr int HIDDEN_SIZE_ALIGN = 256;
constexpr int AIV_ALG_NUM_MIN = 4;
constexpr int AIV_ALG_NUM_MAX = 48;
}  // namespace

namespace optiling {
    struct A2ECheckParams {
        int rank;
        int batchSize;
        int hiddenSize;
        int topk;
        int expertRankSize;
        int attentionRankSize;
        int aivAlgNum;
        uint32_t aivNum;
        int computeGate;
    };

    static ge::graphStatus CheckData(const char* nodeName, const A2ECheckParams& params)
    {
        OP_TILING_CHECK(params.rank < 0 || params.rank >= params.expertRankSize + params.attentionRankSize,
            OP_LOGE(nodeName, "CAM A2E PARAMETER INVALID: rank must >= 0 and < expertRankSize + attentionRankSize"),
            return ge::GRAPH_FAILED);

        OP_TILING_CHECK(params.batchSize <= 0 || params.batchSize > MAX_BATCH_SIZE,
            OP_LOGE(nodeName, "CAM A2E PARAMETER INVALID: batchSize must >= 0 and <= 1024"),
            return ge::GRAPH_FAILED);

        OP_TILING_CHECK(params.hiddenSize < MIN_HIDDEN_SIZE || params.hiddenSize > MAX_HIDDEN_SIZE ||
                        params.hiddenSize % HIDDEN_SIZE_ALIGN != 0,
            OP_LOGE(nodeName, "CAM A2E PARAMETER INVALID: hiddenSize must >= 1024 and <= 7168 and be divisible by 256"),
            return ge::GRAPH_FAILED);

        OP_TILING_CHECK(params.topk <= 0 || params.topk > MAX_TOPK,
            OP_LOGE(nodeName, "CAM A2E PARAMETER INVALID: topk must >= 1 and <= 8"),
            return ge::GRAPH_FAILED);

        OP_TILING_CHECK(params.expertRankSize <= 0 || params.expertRankSize > params.attentionRankSize,
            OP_LOGE(nodeName, "CAM A2E PARAMETER INVALID: expertRankSize must > 0 and <= attentionRankSize"),
            return ge::GRAPH_FAILED);

        OP_TILING_CHECK(params.aivAlgNum < AIV_ALG_NUM_MIN || params.aivAlgNum > AIV_ALG_NUM_MAX,
            OP_LOGE(nodeName, "CAM A2E PARAMETER INVALID: aivAlgNum must >= 4 and <= 48"),
            return ge::GRAPH_FAILED);

        OP_TILING_CHECK(params.computeGate != 0 && params.computeGate != 1,
            OP_LOGE(nodeName, "CAM A2E PARAMETER INVALID: computeGate must be 0 or 1"),
            return ge::GRAPH_FAILED);

        return ge::GRAPH_SUCCESS;
    }

    static ge::graphStatus TilingFunc(gert::TilingContext* context)
    {
        A2ETilingData *tiling = context->GetTilingData<A2ETilingData>();

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
        int computeGate = *(attrPointers->GetInt(ATTR_COMPUTE_GATE));

        uint32_t blockNum = 1U;
        auto ascendcPlatform = platform_ascendc::PlatformAscendC(context->GetPlatformInfo());
        uint32_t aivNum = ascendcPlatform.GetCoreNumAiv();
        blockNum = ascendcPlatform.CalcTschBlockDim(aivNum, 0, aivNum);

        const char* nodeName = context->GetNodeName();
        A2ECheckParams checkParams{rank, batchSize, hiddenSize, topk, expertRankSize,
            attentionRankSize, aivAlgNum, aivNum, computeGate};
        OP_TILING_CHECK(CheckData(nodeName, checkParams) != ge::GRAPH_SUCCESS,
            OP_LOGE(nodeName, "CheckData failed."),
            return ge::GRAPH_FAILED);

        tiling->batchSize = batchSize;
        tiling->hiddenSize = hiddenSize;
        tiling->topk = topk;
        tiling->expertRankSize = expertRankSize;
        tiling->attentionRankSize = attentionRankSize;
        tiling->rank = rank;
        tiling->computeGate = computeGate;

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
        int topk = *(attrPointers->GetInt(ATTR_ENUM_TOPK));
        int expertRankSize = *(attrPointers->GetInt(ATTR_ENUM_EP_RANK_SIZE));
        int attentionRankSize = *(attrPointers->GetInt(ATTR_ENUM_ATTN_RANK_SIZE));
        int rank = *(attrPointers->GetInt(ATTR_ENUM_RANK));
        batchSize = batchSize * (attentionRankSize + expertRankSize - 1) / expertRankSize;
    
        gert::Shape* expandXShape = context->GetOutputShape(0);
        expandXShape->SetDimNum(2);
        if (rank < expertRankSize) {
            expandXShape->SetDim(0, batchSize);
            expandXShape->SetDim(1, hiddenSize);
        } else {
            expandXShape->SetDim(0, 1);
            expandXShape->SetDim(1, 1);
        }

        gert::Shape* simulateExpertIdsShape = context->GetOutputShape(1);
        simulateExpertIdsShape->SetDimNum(2);
        if (rank < attentionRankSize) {
            simulateExpertIdsShape->SetDim(0, batchSize);
            simulateExpertIdsShape->SetDim(1, topk);
        } else {
            simulateExpertIdsShape->SetDim(0, 1);
            simulateExpertIdsShape->SetDim(1, 1);
        }

        gert::Shape* simulateExpertScalesShape = context->GetOutputShape(2);
        simulateExpertScalesShape->SetDimNum(2);
        if (rank < attentionRankSize) {
            simulateExpertScalesShape->SetDim(0, batchSize);
            simulateExpertScalesShape->SetDim(1, topk);
        } else {
            simulateExpertScalesShape->SetDim(0, 1);
            simulateExpertScalesShape->SetDim(1, 1);
        }

        gert::Shape* attenBatchSizeShape = context->GetOutputShape(3);
        attenBatchSizeShape->SetDimNum(1);
        attenBatchSizeShape->SetDim(0, (attentionRankSize + expertRankSize - 1) / expertRankSize);

        gert::Shape* xActiveMaskOutShape = context->GetOutputShape(4);
        xActiveMaskOutShape->SetDimNum(1);
        if (rank < attentionRankSize) {
            xActiveMaskOutShape->SetDim(0, batchSize);
        } else {
            xActiveMaskOutShape->SetDim(0, 1);
        }

        return GRAPH_SUCCESS;
    }

    static ge::graphStatus InferDataType(gert::InferDataTypeContext *context)
    {
        const auto expertIdsType = context->GetInputDataType(INPUT_EXPERT_IDS_IDX);
        const auto expertScalesType = context->GetInputDataType(INPUT_EXPERT_SCALES_IDX);
        const auto expandXDType = context->GetInputDataType(INPUT_EXPANDX_IDX);

        int outputIdx = 0;
        context->SetOutputDataType(outputIdx++, expandXDType);
        context->SetOutputDataType(outputIdx++, expertIdsType);
        context->SetOutputDataType(outputIdx++, expertScalesType);
        context->SetOutputDataType(outputIdx++, ge::DT_BOOL);
        return ge::GRAPH_SUCCESS;
    }
}

namespace ops {
class A2e : public OpDef {
public:
    explicit A2e(const char* name) : OpDef(name)
    {
        this->Input("x")
            .ParamType(REQUIRED)
            .DataType({ge::DT_BF16, ge::DT_BF16, ge::DT_FLOAT16, ge::DT_FLOAT16})
            .Format({ge::FORMAT_ND, ge::FORMAT_ND, ge::FORMAT_ND, ge::FORMAT_ND})
            .UnknownShapeFormat({ge::FORMAT_ND, ge::FORMAT_ND, ge::FORMAT_ND, ge::FORMAT_ND})
            .AutoContiguous();
        this->Input("expert_ids")
            .ParamType(OPTIONAL)
            .DataType({ge::DT_INT32, ge::DT_INT32, ge::DT_INT32, ge::DT_INT32})
            .Format({ge::FORMAT_ND, ge::FORMAT_ND, ge::FORMAT_ND, ge::FORMAT_ND})
            .UnknownShapeFormat({ge::FORMAT_ND, ge::FORMAT_ND, ge::FORMAT_ND, ge::FORMAT_ND})
            .AutoContiguous();
        this->Input("scales")
            .ParamType(OPTIONAL)
            .DataType({ge::DT_FLOAT, ge::DT_FLOAT, ge::DT_FLOAT, ge::DT_FLOAT})
            .Format({ge::FORMAT_ND, ge::FORMAT_ND, ge::FORMAT_ND, ge::FORMAT_ND})
            .UnknownShapeFormat({ge::FORMAT_ND, ge::FORMAT_ND, ge::FORMAT_ND, ge::FORMAT_ND})
            .AutoContiguous();

        this->Output("expand_x")
            .ParamType(REQUIRED)
            .DataType({ge::DT_BF16, ge::DT_INT8, ge::DT_FLOAT16, ge::DT_INT8})
            .Format({ge::FORMAT_ND, ge::FORMAT_ND, ge::FORMAT_ND, ge::FORMAT_ND})
            .UnknownShapeFormat({ge::FORMAT_ND, ge::FORMAT_ND, ge::FORMAT_ND, ge::FORMAT_ND});
        this->Output("simulate_expert_ids")
            .ParamType(REQUIRED)
            .DataType({ge::DT_INT32, ge::DT_INT32, ge::DT_INT32, ge::DT_INT32})
            .Format({ge::FORMAT_ND, ge::FORMAT_ND, ge::FORMAT_ND, ge::FORMAT_ND})
            .UnknownShapeFormat({ge::FORMAT_ND, ge::FORMAT_ND, ge::FORMAT_ND, ge::FORMAT_ND})
            .AutoContiguous();
        this->Output("simulate_expert_scales")
            .ParamType(REQUIRED)
            .DataType({ge::DT_FLOAT, ge::DT_FLOAT, ge::DT_FLOAT, ge::DT_FLOAT})
            .Format({ge::FORMAT_ND, ge::FORMAT_ND, ge::FORMAT_ND, ge::FORMAT_ND})
            .UnknownShapeFormat({ge::FORMAT_ND, ge::FORMAT_ND, ge::FORMAT_ND, ge::FORMAT_ND})
            .AutoContiguous();
        this->Output("atten_batch_size")
            .ParamType(REQUIRED)
            .DataType({ge::DT_INT32, ge::DT_INT32, ge::DT_INT32, ge::DT_INT32})
            .Format({ge::FORMAT_ND, ge::FORMAT_ND, ge::FORMAT_ND, ge::FORMAT_ND})
            .UnknownShapeFormat({ge::FORMAT_ND, ge::FORMAT_ND, ge::FORMAT_ND, ge::FORMAT_ND})
            .AutoContiguous();
        this->Output("x_active_mask")
            .ParamType(REQUIRED)
            .DataType({ge::DT_BOOL, ge::DT_BOOL, ge::DT_BOOL, ge::DT_BOOL})
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
        this->Attr("compute_gate").Int();

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

OP_ADD(A2e);
}