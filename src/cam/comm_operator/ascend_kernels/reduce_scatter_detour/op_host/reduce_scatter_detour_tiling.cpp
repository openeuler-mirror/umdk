/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2026-2026. All rights reserved.
 * Description: The tiling function definition file of ReduceScatter operator
 * Create: 2026-01-22
 * Note:
 * History: 2026-01-22 create a tiling function of ReduceScatter operator
 */

#include <queue>
#include <vector>
#include <dlfcn.h>
#include <fcntl.h>
#include <cstdio>
#include <unistd.h>
#include <cmath>
#include <cstdint>
#include <string>

#include "error_log.h"
#include "graph/utils/type_utils.h"
#include "register/op_def_registry.h"
#include "tiling/platform/platform_ascendc.h"
#include "tiling/hccl/hccl_tiling.h"
#include  "../op_kernel/reduce_scatter_detour_tiling.h"

using namespace ge;
using namespace Cam;

namespace {
    constexpr uint32_t INPUT_SEND_DATA_INDEX = 0;
    constexpr uint32_t INPUT_COMM_RANKIDS_INDEX = 1;

    constexpr uint32_t ATTR_MAGIC_INDEX = 0;
    constexpr uint32_t ATTR_RANK_SIZE_INDEX = 1;
    constexpr uint32_t ATTR_OP_INDEX = 2;

    constexpr uint32_t SYSTEM_NEED_WORKSPACE = 16 * 1024 * 1024;

    constexpr static int TILING_KEY_FLOAT16 = 20;

    constexpr int64_t MAX_NPU_NUM = 16;
}

namespace optiling {
static void PrintTilingDataInfo(const char *nodeName, const ReduceScatterDetourTilingData &tilingData)
{
    OP_LOGD(nodeName, "sendCount is %u.", tilingData.sendCount);
}

static ge::graphStatus GetAttrAndSetTilingData(const gert::TilingContext *context, const char *nodeName,
    ReduceScatterDetourTilingData &tilingData)
{
    auto attrs = context->GetAttrs();
    OP_TILING_CHECK(attrs == nullptr, OP_LOGE(nodeName, "attrs is nullptr."), return ge::GRAPH_FAILED);

    auto magicPtr = attrs->GetAttrPointer<int64_t>(ATTR_MAGIC_INDEX);
    auto rankSizePtr = attrs->GetAttrPointer<int64_t>(ATTR_RANK_SIZE_INDEX);
    auto opPtr = attrs->GetAttrPointer<int64_t>(ATTR_OP_INDEX);

    const gert::StorageShape* inputShape = context->GetInputShape(INPUT_SEND_DATA_INDEX);
    uint32_t sendCount = 1;
    for (size_t i = 0; i < inputShape->GetStorageShape().GetDimNum(); i++) {
        sendCount *= inputShape->GetStorageShape().GetDim(i);
    }

    OP_TILING_CHECK(magicPtr == nullptr, OP_LOGE(nodeName, "magicPtr is null."), return ge::GRAPH_FAILED);
    OP_TILING_CHECK(rankSizePtr == nullptr, OP_LOGE(nodeName, "rankSizePtr is null."), return ge::GRAPH_FAILED);
    OP_TILING_CHECK(opPtr == nullptr, OP_LOGE(nodeName, "opPtr is null."), return ge::GRAPH_FAILED);

    OP_TILING_CHECK((sendCount <= 0),
        OP_LOGE(nodeName, "sendCount is invalid, only support >=0, but got sendCount=%u.", sendCount),
        return ge::GRAPH_FAILED);
    OP_TILING_CHECK((*rankSizePtr <= 0) || (*rankSizePtr > MAX_NPU_NUM),
        OP_LOGE(nodeName,
            "rankSize is invalid, only support (0, %ld], but got rankSize=%ld.",
            MAX_NPU_NUM,
            *rankSizePtr),
        return ge::GRAPH_FAILED);
    OP_TILING_CHECK((sendCount % (*rankSizePtr) != 0),
        OP_LOGE(nodeName, "inputSize is invalid, inputSize %u, rankSize %ld.", sendCount, *rankSizePtr),
        return ge::GRAPH_FAILED);
    
    const gert::StorageShape* commRankIdsShape = context->GetInputShape(INPUT_COMM_RANKIDS_INDEX);
    if (commRankIdsShape == nullptr) {
        return ge::GRAPH_FAILED;
    }
    int32_t commRankCount = 1;
    for (size_t i = 0; i < commRankIdsShape->GetStorageShape().GetDimNum(); i++) {
        commRankCount *= commRankIdsShape->GetStorageShape().GetDim(i);
    }

    tilingData.magic = *magicPtr;
    tilingData.sendCount = sendCount;
    tilingData.op = static_cast<uint32_t>(*opPtr);
    tilingData.commRankCount = commRankCount;

    return ge::GRAPH_SUCCESS;
}

static ge::graphStatus SetWorkSpace(gert::TilingContext *context, const char *nodeName)
{
    size_t *workSpaces = context->GetWorkspaceSizes(1);
    OP_TILING_CHECK(workSpaces == nullptr, OP_LOGE(nodeName, "workSpaces is nullptr."), return ge::GRAPH_FAILED);
    workSpaces[0] = SYSTEM_NEED_WORKSPACE;
    return ge::GRAPH_SUCCESS;
}

static ge::graphStatus ReduceScatterDetourTilingFuncImpl(gert::TilingContext *context)
{
    const char *nodeName = context->GetNodeName();
    ReduceScatterDetourTilingData *tilingData = context->GetTilingData<ReduceScatterDetourTilingData>();
    OP_TILING_CHECK(tilingData == nullptr, OP_LOGE(nodeName, "tilingData is nullptr."), return ge::GRAPH_FAILED);

    OP_TILING_CHECK(GetAttrAndSetTilingData(context, nodeName, *tilingData) != ge::GRAPH_SUCCESS,
        OP_LOGE(nodeName, "Get attr and set tiling data failed."),
        return ge::GRAPH_FAILED);
    
    OP_TILING_CHECK(SetWorkSpace(context, nodeName) != ge::GRAPH_SUCCESS,
        OP_LOGE(nodeName, "Tiling set workspace failed."),
        return ge::GRAPH_FAILED);
    if (!context->GetInputDesc(0)) {
        OP_LOGE(nodeName, "inputDesc is nullptr.");
        return ge::GRAPH_FAILED;
    }
    auto sendDtype = context->GetInputDesc(0)->GetDataType();
    if (sendDtype == ge::DT_FLOAT16) {
        context->SetTilingKey(TILING_KEY_FLOAT16);
    } else {
        OP_LOGE(nodeName, "input datatype is invalid, datatype should be float16, but is %d.",
            static_cast<ge::DataType>(sendDtype));
        return ge::GRAPH_FAILED;
    }

    uint32_t blockDim = 1U;
    auto ascendcPlatform = platform_ascendc::PlatformAscendC(context->GetPlatformInfo());
    uint32_t aivNum = ascendcPlatform.GetCoreNumAiv();
    blockDim = ascendcPlatform.CalcTschBlockDim(aivNum, 0, aivNum);
    context->SetBlockDim(blockDim);

    OP_LOGD(nodeName, "blockDim=%u", blockDim);
    PrintTilingDataInfo(nodeName, *tilingData);
    return ge::GRAPH_SUCCESS;
}

static ge::graphStatus ReduceScatterDetourTilingFunc(gert::TilingContext *context)
{
    ge::graphStatus ret = ReduceScatterDetourTilingFuncImpl(context);
    return ret;
}

struct ReduceScatterDetourCompileInfo {};
static ge::graphStatus TilingParseForReduceScatterDetour(gert::TilingParseContext *context)
{
    (void)context;
    return ge::GRAPH_SUCCESS;
}

IMPL_OP_OPTILING(ReduceScatterDetour)
    .Tiling(ReduceScatterDetourTilingFunc)
    .TilingParse<ReduceScatterDetourCompileInfo>(TilingParseForReduceScatterDetour);
}