/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2026-2026. All rights reserved.
 * Description: cam_moe_distribute_combine_send implementation file
 * Create: 2026-09-17
 * Note:
 * History: 2026-09-17 port from cam_async repository
 */

#include "kernel_operator.h"
#include "lib/matmul_intf.h"
#include "cam_moe_distribute_combine_send_tiling.h"
#include "cam_moe_distribute_combine_send.h"

using namespace AscendC;
using namespace MoeDistributeCombineSendImpl;
using namespace Cam;
extern "C" __global__ __aicore__ void cam_moe_distribute_combine_send(
    GM_ADDR expandX, GM_ADDR commArgs, GM_ADDR batchInfo,
    GM_ADDR XOut, GM_ADDR workspaceGM, GM_ADDR tilingGM)
{
    REGISTER_TILING_DEFAULT(CamMoeDistributeCombineSendTilingData);
    REGISTER_TILING_FOR_TILINGKEY("TILING_KEY_VAR < 2000", CamMoeDistributeCombineSendTilingData);
    TPipe pipe;
    int32_t isCamComm = 1;
    GET_TILING_DATA_WITH_STRUCT(CamMoeDistributeCombineSendTilingData, tilingData, tilingGM);
    if (TILING_KEY_IS(100)) {
        CamMoeDistributeCombineSend<bfloat16_t> op;
        op.Init(expandX, workspaceGM, &pipe, &tilingData, commArgs, batchInfo, isCamComm);
        op.Process();
    } else if (TILING_KEY_IS(101)) {
        CamMoeDistributeCombineSend<float16_t> op;
        op.Init(expandX, workspaceGM, &pipe, &tilingData, commArgs, batchInfo, isCamComm);
        op.Process();
    }
}
