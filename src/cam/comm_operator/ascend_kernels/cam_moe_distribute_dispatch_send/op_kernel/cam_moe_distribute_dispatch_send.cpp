/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2026-2026. All rights reserved.
 * Description: cam_moe_distribute_dispatch_send implementation file
 * Create: 2026-09-17
 * Note:
 * History: 2026-09-17 port from cam_async repository
 */

#include "kernel_operator.h"
#include "op_def.h"  // GET_COMM_ARGS macro (defined in utils/op_kernel/op_def.h, copied into build op_kernel/ dir).
#include "cam_moe_distribute_dispatch_send_tiling.h"
#include "cam_moe_distribute_dispatch_send.h"

using namespace AscendC;
using namespace MoeDistributeDispatchImpl;
using namespace Cam;

extern "C" __global__ __aicore__ void cam_moe_distribute_dispatch_send(
    GM_ADDR x, GM_ADDR expertIds, GM_ADDR commArgs, GM_ADDR expandXOut,
    GM_ADDR workspaceGM, GM_ADDR tilingGM)
{
    REGISTER_TILING_DEFAULT(CamMoeDistributeDispatchSendTilingData);
    REGISTER_TILING_FOR_TILINGKEY("TILING_KEY_VAR < 2000000000", CamMoeDistributeDispatchSendTilingData);
    TPipe pipe;
    int32_t isCamComm = 1;
    GET_COMM_ARGS;
    GET_TILING_DATA_WITH_STRUCT(CamMoeDistributeDispatchSendTilingData, tilingData, tilingGM);

    int dynamicQuant = tilingData.moeDistributeDispatchInfo.dynamicQuant;

    if (TILING_KEY_IS(100)) {
        if (dynamicQuant == 0) {
            CamMoeDistributeDispatchSend<bfloat16_t, bfloat16_t, false> op;
            op.Init(x, expertIds, workspaceGM, &pipe, &tilingData, commArgs, isCamComm);
            op.Process();
        } else {
            CamMoeDistributeDispatchSend<bfloat16_t, int8_t, true> op;
            op.Init(x, expertIds, workspaceGM, &pipe, &tilingData, commArgs, isCamComm);
            op.Process();
        }
    } else if (TILING_KEY_IS(101)) {
        if (dynamicQuant == 0) {
            CamMoeDistributeDispatchSend<float16_t, float16_t, false> op;
            op.Init(x, expertIds, workspaceGM, &pipe, &tilingData, commArgs, isCamComm);
            op.Process();
        } else {
            CamMoeDistributeDispatchSend<float16_t, int8_t, true> op;
            op.Init(x, expertIds, workspaceGM, &pipe, &tilingData, commArgs, isCamComm);
            op.Process();
        }
    }
}
