/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2026-2026. All rights reserved.
 * Description: cam_moe_distribute_combine_recv implementation file
 * Create: 2026-09-17
 * Note:
 * History: 2026-09-17 port from cam_async repository
 */

#include "kernel_operator.h"
#include "op_def.h"  // GET_COMM_ARGS macro (defined in utils/op_kernel/op_def.h, copied into build op_kernel/ dir).
#include "lib/matmul_intf.h"
#include "cam_moe_distribute_combine_recv_tiling.h"
#include "cam_moe_distribute_combine_recv.h"

using namespace AscendC;
using namespace MoeDistributeCombineRecvImpl;
using namespace Cam;
extern "C" __global__ __aicore__ void cam_moe_distribute_combine_recv(
    GM_ADDR expandX, GM_ADDR expertIds, GM_ADDR expertScales, GM_ADDR commArgs,
    GM_ADDR xOut, GM_ADDR workspaceGM, GM_ADDR tilingGM)
{
    REGISTER_TILING_DEFAULT(CamMoeDistributeCombineRecvTilingData);
    REGISTER_TILING_FOR_TILINGKEY("TILING_KEY_VAR < 2000", CamMoeDistributeCombineRecvTilingData);
    TPipe pipe;
    int32_t isCamComm = 1;
    GET_COMM_ARGS;
    GET_TILING_DATA_WITH_STRUCT(CamMoeDistributeCombineRecvTilingData, tilingData, tilingGM);
    if (TILING_KEY_IS(100)) {
        CamMoeDistributeCombineRecv<bfloat16_t> op;
        op.Init(expandX, expertIds, expertScales, xOut, workspaceGM, &pipe, &tilingData, commArgs, isCamComm);
        op.Process();
    } else if (TILING_KEY_IS(101)) {
        CamMoeDistributeCombineRecv<float16_t> op;
        op.Init(expandX, expertIds, expertScales, xOut, workspaceGM, &pipe, &tilingData, commArgs, isCamComm);
        op.Process();
    }
}
