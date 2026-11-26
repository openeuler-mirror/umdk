/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2026-2026. All rights reserved.
 * Description: afd_async_combine_recv implementation file
 * Create: 2026-09-17
 * Note:
 * History: 2026-09-17 initial CAM port
 */

#include "kernel_operator.h"
#include "lib/matmul_intf.h"
#include "afd_async_combine_recv_tiling.h"
#include "afd_async_combine_recv.h"

using namespace AscendC;
using namespace AfdAsyncCombineRecvImpl;
using namespace Cam;
extern "C" __global__ __aicore__ void afd_async_combine_recv(
    GM_ADDR expandX, GM_ADDR expertIds, GM_ADDR expertScales, GM_ADDR commArgs,
    GM_ADDR xOut, GM_ADDR workspaceGM, GM_ADDR tilingGM)
{
    REGISTER_TILING_DEFAULT(AfdAsyncCombineRecvTilingData);
    REGISTER_TILING_FOR_TILINGKEY("TILING_KEY_VAR < 2000", AfdAsyncCombineRecvTilingData);
    TPipe pipe;
    int32_t isCamComm = 1;
    GET_TILING_DATA_WITH_STRUCT(AfdAsyncCombineRecvTilingData, tilingData, tilingGM);
    if (TILING_KEY_IS(100)) {
        AfdAsyncCombineRecv<bfloat16_t, false> op;
        op.Init(expandX, expertIds, expertScales, xOut, workspaceGM, &pipe, &tilingData, commArgs, isCamComm);
        op.Process();
    } else if (TILING_KEY_IS(101)) {
        AfdAsyncCombineRecv<float16_t, false> op;
        op.Init(expandX, expertIds, expertScales, xOut, workspaceGM, &pipe, &tilingData, commArgs, isCamComm);
        op.Process();
    } else if (TILING_KEY_IS(102)) {
        AfdAsyncCombineRecv<bfloat16_t, true> op;
        op.Init(expandX, expertIds, expertScales, xOut, workspaceGM, &pipe, &tilingData, commArgs, isCamComm);
        op.Process();
    } else if (TILING_KEY_IS(103)) {
        AfdAsyncCombineRecv<float16_t, true> op;
        op.Init(expandX, expertIds, expertScales, xOut, workspaceGM, &pipe, &tilingData, commArgs, isCamComm);
        op.Process();
    }
}
