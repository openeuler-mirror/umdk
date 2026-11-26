/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2026-2026. All rights reserved.
 * Description: afd_async_combine_send implementation file
 * Create: 2026-09-17
 * Note:
 * History: 2026-09-17 initial CAM port
 */

#include "kernel_operator.h"
#include "lib/matmul_intf.h"
#include "afd_async_combine_send_tiling.h"
#include "afd_async_combine_send.h"

using namespace AscendC;
using namespace AfdAsyncCombineSendImpl;
using namespace Cam;
extern "C" __global__ __aicore__ void afd_async_combine_send(
    GM_ADDR expandX, GM_ADDR commArgs, GM_ADDR batchInfo,
    GM_ADDR XOut, GM_ADDR workspaceGM, GM_ADDR tilingGM)
{
    REGISTER_TILING_DEFAULT(AfdAsyncCombineSendTilingData);
    REGISTER_TILING_FOR_TILINGKEY("TILING_KEY_VAR < 2000", AfdAsyncCombineSendTilingData);
    TPipe pipe;
    int32_t isCamComm = 1;
    GET_TILING_DATA_WITH_STRUCT(AfdAsyncCombineSendTilingData, tilingData, tilingGM);
    if (TILING_KEY_IS(100)) {
        AfdAsyncCombineSend<bfloat16_t> op;
        op.Init(expandX, workspaceGM, &pipe, &tilingData, commArgs, batchInfo, isCamComm);
        op.Process();
    } else if (TILING_KEY_IS(101)) {
        AfdAsyncCombineSend<float16_t> op;
        op.Init(expandX, workspaceGM, &pipe, &tilingData, commArgs, batchInfo, isCamComm);
        op.Process();
    }
}
