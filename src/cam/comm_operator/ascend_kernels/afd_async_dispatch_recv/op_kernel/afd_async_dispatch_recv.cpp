/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2026-2026. All rights reserved.
 * Description: afd_async_dispatch_recv implementation file
 * Create: 2026-09-17
 * Note:
 * History: 2026-09-17 initial CAM port
 */

#include "kernel_operator.h"
#include "afd_async_dispatch_recv_tiling.h"
#include "afd_async_dispatch_recv.h"

using namespace AscendC;
using namespace AfdAsyncDispatchImpl;
using namespace Cam;

extern "C" __global__ __aicore__ void afd_async_dispatch_recv(
    GM_ADDR x, GM_ADDR commArgs,
    GM_ADDR expandXOut, GM_ADDR dynamicScalesOut,
    GM_ADDR batchInfoOut, GM_ADDR epRecvCountRoutedOut,
    GM_ADDR workspaceGM, GM_ADDR tilingGM)
{
    REGISTER_TILING_DEFAULT(AfdAsyncDispatchRecvTilingData);
    TPipe pipe;
    int32_t isCamComm = 1;
    GET_TILING_DATA_WITH_STRUCT(AfdAsyncDispatchRecvTilingData, tilingData, tilingGM);

    int dynamicQuant = tilingData.afdAsyncDispatchInfo.dynamicQuant;

    if (TILING_KEY_IS(100)) {
        if (dynamicQuant == 0) {
            AfdAsyncDispatchRecv<bfloat16_t, bfloat16_t, false> op;
            op.Init(x, expandXOut, dynamicScalesOut,
                batchInfoOut, epRecvCountRoutedOut,
                workspaceGM, &pipe, &tilingData, commArgs, isCamComm);
            op.Process();
        } else {
            AfdAsyncDispatchRecv<bfloat16_t, int8_t, true> op;
            op.Init(x, expandXOut, dynamicScalesOut,
                batchInfoOut, epRecvCountRoutedOut,
                workspaceGM, &pipe, &tilingData, commArgs, isCamComm);
            op.Process();
        }
    } else if (TILING_KEY_IS(101)) {
        if (dynamicQuant == 0) {
            AfdAsyncDispatchRecv<float16_t, float16_t, false> op;
            op.Init(x, expandXOut, dynamicScalesOut,
                batchInfoOut, epRecvCountRoutedOut,
                workspaceGM, &pipe, &tilingData, commArgs, isCamComm);
            op.Process();
        } else {
            AfdAsyncDispatchRecv<float16_t, int8_t, true> op;
            op.Init(x, expandXOut, dynamicScalesOut,
                batchInfoOut, epRecvCountRoutedOut,
                workspaceGM, &pipe, &tilingData, commArgs, isCamComm);
            op.Process();
        }
    }
}
