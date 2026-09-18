/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2026-2026. All rights reserved.
 * Description: cam_moe_distribute_dispatch_recv implementation file
 * Create: 2026-09-17
 * Note:
 * History: 2026-09-17 port from cam_async repository
 */

#include "kernel_operator.h"
#include "cam_moe_distribute_dispatch_recv_tiling.h"
#include "cam_moe_distribute_dispatch_recv.h"

using namespace AscendC;
using namespace MoeDistributeDispatchImpl;
using namespace Cam;

extern "C" __global__ __aicore__ void cam_moe_distribute_dispatch_recv(
    GM_ADDR x, GM_ADDR commArgs,
    GM_ADDR expandXOut, GM_ADDR expandXOutShared, GM_ADDR dynamicScalesOut, GM_ADDR dynamicScalesShared,
    GM_ADDR batchInfoOut, GM_ADDR epRecvCountRoutedOut, GM_ADDR epRecvCountSharedOut,
    GM_ADDR workspaceGM, GM_ADDR tilingGM)
{
    REGISTER_TILING_DEFAULT(CamMoeDistributeDispatchRecvTilingData);
    TPipe pipe;
    int32_t isCamComm = 1;
    GET_TILING_DATA_WITH_STRUCT(CamMoeDistributeDispatchRecvTilingData, tilingData, tilingGM);

    int dynamicQuant = tilingData.moeDistributeDispatchInfo.dynamicQuant;

    if (TILING_KEY_IS(100)) {
        if (dynamicQuant == 0) {
            CamMoeDistributeDispatchRecv<bfloat16_t, bfloat16_t, false> op;
            op.Init(x, expandXOut, expandXOutShared, dynamicScalesOut, dynamicScalesShared,
                batchInfoOut, epRecvCountRoutedOut, epRecvCountSharedOut,
                workspaceGM, &pipe, &tilingData, commArgs, isCamComm);
            op.Process();
        } else {
            CamMoeDistributeDispatchRecv<bfloat16_t, int8_t, true> op;
            op.Init(x, expandXOut, expandXOutShared, dynamicScalesOut, dynamicScalesShared,
                batchInfoOut, epRecvCountRoutedOut, epRecvCountSharedOut,
                workspaceGM, &pipe, &tilingData, commArgs, isCamComm);
            op.Process();
        }
    } else if (TILING_KEY_IS(101)) {
        if (dynamicQuant == 0) {
            CamMoeDistributeDispatchRecv<float16_t, float16_t, false> op;
            op.Init(x, expandXOut, expandXOutShared, dynamicScalesOut, dynamicScalesShared,
                batchInfoOut, epRecvCountRoutedOut, epRecvCountSharedOut,
                workspaceGM, &pipe, &tilingData, commArgs, isCamComm);
            op.Process();
        } else {
            CamMoeDistributeDispatchRecv<float16_t, int8_t, true> op;
            op.Init(x, expandXOut, expandXOutShared, dynamicScalesOut, dynamicScalesShared,
                batchInfoOut, epRecvCountRoutedOut, epRecvCountSharedOut,
                workspaceGM, &pipe, &tilingData, commArgs, isCamComm);
            op.Process();
        }
    }
}
