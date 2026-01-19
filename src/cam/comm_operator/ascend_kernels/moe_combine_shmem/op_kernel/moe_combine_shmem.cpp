/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2026-2026. All rights reserved.
 * Description: shmem combine function device implementation file
 * Create: 2026-01-06
 * Note:
 * History: 2026-01-06 create shmem combine function file in device part
 */

#include "kernel_operator.h"
#include "lib/matmul_intf.h"
#include "moe_combine_shmem.h"
#include "moe_combine_shmem_tiling.h"

using namespace AscendC;
using namespace MoeDistributeCombineImpl;

extern "C" __global__ __aicore__ void moe_combine_shmem(
    GM_ADDR expandX, GM_ADDR expertIds, GM_ADDR expandIdx, GM_ADDR epSendCount, GM_ADDR scales, GM_ADDR tpSendCount,
    GM_ADDR xActiveMask, GM_ADDR activationScale, GM_ADDR weightScale, GM_ADDR groupList, GM_ADDR expandScales,
    GM_ADDR XOut, GM_ADDR workspaceGM, GM_ADDR tilingGM)
{
    REGISTER_TILING_DEFAULT(MoeCombineShmemTilingData);
    TPipe pipe;

#if (ORIG_DTYPE_EXPAND_X == DT_BF16 || ORIG_DTYPE_EXPAND_X == DT_FLOAT16)
    if (TILING_KEY_IS(1100)) {  // tp=2
        GET_TILING_DATA_WITH_STRUCT(MoeCombineShmemTilingData, tilingData, tilingGM);
        MoeCombineShmem<DTYPE_EXPAND_X, int32_t, true, false> op;
        op.Init(expandX, expertIds, expandIdx, epSendCount, tpSendCount, scales, XOut, workspaceGM, &pipe, &tilingData);
        op.Process();
    } else if (TILING_KEY_IS(1000)) {  // tp=1
        GET_TILING_DATA_WITH_STRUCT(MoeCombineShmemTilingData, tilingData, tilingGM);
        MoeCombineShmem<DTYPE_EXPAND_X, int32_t, false, false> op;
        op.Init(expandX, expertIds, expandIdx, epSendCount, tpSendCount, scales, XOut, workspaceGM, &pipe, &tilingData);
        op.Process();
    } else if (TILING_KEY_IS(1020)) {  // tp=1, isQuant=true
        GET_TILING_DATA_WITH_STRUCT(MoeCombineShmemTilingData, tilingData, tilingGM);
        MoeCombineShmem<DTYPE_EXPAND_X, int32_t, false, true> op;
        op.Init(expandX, expertIds, expandIdx, epSendCount, tpSendCount, scales, XOut, workspaceGM, &pipe, &tilingData);
        op.Process();
    }
#endif
}
