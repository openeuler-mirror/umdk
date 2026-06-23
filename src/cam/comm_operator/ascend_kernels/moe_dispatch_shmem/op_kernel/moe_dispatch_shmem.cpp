/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2026-2026. All rights reserved.
 * Description: shmem dispatch function device implementation file
 * Create: 2026-01-06
 * Note:
 * History: 2026-01-06 create shmem dispatch function file in device part
 */

#include "kernel_operator.h"
#include "moe_dispatch_shmem.h"
#include "moe_dispatch_shmem_tiling.h"

using namespace AscendC;
using namespace MoeDistributeDispatchImpl;

/*
 * A3 tilingKey description
 * 5-digit decimal number
 * 1st digit (ones): quantMode:
 *     0: no quantization, 1: static quantization, 2: dynamic quantization
 * 2nd digit (tens): whether smoothScale exists:
 *     0: no, 1: yes
 * 3rd digit (hundreds): whether to do tp-domain allgather:
 *     0: no, 1: yes
 * 4th digit (thousands): whether it is a shared expert card:
 *     0: no, 1: yes
 * 5th digit (ten-thousands): no actual meaning
 */

extern "C" __global__ __aicore__ void moe_dispatch_shmem(GM_ADDR x, GM_ADDR expertIds, GM_ADDR scales,
                                                                    GM_ADDR xActiveMask, GM_ADDR expandXOut,
                                                                    GM_ADDR dynamicScalesOut, GM_ADDR expandIdxOut,
                                                                    GM_ADDR expertTokenNumsOut, GM_ADDR epSendCountsOut,
                                                                    GM_ADDR tpSendCountsOut, GM_ADDR workspaceGM,
                                                                    GM_ADDR tilingGM)
{
    REGISTER_TILING_DEFAULT(MoeDispatchShmemTilingData);
    TPipe pipe;
#if (ORIG_DTYPE_EXPAND_X == DT_BF16 || ORIG_DTYPE_EXPAND_X == DT_FLOAT16)
    if (TILING_KEY_IS(1000)) {
        GET_TILING_DATA_WITH_STRUCT(MoeDispatchShmemTilingData, tilingData, tilingGM);
        MoeDispatchShmem<DTYPE_X, DTYPE_EXPAND_X, false, false, false, false> op;
        op.Init(x, expertIds, scales, expandXOut, dynamicScalesOut, expandIdxOut, expertTokenNumsOut, epSendCountsOut,
                tpSendCountsOut, workspaceGM, &pipe, &tilingData);
        op.Process();
    } else if (TILING_KEY_IS(1100)) {
        GET_TILING_DATA_WITH_STRUCT(MoeDispatchShmemTilingData, tilingData, tilingGM);
        MoeDispatchShmem<DTYPE_X, DTYPE_EXPAND_X, false, false, false, true> op;
        op.Init(x, expertIds, scales, expandXOut, dynamicScalesOut, expandIdxOut, expertTokenNumsOut, epSendCountsOut,
                tpSendCountsOut, workspaceGM, &pipe, &tilingData);
        op.Process();
    }
#elif (ORIG_DTYPE_EXPAND_X == DT_INT8)
    if (TILING_KEY_IS(1002)) {
        GET_TILING_DATA_WITH_STRUCT(MoeDispatchShmemTilingData, tilingData, tilingGM);
        MoeDispatchShmem<DTYPE_X, DTYPE_EXPAND_X, false, true, false, false> op;
        op.Init(x, expertIds, scales, expandXOut, dynamicScalesOut, expandIdxOut, expertTokenNumsOut, epSendCountsOut,
                tpSendCountsOut, workspaceGM, &pipe, &tilingData);
        op.Process();
    } else if (TILING_KEY_IS(1102)) {
        GET_TILING_DATA_WITH_STRUCT(MoeDispatchShmemTilingData, tilingData, tilingGM);
        MoeDispatchShmem<DTYPE_X, DTYPE_EXPAND_X, false, true, false, true> op;
        op.Init(x, expertIds, scales, expandXOut, dynamicScalesOut, expandIdxOut, expertTokenNumsOut, epSendCountsOut,
                tpSendCountsOut, workspaceGM, &pipe, &tilingData);
        op.Process();
    }
#endif
}
