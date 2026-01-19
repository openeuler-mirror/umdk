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
 * A3 tilingkey说明
 * 5位的十进制数
 * 第1位（个位）：quantMode:
 *     0: 不量化, 1: 静态量化, 2: 动态量化
 * 第2位（十位）：是否有smoothScale:
 *     0: 无, 1: 有
 * 第3位（百位）：是否做tp域allgather:
 *     0: 不做, 1: 做
 * 第4位（千位）：是否是共享专家卡:
 *     0: 不是, 1: 是
 * 第5位（万位）：无实际意义
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
