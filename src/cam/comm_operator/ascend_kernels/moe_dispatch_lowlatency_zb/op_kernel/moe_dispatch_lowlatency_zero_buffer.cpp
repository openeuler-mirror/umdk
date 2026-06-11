/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2026-2026. All rights reserved.
 * Description: MoeDispatchLowlatencyZeroBuffer function implementation file
 * Create: 2026-06-10
 * Note:
 * History: 2026-06-10 create MoeDispatchLowlatencyZeroBuffer function implementation file
 */
#include "kernel_operator.h"
#include "moe_dispatch_lowlatency_zero_buffer_tiling.h"
#include "moe_dispatch_lowlatency_zero_buffer.h"

using namespace AscendC;
using namespace MoeDispatchLowlatencyZeroBufferImpl;

extern "C" __global__ __aicore__ void moe_dispatch_lowlatency_zero_buffer(
    GM_ADDR x, GM_ADDR expertIds, GM_ADDR scales, GM_ADDR xActiveMask, GM_ADDR elasticInfo, GM_ADDR expandXOut,
    GM_ADDR dynamicScalesOut, GM_ADDR assistInfoOut, GM_ADDR expertTokenNumsOut, GM_ADDR epSendCountsOut,
    GM_ADDR tpSendCountsOut, GM_ADDR workspaceGM, GM_ADDR tilingGM)
{
    REGISTER_TILING_DEFAULT(MoeDispatchLowlatencyZeroBufferTilingData);
    TPipe pipe;
#if (ORIG_DTYPE_EXPAND_X == DT_BF16 || ORIG_DTYPE_EXPAND_X == DT_FLOAT16)
    // PRINTF("[--------- DISPATCH ---------] GETTING TILING KEY \n");
    if (TILING_KEY_IS(10000)) {
        GET_TILING_DATA_WITH_STRUCT(MoeDispatchLowlatencyZeroBufferTilingData, tilingData, tilingGM);
        MoeDispatchLowlatencyZeroBuffer<DTYPE_X, DTYPE_EXPAND_X, false, false, false, false> op;
        op.Init(x, expertIds, scales, xActiveMask, elasticInfo, expandXOut, dynamicScalesOut, assistInfoOut,
                expertTokenNumsOut, epSendCountsOut, tpSendCountsOut, workspaceGM, &pipe, &tilingData);
        op.Process();
        return;
    }
    if (TILING_KEY_IS(10100)) {
        GET_TILING_DATA_WITH_STRUCT(MoeDispatchLowlatencyZeroBufferTilingData, tilingData, tilingGM);
        MoeDispatchLowlatencyZeroBuffer<DTYPE_X, DTYPE_EXPAND_X, false, false, false, true> op;
        op.Init(x, expertIds, scales, xActiveMask, elasticInfo, expandXOut, dynamicScalesOut, assistInfoOut,
                expertTokenNumsOut, epSendCountsOut, tpSendCountsOut, workspaceGM, &pipe, &tilingData);
        op.Process();
        return;
    }
#elif (ORIG_DTYPE_EXPAND_X == DT_INT8)
    if (TILING_KEY_IS(10011)) {
        GET_TILING_DATA_WITH_STRUCT(MoeDispatchLowlatencyZeroBufferTilingData, tilingData, tilingGM);
        MoeDispatchLowlatencyZeroBuffer<DTYPE_X, DTYPE_EXPAND_X, true, false, false, false> op;
        op.Init(x, expertIds, scales, xActiveMask, elasticInfo, expandXOut, dynamicScalesOut, assistInfoOut,
                expertTokenNumsOut, epSendCountsOut, tpSendCountsOut, workspaceGM, &pipe, &tilingData);
        op.Process();
        return;
    }
    if (TILING_KEY_IS(10002)) {
        GET_TILING_DATA_WITH_STRUCT(MoeDispatchLowlatencyZeroBufferTilingData, tilingData, tilingGM);
        MoeDispatchLowlatencyZeroBuffer<DTYPE_X, DTYPE_EXPAND_X, false, true, false, false> op;
        op.Init(x, expertIds, scales, xActiveMask, elasticInfo, expandXOut, dynamicScalesOut, assistInfoOut,
                expertTokenNumsOut, epSendCountsOut, tpSendCountsOut, workspaceGM, &pipe, &tilingData);
        op.Process();
        return;
    }
    if (TILING_KEY_IS(10012)) {
        GET_TILING_DATA_WITH_STRUCT(MoeDispatchLowlatencyZeroBufferTilingData, tilingData, tilingGM);
        MoeDispatchLowlatencyZeroBuffer<DTYPE_X, DTYPE_EXPAND_X, false, true, true, false> op;
        op.Init(x, expertIds, scales, xActiveMask, elasticInfo, expandXOut, dynamicScalesOut, assistInfoOut,
                expertTokenNumsOut, epSendCountsOut, tpSendCountsOut, workspaceGM, &pipe, &tilingData);
        op.Process();
        return;
    }
    if (TILING_KEY_IS(10111)) {
        GET_TILING_DATA_WITH_STRUCT(MoeDispatchLowlatencyZeroBufferTilingData, tilingData, tilingGM);
        MoeDispatchLowlatencyZeroBuffer<DTYPE_X, DTYPE_EXPAND_X, true, false, false, true> op;
        op.Init(x, expertIds, scales, xActiveMask, elasticInfo, expandXOut, dynamicScalesOut, assistInfoOut,
                expertTokenNumsOut, epSendCountsOut, tpSendCountsOut, workspaceGM, &pipe, &tilingData);
        op.Process();
        return;
    }
    if (TILING_KEY_IS(10102)) {
        GET_TILING_DATA_WITH_STRUCT(MoeDispatchLowlatencyZeroBufferTilingData, tilingData, tilingGM);
        MoeDispatchLowlatencyZeroBuffer<DTYPE_X, DTYPE_EXPAND_X, false, true, false, true> op;
        op.Init(x, expertIds, scales, xActiveMask, elasticInfo, expandXOut, dynamicScalesOut, assistInfoOut,
                expertTokenNumsOut, epSendCountsOut, tpSendCountsOut, workspaceGM, &pipe, &tilingData);
        op.Process();
        return;
    }
    if (TILING_KEY_IS(10112)) {
        GET_TILING_DATA_WITH_STRUCT(MoeDispatchLowlatencyZeroBufferTilingData, tilingData, tilingGM);
        MoeDispatchLowlatencyZeroBuffer<DTYPE_X, DTYPE_EXPAND_X, false, true, true, true> op;
        op.Init(x, expertIds, scales, xActiveMask, elasticInfo, expandXOut, dynamicScalesOut, assistInfoOut,
                expertTokenNumsOut, epSendCountsOut, tpSendCountsOut, workspaceGM, &pipe, &tilingData);
        op.Process();
        return;
    }
#endif
}
