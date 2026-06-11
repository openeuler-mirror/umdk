/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2026-2026. All rights reserved.
 * Description: MoeDispatchNormalZeroBuffer function implementation file
 * Create: 2026-06-10
 * Note:
 * History: 2026-06-10 create MoeDispatchNormalZeroBuffer function implementation file
 */
#include "kernel_operator.h"
#include "moe_dispatch_normal_zero_buffer_tiling.h"
#include "moe_dispatch_normal_zero_buffer.h"

using namespace AscendC;
using namespace MoeDispatchNormalZeroBufferImpl;

#define TILINGKEY_NO_QUANT 10000
#define TILINGKEY_QUANT 10002

extern "C" __global__ __aicore__ void moe_dispatch_normal_zero_buffer(
    GM_ADDR x, GM_ADDR expertIds, GM_ADDR send_token_idx, GM_ADDR put_offset, GM_ADDR expandXOut,
    GM_ADDR dynamicScalesOut, GM_ADDR assist_info_for_combine, GM_ADDR waitRecvCostStatsOut, GM_ADDR workspaceGM,
    GM_ADDR tilingGM)
{
    REGISTER_TILING_DEFAULT(MoeDispatchNormalZeroBufferTilingData);
    TPipe pipe;
#if (ORIG_DTYPE_RECV_X == DT_BF16 || ORIG_DTYPE_RECV_X == DT_FLOAT16)
    if (TILING_KEY_IS(TILINGKEY_NO_QUANT)) {
        GET_TILING_DATA_WITH_STRUCT(MoeDispatchNormalZeroBufferTilingData, tilingData, tilingGM);
        MoeDispatchNormalZeroBuffer<DTYPE_X, DTYPE_RECV_X, false, false, false> op;
        op.Init(x, expertIds, send_token_idx, put_offset, expandXOut, dynamicScalesOut, assist_info_for_combine,
                waitRecvCostStatsOut, workspaceGM, &pipe, &tilingData);
        op.Process();
        return;
    }
#elif (ORIG_DTYPE_RECV_X == DT_INT8)
    if (TILING_KEY_IS(TILINGKEY_QUANT)) {
        GET_TILING_DATA_WITH_STRUCT(MoeDispatchNormalZeroBufferTilingData, tilingData, tilingGM);
        MoeDispatchNormalZeroBuffer<DTYPE_X, DTYPE_RECV_X, true, false, false> op;
        op.Init(x, expertIds, send_token_idx, put_offset, expandXOut, dynamicScalesOut, assist_info_for_combine,
                waitRecvCostStatsOut, workspaceGM, &pipe, &tilingData);
        op.Process();
        return;
    }
#endif
}
