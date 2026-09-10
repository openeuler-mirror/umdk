/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2026-2026. All rights reserved.
 * Description: MoeDispatchNormalZb function implementation file
 * Create: 2026-06-10
 * Note:
 * History: 2026-06-10 create MoeDispatchNormalZb function implementation file
 */
#include "kernel_operator.h"
#include "moe_dispatch_normal_zb_tiling.h"
#include "moe_dispatch_normal_zb.h"

using namespace AscendC;
using namespace MoeDispatchNormalZbImpl;

#define TILINGKEY_NO_QUANT 10000
#define TILINGKEY_QUANT 10002

extern "C" __global__ __aicore__ void moe_dispatch_normal_zb(
    GM_ADDR x, GM_ADDR topkIdx, GM_ADDR sendTokenIdx, GM_ADDR putOffset, GM_ADDR recvX,
    GM_ADDR recvXScales, GM_ADDR workspaceGM, GM_ADDR tilingGM)
{
    REGISTER_TILING_DEFAULT(MoeDispatchNormalZbTilingData);
    TPipe pipe;
#if (ORIG_DTYPE_RECV_X == DT_BF16 || ORIG_DTYPE_RECV_X == DT_FLOAT16)
    if (TILING_KEY_IS(TILINGKEY_NO_QUANT)) {
        GET_TILING_DATA_WITH_STRUCT(MoeDispatchNormalZbTilingData, tilingData, tilingGM);
        MoeDispatchNormalZb<DTYPE_X, DTYPE_RECV_X, false, false, false> op;
        op.Init(x, topkIdx, sendTokenIdx, putOffset, recvX, recvXScales, workspaceGM, &pipe,
                &tilingData);
        op.Process();
        return;
    }
#elif (ORIG_DTYPE_RECV_X == DT_INT8)
    if (TILING_KEY_IS(TILINGKEY_QUANT)) {
        GET_TILING_DATA_WITH_STRUCT(MoeDispatchNormalZbTilingData, tilingData, tilingGM);
        MoeDispatchNormalZb<DTYPE_X, DTYPE_RECV_X, true, false, false> op;
        op.Init(x, topkIdx, sendTokenIdx, putOffset, recvX, recvXScales, workspaceGM, &pipe,
                &tilingData);
        op.Process();
        return;
    }
#endif
}
