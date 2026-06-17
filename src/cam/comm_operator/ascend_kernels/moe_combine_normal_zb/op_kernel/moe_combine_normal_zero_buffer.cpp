/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2026-2026. All rights reserved.
 * Description: MoeCombineNormalZeroBuffer function implementation file
 * Create: 2026-06-10
 * Note:
 * History: 2026-06-10 create MoeCombineNormalZeroBuffer function implementation file
 */
#include "kernel_operator.h"
#include "lib/matmul_intf.h"
#include "moe_combine_normal_zero_buffer_tiling.h"
#include "moe_combine_normal_zero_buffer.h"
using namespace AscendC;
using namespace MoeCombineNormalZeroBufferImpl;

extern "C" __global__ __aicore__ void moe_combine_normal_zero_buffer(
    GM_ADDR recvX, GM_ADDR epRecvCount, GM_ADDR topkWeights, GM_ADDR topkIdx, GM_ADDR sendTokenIdx,
    GM_ADDR probGrad, GM_ADDR XOut, GM_ADDR sendCostStatsOut, GM_ADDR gradOut,
    GM_ADDR workspaceGM, GM_ADDR tilingGM)
{
    REGISTER_TILING_DEFAULT(MoeCombineNormalZeroBufferTilingData);
    TPipe pipe;

#if (ORIG_DTYPE_RECV_X == DT_BF16 || ORIG_DTYPE_RECV_X == DT_FLOAT16)
    GET_TILING_DATA_WITH_STRUCT(MoeCombineNormalZeroBufferTilingData, tilingData, tilingGM);
    MoeCombineNormalZeroBuffer<DTYPE_RECV_X, DTYPE_X, int32_t> op;
    op.Init(recvX, epRecvCount, topkWeights, topkIdx, sendTokenIdx, probGrad,
        XOut, sendCostStatsOut, gradOut, workspaceGM, &pipe, &tilingData);
    op.Process();
#endif
}
