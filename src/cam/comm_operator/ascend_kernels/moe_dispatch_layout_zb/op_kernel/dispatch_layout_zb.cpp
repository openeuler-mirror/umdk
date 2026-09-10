/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2026-2026. All rights reserved.
 * Description: dispatch layout function implementation file
 * Create: 2026-06-10
 * Note:
 * History: 2026-06-10 create dispatch layout function implementation file
 */
#include "kernel_operator.h"
#include "dispatch_layout_zb_tiling.h"
#include "dispatch_layout_zb.h"

#define TILING_KEY_INT 23

extern "C" __global__ __aicore__ void dispatch_layout_zb(GM_ADDR topkIdx, GM_ADDR numTokensPerRank,
    GM_ADDR numTokensPerExpert, GM_ADDR isTokenInRank, GM_ADDR notifySendData, GM_ADDR sendTokenIdx,
    GM_ADDR workspace, GM_ADDR tiling)
{
    REGISTER_TILING_DEFAULT(DispatchLayoutTilingData);
    GET_TILING_DATA_WITH_STRUCT(DispatchLayoutTilingData, tilingData, tiling);

    TPipe pipe;

    if (TILING_KEY_IS(TILING_KEY_INT)) {
        MoeDispatchLayout::DispatchLayout<int32_t> op;
        op.Init(topkIdx, numTokensPerRank, numTokensPerExpert, isTokenInRank, notifySendData, sendTokenIdx,
                workspace, &pipe, &tilingData);
        op.Process();
    }
}
