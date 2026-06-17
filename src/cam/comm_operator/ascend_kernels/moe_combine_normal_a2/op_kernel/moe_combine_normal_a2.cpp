/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2026-2026. All rights reserved.
 * Description: combine normal A2 kernel part operator enterance
 * Create: 2026-01-15
 * Note:
 * History: 2026-01-15 create combine normal A2 kernel part operator enterance
 */

#include <cstdio>
#include "kernel_operator.h"
#include "moe_combine_normal_a2_tiling.h"
#include "moe_combine_normal_a2_layered.h"

using namespace AscendC;
using namespace MoeCombineNormalA2Impl;
using namespace Moe;
extern "C" __global__ __aicore__ void moe_combine_normal_a2(
    GM_ADDR expandX, GM_ADDR expertIds, GM_ADDR expandIdx, GM_ADDR epSendCount, GM_ADDR scales, GM_ADDR tpSendCount,
    GM_ADDR xActiveMask, GM_ADDR activationScale, GM_ADDR weightScale, GM_ADDR groupList, GM_ADDR expandScales,
    GM_ADDR offsetInner, GM_ADDR offsetOuter, GM_ADDR countOuter, GM_ADDR XOut, GM_ADDR workspaceGM, GM_ADDR tilingGM)

{
    REGISTER_TILING_DEFAULT(MoeCombineNormalA2TilingData);
#if (ORIG_DTYPE_EXPAND_X == DT_BF16 || ORIG_DTYPE_EXPAND_X == DT_FLOAT16)
    TPipe pipe;
    if (TILING_KEY_IS(3000)) {
        GET_TILING_DATA_WITH_STRUCT(MoeCombineNormalA2TilingData, tilingData, tilingGM);
        auto tiling = (__gm__ MoeCombineNormalA2TilingData *)tilingGM;
        __gm__ void *mc2InitTiling = (__gm__ void *)(&(tiling->mc2InitTiling));
        __gm__ void *mc2CcTiling = (__gm__ void *)(&(tiling->mc2CcTiling));
        MoeCombineNormalA2Layered<DTYPE_EXPAND_X, int32_t> op;
        op.Init(expandX, expandIdx, epSendCount, offsetInner, offsetOuter, countOuter, expandScales, XOut, workspaceGM,
                &pipe, &tilingData, mc2InitTiling, mc2CcTiling);
        op.Process();
    }
#endif
}
