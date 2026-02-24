/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2026-2026. All rights reserved.
 * Description: all2all with detour function device implementation file
 * Create: 2026-01-22
 * Note:
 * History: 2026-01-22 create all2all with detour function file in device part
 */

#include "kernel_operator.h"
#include "reduce_scatter_detour.h"
#include "reduce_scatter_detour_tiling.h"

#define TILING_KEY_FLOAT16 20

using namespace Cam;

extern "C" __global__ __aicore__ void reduce_scatter_detour(
    GM_ADDR input, GM_ADDR commRankIds, GM_ADDR commArgs, GM_ADDR output, GM_ADDR workspace, GM_ADDR tiling)
{
    REGISTER_TILING_DEFAULT(ReduceScatterDetourTilingData);

    GET_TILING_DATA_WITH_STRUCT(ReduceScatterDetourTilingData, tilingData, tiling);

    int32_t isCamComm = 1;
    AscendC::GlobalTensor<int32_t> commArgsGm;
    commArgsGm.SetGlobalBuffer(reinterpret_cast<__gm__ int32_t *>(commArgs), 6);
    int32_t rank = commArgsGm.GetValue(0);
    int32_t rankSize = commArgsGm.GetValue(2);

    int32_t op = tilingData.op;
    int64_t magic = tilingData.magic;
    uint32_t commRankSize = tilingData.commRankCount;
    int64_t len = tilingData.sendCount / commRankSize;

    uint32_t extraFlag = 0;
    GM_ADDR scale = nullptr;
    int32_t root = 0;
    int32_t cycleCount = 0;
    int64_t scaleCount = 0;
    GM_ADDR offset = nullptr;

    if (TILING_KEY_IS(TILING_KEY_FLOAT16)) {
        ReduceScatterWithDetour<float16_t, float> opKernel(rank, rankSize, extraFlag);
        opKernel.Init(KERNELS_ARGS_CALL_MIX, commRankIds, commRankSize);
        opKernel.Process();
    }
}