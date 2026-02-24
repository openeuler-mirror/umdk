/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2026-2026. All rights reserved.
 * Description: all2all with detour function device implementation file
 * Create: 2026-01-22
 * Note:
 * History: 2026-01-22 create all2all with detour function file in device part
 */

#include "kernel_operator.h"
#include "all2all_small_fullmesh_with_detour.h"
#include "op_def.h"

#define TILING_KEY_FLOAT16 20
#define TILING_KEY_BFLOAT16 21
#define TILING_KEY_FLOAT 22
#define TILING_KEY_INT 23

extern "C" __global__ __aicore__ void all2_all_detour(
    GM_ADDR sendData, GM_ADDR commRankIds, GM_ADDR commArgs, GM_ADDR recvData, GM_ADDR workspace, GM_ADDR tiling)
{
    GET_TILING_DATA(tiling_data, tiling);
    int32_t isCamComm = 1;
    int64_t magic = tiling_data.magic;
    int64_t len = tiling_data.sendCount;
    uint32_t commRankSize = tiling_data.commRankCount;
    GM_ADDR input = sendData;
    GM_ADDR output = recvData;
    GET_COMM_ARGS;

    GM_ADDR scale = nullptr;
    int root = 0;
    int op = 0;
    int cycleCount = 0;
    int blockNum = GetBlockNum();
    int64_t scaleCount = 0;
    GM_ADDR offset = nullptr;

    if (TILING_KEY_IS(TILING_KEY_FLOAT16)) {
        All2AllSmallFullmeshWithDetour<float16_t> opKernel(rank, rankSize, extraFlag);
        opKernel.Init(KERNELS_ARGS_CALL_ALL2ALL, commRankIds, commRankSize);
        opKernel.Process();
    } else if (TILING_KEY_IS(TILING_KEY_BFLOAT16)) {
        All2AllSmallFullmeshWithDetour<bfloat16_t> opKernel(rank, rankSize, extraFlag);
        opKernel.Init(KERNELS_ARGS_CALL_ALL2ALL, commRankIds, commRankSize);
        opKernel.Process();
    } else if (TILING_KEY_IS(TILING_KEY_FLOAT)) {
        All2AllSmallFullmeshWithDetour<float> opKernel(rank, rankSize, extraFlag);
        opKernel.Init(KERNELS_ARGS_CALL_ALL2ALL, commRankIds, commRankSize);
        opKernel.Process();
    } else if (TILING_KEY_IS(TILING_KEY_INT)) {
        All2AllSmallFullmeshWithDetour<int> opKernel(rank, rankSize, extraFlag);
        opKernel.Init(KERNELS_ARGS_CALL_ALL2ALL, commRankIds, commRankSize);
        opKernel.Process();
    }
}