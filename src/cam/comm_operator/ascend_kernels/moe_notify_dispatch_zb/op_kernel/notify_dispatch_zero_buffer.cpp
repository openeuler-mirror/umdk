/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2026-2026. All rights reserved.
 * Description: NotifyDispatchZeroBuffer function implementation file
 * Create: 2026-06-10
 * Note:
 * History: 2026-06-10 create NotifyDispatchZeroBuffer function implementation file
 */
#include "kernel_operator.h"
#include "notify_dispatch_zero_buffer_tiling.h"
#include "notify_dispatch_zero_buffer.h"

#define TILING_KEY_INT_ZERO_BUFFER 223

#define KERNEL_USE_WORKSPACE (1 * 1024 * 1024)

extern "C" __global__ __aicore__ void notify_dispatch_zero_buffer(GM_ADDR tokenPerExpertData, GM_ADDR recvData,
    GM_ADDR totalRecvTokens, GM_ADDR maxBs, GM_ADDR recvTokensPerExpert, GM_ADDR putOffset, GM_ADDR workspace,
    GM_ADDR tiling)
{
    REGISTER_TILING_DEFAULT(NotifyDispatchZeroBufferTilingData);
    GET_TILING_DATA_WITH_STRUCT(NotifyDispatchZeroBufferTilingData, tilingData, tiling);
    int64_t len = tilingData.notifyDispatchInfo.sendCount;
    int localRank = tilingData.notifyDispatchInfo.localRankId;
    int localRankSize = tilingData.notifyDispatchInfo.localRankSize;
    int rank = tilingData.notifyDispatchInfo.rankId;
    int rankSize = tilingData.notifyDispatchInfo.rankSize;
    uint32_t topkNum = tilingData.notifyDispatchInfo.topkNum;
    uint64_t zeroBufferPtr = tilingData.zeroBufferPtr;

    GM_ADDR tokenPerExpertDataInput = tokenPerExpertData;
    GM_ADDR recvDataOutput = recvData;

    // fill in unused args
    uint32_t extraFlag = 0;
    GM_ADDR scale = nullptr;
    int root = 0;
    int op = 0;
    int cycleCount = 0;
    int64_t scaleCount = 0;
    GM_ADDR offset = nullptr;
    int blockNum = GetBlockNum();
    if (TILING_KEY_IS(TILING_KEY_INT_ZERO_BUFFER)) {
        NotifyDispatchZeroBuffer<int> opKernel(rank, rankSize, extraFlag);
        opKernel.Init(KERNELS_ARGS_CALL_ALLGATHER());
        opKernel.Process();
    }
}
