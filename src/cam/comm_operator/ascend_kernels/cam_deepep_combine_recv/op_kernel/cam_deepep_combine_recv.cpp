/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2026-2026. All rights reserved.
 * Description: cam_deepep_combine_recv kernel entry (runtime-parameterized)
 * Create: 2026-11-03
 * Note: sizes come from tiling; the TU holds exactly one __global__, so the AFD
 *       body is a __aicore__ device function.
 * History: 2026-11-03 create runtime parameter port;
 *          2026-11-03 real tensor interface (arg order follows the OpDef)
 */

#include "kernel_operator.h"
#include "cam_deepep_combine_recv_tiling.h"
#include "cam_deepep_combine_recv_rt.h"

using namespace Cam;

static_assert(sizeof(CamDeepepCombineRecvTilingData) % 8 == 0,
              "tiling data must stay 8-byte aligned for the kernel copy");

// Argument order mirrors CamDeepepCombineRecv's OpDef inputs (payload,
// task_info, context, control_buffer, round_ledger, workspace, token_mask),
// then the combined_x / combined_topk_idx / topk_weights / recv_status /
// return_progress outputs, then the framework workspace and tiling.
extern "C" __global__ __aicore__ void cam_deepep_combine_recv(GM_ADDR payload,
    GM_ADDR taskInfo, GM_ADDR context, GM_ADDR controlBuffer, GM_ADDR roundLedger,
    GM_ADDR afdWorkspace, GM_ADDR tokenMask, GM_ADDR combinedX, GM_ADDR combinedTopkIdx,
    GM_ADDR topkWeights, GM_ADDR recvStatus, GM_ADDR returnProgress, GM_ADDR workspace,
    GM_ADDR tiling)
{
    // The AFD body is vector-only (SyncAll over blockDim AIVs). Without an
    // explicit type bisheng compiles the entry as MIX and queues it on AIC too.
    KERNEL_TASK_TYPE_DEFAULT(KERNEL_TYPE_AIV_ONLY);
    (void)workspace;

    REGISTER_TILING_DEFAULT(CamDeepepCombineRecvTilingData);
    GET_TILING_DATA_WITH_STRUCT(CamDeepepCombineRecvTilingData, tilingData, tiling);

    deep_ep::afd::rt::CombineRecvParams p{};
    p.num_experts = tilingData.numExperts;
    p.num_ranks = tilingData.numRanks;
    p.num_topk = tilingData.numTopk;
    p.num_hidden = tilingData.numHidden;
    p.num_hidden_chunk = tilingData.numHiddenChunk;
    p.num_vec_cores = tilingData.numVecCores;
    p.num_ub_bytes = tilingData.numUbBytes;
    p.round_step = tilingData.roundStep;
    p.start = tilingData.start;
    p.timeout_cycles = tilingData.timeoutCycles;

    deep_ep::afd::rt::combine_recv_body(p,
        reinterpret_cast<__gm__ bfloat16_t*>(combinedX),
        reinterpret_cast<__gm__ int64_t*>(combinedTopkIdx),
        reinterpret_cast<__gm__ float*>(topkWeights),
        reinterpret_cast<__gm__ uint8_t*>(tokenMask),
        reinterpret_cast<__gm__ uint8_t*>(payload),
        reinterpret_cast<__gm__ const deep_ep::afd::AFDTaskInfo*>(taskInfo),
        reinterpret_cast<__gm__ const deep_ep::afd::AFDContextLayout*>(context),
        reinterpret_cast<__gm__ void*>(controlBuffer),
        reinterpret_cast<__gm__ deep_ep::afd::AFDRoundLedger*>(roundLedger),
        reinterpret_cast<__gm__ void*>(afdWorkspace),
        reinterpret_cast<__gm__ uint32_t*>(recvStatus),
        reinterpret_cast<__gm__ deep_ep::afd::AFDReturnProgress*>(returnProgress));
}
