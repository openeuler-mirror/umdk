/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2026-2026. All rights reserved.
 * Description: cam_deepep_combine_send kernel entry (runtime-parameterized)
 * Create: 2026-11-03
 * Note: sizes come from tiling; the TU holds exactly one __global__, so the AFD
 *       body is a __aicore__ device function.
 * History: 2026-11-03 create runtime parameter port;
 *          2026-11-03 real tensor interface (completion output)
 */

#include "kernel_operator.h"
#include "cam_deepep_combine_send_tiling.h"
#include "cam_deepep_combine_send_rt.h"

using namespace Cam;

static_assert(sizeof(CamDeepepCombineSendTilingData) % 8 == 0,
              "tiling data must stay 8-byte aligned for the kernel copy");

// Argument order mirrors CamDeepepCombineSend's OpDef inputs (x, src_metadata,
// context, active, control_buffer, execution_state, workspace, jetty_ptrs),
// then the completion output, then the framework workspace and tiling. The
// framework workspace is unused: the AFD workspace tensor is the caller-visible
// scratch the scheduler also references.
extern "C" __global__ __aicore__ void cam_deepep_combine_send(GM_ADDR x,
    GM_ADDR srcMetadata, GM_ADDR context, GM_ADDR active, GM_ADDR controlBuffer,
    GM_ADDR executionState, GM_ADDR afdWorkspace, GM_ADDR jettyPtrs,
    GM_ADDR completion, GM_ADDR workspace, GM_ADDR tiling)
{
    // The AFD body is vector-only (SyncAll over blockDim AIVs). Without an
    // explicit type bisheng compiles the entry as MIX and queues it on AIC too.
    KERNEL_TASK_TYPE_DEFAULT(KERNEL_TYPE_AIV_ONLY);
    (void)workspace;

    REGISTER_TILING_DEFAULT(CamDeepepCombineSendTilingData);
    GET_TILING_DATA_WITH_STRUCT(CamDeepepCombineSendTilingData, tilingData, tiling);

    deep_ep::afd::rt::CombineSendParams p{};
    p.num_src_ranks = tilingData.numSrcRanks;
    p.num_ranks = tilingData.numRanks;
    p.experts_per_rank = tilingData.expertsPerRank;
    p.num_topk = tilingData.numTopk;
    p.num_hidden = tilingData.numHidden;
    p.num_vec_cores = tilingData.numVecCores;
    p.num_source_lanes = tilingData.numSourceLanes;
    p.num_layers = tilingData.numLayers;
    p.max_padded_tokens = tilingData.maxPaddedTokens;
    p.num_tokens_per_tile = tilingData.numTokensPerTile;
    p.num_ub_bytes = tilingData.numUbBytes;
    p.rank_idx = tilingData.rankIdx;
    p.timeout_cycles = tilingData.timeoutCycles;

    deep_ep::afd::rt::combine_send_body(p,
        reinterpret_cast<__gm__ bfloat16_t*>(x),
        reinterpret_cast<__gm__ int*>(srcMetadata),
        reinterpret_cast<__gm__ const deep_ep::afd::AFDContextLayout*>(context),
        reinterpret_cast<__gm__ const deep_ep::afd::AFDActive*>(active),
        reinterpret_cast<__gm__ void*>(controlBuffer),
        reinterpret_cast<__gm__ deep_ep::afd::AFDExecutionState*>(executionState),
        reinterpret_cast<__gm__ void*>(afdWorkspace),
        reinterpret_cast<__gm__ void*>(jettyPtrs),
        reinterpret_cast<__gm__ deep_ep::afd::AFDCompletion*>(completion));
}
