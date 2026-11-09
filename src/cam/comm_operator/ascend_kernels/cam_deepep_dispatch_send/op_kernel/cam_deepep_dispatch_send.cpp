/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2026-2026. All rights reserved.
 * Description: cam_deepep_dispatch_send kernel entry (runtime-parameterized)
 * Create: 2026-11-03
 * Note: every AFD control-plane pointer is now a tensor argument; sizes come
 *       from tiling, so one binary serves all model shapes.
 * History: 2026-11-03 create probe shell; 2026-11-03 call the runtime body;
 *          2026-11-03 real tensor interface (arg order follows the OpDef)
 */

#include "kernel_operator.h"
#include "cam_deepep_dispatch_send_tiling.h"
#include "cam_deepep_dispatch_send_rt.h"

using namespace Cam;

// The FP8 scale-factor gather (nddma builtins) is selected inside the body by
// num_sf_packs, so a BF16 launch never builds an empty descriptor.

static_assert(sizeof(CamDeepepDispatchSendTilingData) % 8 == 0,
              "tiling data must stay 8-byte aligned for the kernel copy");

// Argument order mirrors CamDeepepDispatchSend's OpDef inputs (x, sf, topk_idx,
// topk_weights, token_mask, task_info, context, control_buffer, round_ledger,
// workspace, jetty_ptrs), then the send_status output, then the framework
// workspace and tiling. The framework workspace is unused: deep_ep uses its
// own user-visible workspace tensor so the caller can carve it by layout.
extern "C" __global__ __aicore__ void cam_deepep_dispatch_send(GM_ADDR x, GM_ADDR sf,
    GM_ADDR topkIdx, GM_ADDR topkWeights, GM_ADDR tokenMask, GM_ADDR taskInfo,
    GM_ADDR context, GM_ADDR controlBuffer, GM_ADDR roundLedger, GM_ADDR afdWorkspace,
    GM_ADDR jettyPtrs, GM_ADDR sendStatus, GM_ADDR workspace, GM_ADDR tiling)
{
    // The AFD body is vector-only (SIMT VF_CALL + SyncAll over blockDim AIVs).
    // Without an explicit type bisheng compiles the entry as MIX and the kernel
    // is also queued on AIC cores, where the vector path is invalid.
    KERNEL_TASK_TYPE_DEFAULT(KERNEL_TYPE_AIV_ONLY);
    (void)workspace;

    REGISTER_TILING_DEFAULT(CamDeepepDispatchSendTilingData);
    GET_TILING_DATA_WITH_STRUCT(CamDeepepDispatchSendTilingData, tilingData, tiling);

    deep_ep::afd::rt::Params p{};
    p.num_ranks = tilingData.numRanks;
    p.num_experts = tilingData.numExperts;
    p.experts_per_rank = tilingData.expertsPerRank;
    p.num_topk = tilingData.numTopk;
    p.num_tokens_per_tile = tilingData.numTokensPerTile;
    p.num_vec_cores = tilingData.numVecCores;
    p.num_hidden_bytes = tilingData.numHiddenBytes;
    p.num_sf_packs = tilingData.numSFPacks;
    p.num_ub_bytes = tilingData.numUbBytes;
    p.timeout_cycles = tilingData.timeoutCycles;

    deep_ep::afd::rt::dispatch_body(p,
        reinterpret_cast<__gm__ void*>(x),
        reinterpret_cast<__gm__ deep_ep::sf_pack_t*>(sf),
        reinterpret_cast<__gm__ int64_t*>(topkIdx),
        reinterpret_cast<__gm__ float*>(topkWeights),
        reinterpret_cast<__gm__ uint8_t*>(tokenMask),
        reinterpret_cast<__gm__ const deep_ep::afd::AFDTaskInfo*>(taskInfo),
        reinterpret_cast<__gm__ const deep_ep::afd::AFDContextLayout*>(context),
        reinterpret_cast<__gm__ void*>(controlBuffer),
        reinterpret_cast<__gm__ deep_ep::afd::AFDRoundLedger*>(roundLedger),
        reinterpret_cast<__gm__ void*>(afdWorkspace),
        reinterpret_cast<__gm__ void*>(jettyPtrs),
        reinterpret_cast<__gm__ uint32_t*>(sendStatus),
        tilingData.sfTokenStride,
        tilingData.sfHiddenStride);
}
