/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2026-2026. All rights reserved.
 * Description: cam_deepep_dispatch_recv kernel entry (runtime-parameterized)
 * Create: 2026-11-03
 * Note: sizes come from tiling; the TU holds exactly one __global__, so the AFD
 *       body is a __aicore__ device function.
 * History: 2026-11-03 create runtime parameter port;
 *          2026-11-03 real tensor interface (arg order follows the OpDef)
 */

#include "kernel_operator.h"
#include "cam_deepep_dispatch_recv_tiling.h"
#include "cam_deepep_dispatch_recv_rt.h"

using namespace Cam;

static_assert(sizeof(CamDeepepDispatchRecvTilingData) % 8 == 0,
              "tiling data must stay 8-byte aligned for the kernel copy");

// Argument order mirrors CamDeepepDispatchRecv's OpDef inputs (payload,
// context, active, execution_state, workspace, control_buffer), then the
// recv_x / recv_sf / recv_src_metadata outputs, then the framework workspace
// and tiling. The framework workspace is unused: the AFD workspace tensor is
// the caller-visible scratch the scheduler also references.
extern "C" __global__ __aicore__ void cam_deepep_dispatch_recv(GM_ADDR payload,
    GM_ADDR context, GM_ADDR active, GM_ADDR executionState, GM_ADDR afdWorkspace,
    GM_ADDR controlBuffer, GM_ADDR recvX, GM_ADDR recvSf, GM_ADDR recvSrcMetadata,
    GM_ADDR workspace, GM_ADDR tiling)
{
    // The AFD body is vector-only (SyncAll over blockDim AIVs). Without an
    // explicit type bisheng compiles the entry as MIX and queues it on AIC too.
    KERNEL_TASK_TYPE_DEFAULT(KERNEL_TYPE_AIV_ONLY);
    (void)workspace;

    REGISTER_TILING_DEFAULT(CamDeepepDispatchRecvTilingData);
    GET_TILING_DATA_WITH_STRUCT(CamDeepepDispatchRecvTilingData, tilingData, tiling);

    deep_ep::afd::rt::DispatchRecvParams p{};
    p.num_ranks = tilingData.numRanks;
    p.num_experts = tilingData.numExperts;
    p.experts_per_rank = tilingData.expertsPerRank;
    p.num_topk = tilingData.numTopk;
    p.num_vec_cores = tilingData.numVecCores;
    p.num_hidden_bytes = tilingData.numHiddenBytes;
    p.num_sf_packs = tilingData.numSFPacks;
    p.num_source_lanes = tilingData.numSourceLanes;
    p.num_layers = tilingData.numLayers;
    p.max_expanded_tokens = tilingData.maxExpandedTokens;
    p.max_padded_tokens = tilingData.maxPaddedTokens;
    p.expert_alignment = tilingData.expertAlignment;
    p.num_tokens_per_stage = tilingData.numTokensPerStage;
    p.num_ub_bytes = tilingData.numUbBytes;
    p.rank_idx = tilingData.rankIdx;
    p.recv_sf_token_stride = tilingData.recvSfTokenStride;
    p.recv_sf_hidden_stride = tilingData.recvSfHiddenStride;
    p.payload_bytes = tilingData.payloadBytes;
    p.control_bytes = tilingData.controlBytes;
    p.context_bytes = tilingData.contextBytes;

    deep_ep::afd::rt::dispatch_recv_body(p,
        reinterpret_cast<__gm__ void*>(payload),
        reinterpret_cast<__gm__ const deep_ep::afd::AFDContextLayout*>(context),
        reinterpret_cast<__gm__ const deep_ep::afd::AFDActive*>(active),
        reinterpret_cast<__gm__ deep_ep::afd::AFDExecutionState*>(executionState),
        reinterpret_cast<__gm__ void*>(afdWorkspace),
        reinterpret_cast<__gm__ void*>(recvX),
        reinterpret_cast<__gm__ int16_t*>(recvSf),
        reinterpret_cast<__gm__ int*>(recvSrcMetadata),
        reinterpret_cast<__gm__ void*>(controlBuffer));
}
