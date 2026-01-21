/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2026-2026. All rights reserved.
 * Description: FusedDeepMoeFwk operator kernel function implementation file
 * Create: 2026-01-20
 */

#include "fused_deep_moe_fwk.h"

extern "C" __global__ __aicore__ void fused_deep_moe_fwk(
    // input
    GM_ADDR x, GM_ADDR expert_ids, GM_ADDR gmm1_permuted_weight, GM_ADDR gmm1_permuted_weight_scale,
    GM_ADDR gmm2_weight, GM_ADDR gmm2_weight_scale, GM_ADDR expert_smooth_scales, GM_ADDR expert_scales,
    // output
    GM_ADDR output, GM_ADDR expertTokenNums,
    // system
    GM_ADDR workspace, GM_ADDR tiling)
{
    icache_preload(8);
    // New output recvCount
    REGISTER_TILING_DEFAULT(FusedDeepMoeFwkTilingData);
    KERNEL_TASK_TYPE_DEFAULT(KERNEL_TYPE_MIX_AIC_1_2);  // 1C2V
    GET_TILING_DATA(tiling_data, tiling);
    if constexpr (TILING_KEY_IS(0) || TILING_KEY_IS(1) || TILING_KEY_IS(2) || TILING_KEY_IS(3)) {
        FusedDeepMoeFwk<DTYPE_X, int32_t, false, TILING_KEY_VAR> op;
        op.Init(x, expert_ids, gmm1_permuted_weight, gmm1_permuted_weight_scale, gmm2_weight, gmm2_weight_scale,
                expert_smooth_scales, expert_scales, output, expertTokenNums, workspace, nullptr, &tiling_data);
        op.Process();
    }
}
