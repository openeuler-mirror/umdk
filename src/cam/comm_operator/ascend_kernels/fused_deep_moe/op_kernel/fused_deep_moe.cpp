/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2025-2025. All rights reserved.
 * Description: FusedDeepMoe operator kernel function implementation file
 * Create: 2025-07-19
 * Note:
 * History: 2025-07-19 create FusedDeepMoe operator kernel function implementation file
 */
#include "fused_deep_moe.h"
#include <kernel_operator.h>
#include "lib/matmul_intf.h"
#include "fused_deep_moe_tiling_key.h"

template <bool TPL_IS_DEEP_FUSE, bool TPL_IS_TENSOR_LIST, bool TPL_IS_X_ACTIVE_MASK,
          bool TPL_IS_SHARED_EXPERT, bool TPL_IS_SMOOTH_QUANT, int TPL_ARCH>
__global__ __aicore__ void fused_deep_moe(
    // input
    GM_ADDR x, GM_ADDR expert_ids, GM_ADDR gmm1_weight, GM_ADDR gmm1_weight_scale,
    GM_ADDR gmm2_weight, GM_ADDR gmm2_weight_scale, GM_ADDR expert_scales,
    GM_ADDR share_gmm1_weight, GM_ADDR share_gmm1_weight_scale,
    GM_ADDR share_gmm2_weight, GM_ADDR share_gmm2_weight_scale,
    GM_ADDR expert_smooth_scales, GM_ADDR share_smooth_scales, GM_ADDR x_active_mask,
    // output
    GM_ADDR output, GM_ADDR share_output, GM_ADDR expertTokenNums,
    // system
    GM_ADDR workspace, GM_ADDR tiling)
{
    icache_preload(8);
    KERNEL_TASK_TYPE_DEFAULT(KERNEL_TYPE_MIX_AIC_1_2);  // 1C2V

    // default tiling struct (required by _gen_tiling_key_struct_map when default != "")
    REGISTER_TILING_DEFAULT(FusedDeepMoeTilingDataPlain);

    // reassemble EXEC_FLAG bitmap from named TPL params (keep kernel class signature unchanged)
    constexpr uint32_t EXEC_FLAG =
        (TPL_IS_DEEP_FUSE     ? EXEC_FLAG_DEEP_FUSE     : 0) |
        (TPL_IS_TENSOR_LIST   ? EXEC_FLAG_TENSOR_LIST   : 0) |
        (TPL_IS_X_ACTIVE_MASK ? EXEC_FLAG_X_ACTIVE_MASK : 0) |
        (TPL_IS_SHARED_EXPERT ? EXEC_FLAG_SHARED_EXPERT : 0) |
        (TPL_IS_SMOOTH_QUANT  ? EXEC_FLAG_SMOOTH_QUANT  : 0);

    // struct routing is driven by ASCENDC_TPL_TILING_STRUCT_SEL in fused_deep_moe_tiling_key.h
    if constexpr (TPL_IS_SHARED_EXPERT) {
        GET_TILING_DATA_WITH_STRUCT(FusedDeepMoeTilingDataShared, tiling_data, tiling);
        FusedDeepMoe<DTYPE_X, DTYPE_GMM1_WEIGHT_SCALE, DTYPE_GMM2_WEIGHT_SCALE, int32_t, false, EXEC_FLAG> op;
        op.Init(x, expert_ids, gmm1_weight, gmm1_weight_scale, gmm2_weight, gmm2_weight_scale,
                expert_scales, share_gmm1_weight, share_gmm1_weight_scale,
                share_gmm2_weight, share_gmm2_weight_scale, expert_smooth_scales, share_smooth_scales, x_active_mask,
                output, share_output, expertTokenNums,
                workspace, nullptr, &tiling_data);
        op.Process();
    } else {
        GET_TILING_DATA_WITH_STRUCT(FusedDeepMoeTilingDataPlain, tiling_data, tiling);
        FusedDeepMoe<DTYPE_X, DTYPE_GMM1_WEIGHT_SCALE, DTYPE_GMM2_WEIGHT_SCALE, int32_t, false, EXEC_FLAG> op;
        op.Init(x, expert_ids, gmm1_weight, gmm1_weight_scale, gmm2_weight, gmm2_weight_scale,
                expert_scales, share_gmm1_weight, share_gmm1_weight_scale,
                share_gmm2_weight, share_gmm2_weight_scale, expert_smooth_scales, share_smooth_scales, x_active_mask,
                output, share_output, expertTokenNums,
                workspace, nullptr, &tiling_data);
        op.Process();
    }
}
