/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2026-2026. All rights reserved.
 * Description: FusedDeepMoe tiling key definition file (ASCENDC_TPL mechanism)
 * Create: 2026-07-03
 * Note:
 * History: 2026-07-03 create FusedDeepMoe tiling key definition file
 */
#ifndef FUSED_DEEP_MOE_TILING_KEY_H
#define FUSED_DEEP_MOE_TILING_KEY_H

#include "ascendc/host_api/tiling/template_argument.h"
#include "fused_deep_moe_tiling.h"

namespace Cam {

// SOC enum, reserved for multi-SOC support (only 910_93 active now)
#define SOC_ASCEND910_93 0
#define SOC_ASCEND950   1   // reserved, not yet implemented

// 5 bool flags (from original EXEC_FLAG bitmap) + 1 reserved ARCH param
ASCENDC_TPL_ARGS_DECL(FusedDeepMoe,
    ASCENDC_TPL_BOOL_DECL(TPL_IS_DEEP_FUSE, 0, 1),        // moeExpertNumPerRank != 1
    ASCENDC_TPL_BOOL_DECL(TPL_IS_TENSOR_LIST, 0, 1),      // weight is tensor list
    ASCENDC_TPL_BOOL_DECL(TPL_IS_X_ACTIVE_MASK, 0, 1),    // x_active_mask enabled
    ASCENDC_TPL_BOOL_DECL(TPL_IS_SHARED_EXPERT, 0, 1),    // share expert enabled
    ASCENDC_TPL_BOOL_DECL(TPL_IS_SMOOTH_QUANT, 0, 1),     // smooth scales enabled
    ASCENDC_TPL_UINT_DECL(TPL_ARCH, ASCENDC_TPL_2_BW, ASCENDC_TPL_UI_LIST,
        SOC_ASCEND910_93),
);

// Selection table: declare valid combinations + corresponding tiling struct.
// Struct routing is driven by ASCENDC_TPL_TILING_STRUCT_SEL.
ASCENDC_TPL_SEL(
    // shared expert path
    ASCENDC_TPL_ARGS_SEL(
        ASCENDC_TPL_BOOL_SEL(TPL_IS_DEEP_FUSE, 0, 1),
        ASCENDC_TPL_BOOL_SEL(TPL_IS_TENSOR_LIST, 0, 1),
        ASCENDC_TPL_BOOL_SEL(TPL_IS_X_ACTIVE_MASK, 0, 1),
        ASCENDC_TPL_BOOL_SEL(TPL_IS_SHARED_EXPERT, 1),
        ASCENDC_TPL_BOOL_SEL(TPL_IS_SMOOTH_QUANT, 0, 1),
        ASCENDC_TPL_UINT_SEL(TPL_ARCH, ASCENDC_TPL_UI_LIST, SOC_ASCEND910_93),
        ASCENDC_TPL_TILING_STRUCT_SEL(FusedDeepMoeTilingDataShared)
    ),
    // non-share path
    ASCENDC_TPL_ARGS_SEL(
        ASCENDC_TPL_BOOL_SEL(TPL_IS_DEEP_FUSE, 0, 1),
        ASCENDC_TPL_BOOL_SEL(TPL_IS_TENSOR_LIST, 0, 1),
        ASCENDC_TPL_BOOL_SEL(TPL_IS_X_ACTIVE_MASK, 0, 1),
        ASCENDC_TPL_BOOL_SEL(TPL_IS_SHARED_EXPERT, 0),
        ASCENDC_TPL_BOOL_SEL(TPL_IS_SMOOTH_QUANT, 0, 1),
        ASCENDC_TPL_UINT_SEL(TPL_ARCH, ASCENDC_TPL_UI_LIST, SOC_ASCEND910_93),
        ASCENDC_TPL_TILING_STRUCT_SEL(FusedDeepMoeTilingDataPlain)
    ),
);

} // namespace Cam
#endif  // FUSED_DEEP_MOE_TILING_KEY_H
