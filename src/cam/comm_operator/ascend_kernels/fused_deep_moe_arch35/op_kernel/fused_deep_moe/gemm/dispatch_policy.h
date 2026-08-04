/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2026-2026. All rights reserved.
 * Description: FusedDeepMoe Arch35 (Ascend950) operator kernel implementation file
 * Create: 2026-08-04
 * Note:
 * History: 2026-08-04 add fused_deep_moe_arch35 for Ascend950
 */
#ifndef FUSED_DEEP_MOE_ARCH35_GEMM_DISPATCH_POLICY_H
#define FUSED_DEEP_MOE_ARCH35_GEMM_DISPATCH_POLICY_H
#include "catlass/gemm/dispatch_policy.hpp"

namespace Catlass::Gemm {

template <class ArchTag_, bool ENABLE_UNIT_FLAG_ = false, uint32_t L1_SCALE_FACTOR_K_ = 16, uint32_t L0C_STAGES_ = 1,
    bool ENABLE_L1_RESIDENT_ = false, uint32_t L1A_STAGES_ = 2, uint32_t L1B_STAGES_ = 2, uint32_t L0A_STAGES_ = 2,
    uint32_t L0B_STAGES_ = 2>
struct MmadMxWithCallback : public MmadMx<ArchTag_, ENABLE_UNIT_FLAG_, L1_SCALE_FACTOR_K_, L0C_STAGES_,
    ENABLE_L1_RESIDENT_, L1A_STAGES_, L1B_STAGES_, L0A_STAGES_, L0B_STAGES_> {
};

}  // namespace Catlass::Gemm
#endif  // FUSED_DEEP_MOE_ARCH35_GEMM_DISPATCH_POLICY_H
