/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2026-2026. All rights reserved.
 * Description: FusedDeepMoe Arch35 (Ascend950) operator kernel implementation file
 * Create: 2026-08-04
 * Note:
 * History: 2026-08-04 add fused_deep_moe_arch35 for Ascend950
 */
#ifndef FUSED_DEEP_MOE_ARCH35_EPILOGUE_DISPATCH_POLICY_H
#define FUSED_DEEP_MOE_ARCH35_EPILOGUE_DISPATCH_POLICY_H
#include "catlass/epilogue/dispatch_policy.hpp"

namespace Catlass::Epilogue {

template <uint32_t UB_STAGES_>
struct EpilogueAtlasA5SiluHalf {
    using ArchTag = Arch::Ascend950;
    static constexpr uint32_t UB_STAGES = UB_STAGES_;
};

template <uint32_t EXEC_FLAG_>
struct EpilogueAtlasA5CastCombine {
    using ArchTag = Arch::Ascend950;
    static constexpr uint32_t UB_STAGES = 1;
    static constexpr uint32_t EXEC_FLAG = EXEC_FLAG_;
};

}  // namespace Catlass::Epilogue
#endif  // FUSED_DEEP_MOE_ARCH35_EPILOGUE_DISPATCH_POLICY_H
