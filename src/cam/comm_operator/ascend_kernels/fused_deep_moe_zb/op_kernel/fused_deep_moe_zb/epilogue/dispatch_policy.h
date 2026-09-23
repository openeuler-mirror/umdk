/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2025-2025. All rights reserved.
 * Description: FusedDeepMoeZb operator kernel function implementation file
 * Create: 2025-07-19
 * Note:
 * History: 2025-07-19 create FusedDeepMoeZb operator kernel function implementation file
 */
#ifndef FUSED_DEEP_MOE_ZB_EPILOGUE_DISPATCH_POLICY_H
#define FUSED_DEEP_MOE_ZB_EPILOGUE_DISPATCH_POLICY_H
#include "catlass/epilogue/dispatch_policy.hpp"

namespace Catlass::Epilogue {

template <uint32_t UB_STAGES_, uint32_t EXEC_FLAG_>
struct EpilogueAtlasA2PerTokenDequantSwiglu {
    using ArchTag = Arch::AtlasA2;
    static constexpr uint32_t UB_STAGES = UB_STAGES_;
    static constexpr uint32_t EXEC_FLAG = EXEC_FLAG_;
};

template <uint32_t UB_STAGES_, uint32_t EXEC_FLAG_>
struct EpilogueAtlasA2PerTokenDequantCombine {
    using ArchTag = Arch::AtlasA2;
    static constexpr uint32_t UB_STAGES = UB_STAGES_;
    static constexpr uint32_t EXEC_FLAG = EXEC_FLAG_;
};

}  // namespace Catlass::Epilogue

#endif  // FUSED_DEEP_MOE_ZB_EPILOGUE_DISPATCH_POLICY_H
