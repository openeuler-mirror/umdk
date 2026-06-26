/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2025-2025. All rights reserved.
 * Description: FusedDeepMoe operator kernel function implementation file
 * Create: 2025-07-19
 * Note:
 * History: 2025-07-19 create FusedDeepMoe operator kernel function implementation file
 */
#ifndef GEMM_DISPATCH_POLICY_H
#define GEMM_DISPATCH_POLICY_H

#include "catlass/gemm/dispatch_policy.hpp"

namespace Catlass::Gemm {

template <uint32_t PRELOAD_STAGES_, uint32_t L1A_STAGES_, uint32_t L1B_STAGES_, uint32_t L0A_STAGES_,
    uint32_t L0B_STAGES_, uint32_t L0C_STAGES_, bool ENABLE_UNIT_FLAG_, bool ENABLE_SHUFFLE_K_>
struct MmadAtlasA2PreloadAsyncWithCallbackResidentA : public MmadAtlasA2Async {
    static constexpr uint32_t PRELOAD_STAGES = PRELOAD_STAGES_;
    static constexpr uint32_t L1A_STAGES = L1A_STAGES_;
    static constexpr uint32_t L1B_STAGES = L1B_STAGES_;
    static constexpr uint32_t L0A_STAGES = L0A_STAGES_;
    static constexpr uint32_t L0B_STAGES = L0B_STAGES_;
    static constexpr uint32_t L0C_STAGES = L0C_STAGES_;
    static constexpr bool ENABLE_UNIT_FLAG = ENABLE_UNIT_FLAG_;
    static constexpr bool ENABLE_SHUFFLE_K = ENABLE_SHUFFLE_K_;
};
template <uint32_t PRELOAD_STAGES_, uint32_t L1_STAGES_, uint32_t L0A_STAGES_,
    uint32_t L0B_STAGES_, uint32_t L0C_STAGES_, bool ENABLE_UNIT_FLAG_, bool ENABLE_SHUFFLE_K_>
struct MmadAtlasA2PreloadAsyncWithCallbackW4a8 : public MmadAtlasA2Async {
    using ArchTag = Arch::AtlasA2;
    static constexpr uint32_t PRELOAD_STAGES = PRELOAD_STAGES_;
    static constexpr uint32_t L1_STAGES = L1_STAGES_;
    static constexpr uint32_t L0A_STAGES = L0A_STAGES_;
    static constexpr uint32_t L0B_STAGES = L0B_STAGES_;
    static constexpr uint32_t L0C_STAGES = L0C_STAGES_;
    static constexpr bool ENABLE_UNIT_FLAG = ENABLE_UNIT_FLAG_;
    static constexpr bool ENABLE_SHUFFLE_K = ENABLE_SHUFFLE_K_;
};
}  // namespace Catlass::Gemm

#endif  // GEMM_DISPATCH_POLICY_H
