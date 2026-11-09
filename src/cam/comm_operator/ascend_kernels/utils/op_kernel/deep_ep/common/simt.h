/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2026-2026. All rights reserved.
 * Description: SIMT warp helpers.
 * Create: 2026-11-03
 * Note: Device header for the CAM DeepEP-compatible operators.
 * History: 2026-11-03 create for the cam_deepep operators
 */
#pragma once

#include <deep_ep/common/compiled.h>
#include <deep_ep/common/math.h>
#include <deep_ep/common/exception.h>

#include <simt_api/device_warp_functions.h>

#ifdef __CCE__
namespace deep_ep::simt {

template <uint32_t kNumCycles = 300> __simt_callee__ __forceinline__ void nop()
{
    EP_STATIC_ASSERT(kNumCycles % 15 == 0);
#pragma unroll 1
    for (int i = 0; i < kNumCycles / 15; ++i) {
        __nop();
    }
}

__simt_callee__ __forceinline__ int exchange(const int &value, const int &lane_idx)
{
    return asc_shfl(value, lane_idx);
}

template <int kMaxValue>
__simt_callee__ __forceinline__ bool deduplicate(const int &value, const int &lane_idx,
                                                 const uint32_t lane_mask = 0xffffffffu)
{
    auto peers = lane_mask;
#pragma unroll
    for (int i = 0; (1 << i) <= kMaxValue; ++i) {
        const auto current_bit = (static_cast<unsigned>(value) >> i) & 1u;
        const auto ones = asc_ballot(current_bit);
        peers &= ones ^ (current_bit - 1u);
    }
    return (peers >> lane_idx) == 1u;
}

__simt_callee__ __forceinline__ int warp_inclusive_sum(int value, const int &lane_idx)
{
#pragma unroll
    for (int offset = 1; offset < warpSize; offset <<= 1) {
        const auto synced = asc_shfl_up(value, offset);
        if (lane_idx >= offset) {
            value += synced;
        }
    }
    return value;
}

__simt_callee__ __forceinline__ int warp_exclusive_sum(const int &value, const int &lane_idx)
{
    return warp_inclusive_sum(value, lane_idx) - value;
}

} // namespace deep_ep::simt
#endif
