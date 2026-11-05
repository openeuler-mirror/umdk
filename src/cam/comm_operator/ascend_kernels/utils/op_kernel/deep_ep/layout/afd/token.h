/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2026-2026. All rights reserved.
 * Description: Token record layout.
 * Create: 2026-11-03
 * Note: Device header for the CAM DeepEP-compatible operators.
 * History: 2026-11-03 create for the cam_deepep operators
 */
#pragma once
#include <deep_ep/layout/afd/context.h>
// ### PATCH START: AFD record layout; DeepEP TokenLayout naming retained
namespace deep_ep::afd {
struct TokenLayout {
    uint64_t num_hidden_bytes, num_sf_bytes, num_topk;
    constexpr __aicore__ __forceinline__ uint64_t sf_offset() const
    {
        return num_hidden_bytes;
    }
    constexpr __aicore__ __forceinline__ uint64_t topk_idx_offset() const
    {
        return sf_offset() + align32(num_sf_bytes);
    }
    constexpr __aicore__ __forceinline__ uint64_t topk_weights_offset() const
    {
        return topk_idx_offset() + align32(8 * num_topk);
    }
    constexpr __aicore__ __forceinline__ uint64_t src_token_idx_offset() const
    {
        return topk_weights_offset() + 4 * num_topk;
    }
    constexpr __aicore__ __forceinline__ uint64_t valid_topk_mask_offset() const
    {
        return src_token_idx_offset() + 4;
    }
    constexpr __aicore__ __forceinline__ uint64_t metadata_stride() const
    {
        return align32(valid_topk_mask_offset() + 4 - num_hidden_bytes);
    }
    constexpr __aicore__ __forceinline__ uint64_t record_stride() const
    {
        return align512(valid_topk_mask_offset() + 4);
    }
};
} // namespace deep_ep::afd
// ### PATCH END: AFD record layout
