/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2026-2026. All rights reserved.
 * Description: Return-directory record layout.
 * Create: 2026-11-03
 * Note: Device header for the CAM DeepEP-compatible operators.
 * History: 2026-11-03 create for the cam_deepep operators
 */
#pragma once
#include <deep_ep/layout/afd/active.h>

// ### PATCH START: AFD reverse-channel directory and local completion ABI
namespace deep_ep::afd {
// Optional Context extension at reserved_address (an offset, not a device pointer).
// Existing dispatch ABI/offsets stay unchanged. Reverse-channel users require version=1.
struct alignas(kNumUbAlignmentBytes) AFDReturnDirectory {
    uint64_t source_peers_offset, lanes_offset, return_stride;
    uint32_t version, reserved;
};
struct alignas(kNumUbAlignmentBytes) AFDReturnLane {
    uint64_t return_offset, done_offset, credit_offset, reserved;
};
// One bounded A-local cursor per physical slot, independent of shared reduction scratch.
// A first start admits immutable TaskInfo; sweeps cannot reset a live or failed transaction.
enum ReturnProgressState : uint32_t {
    RETURN_IDLE = 0,
    RETURN_RUNNING = 1,
    RETURN_WAIT_ACK = 2,
    RETURN_DONE = 3,
    RETURN_ERROR = 4
};
struct alignas(kNumUbAlignmentBytes) AFDReturnProgress {
    AFDTaskInfo task;
    uint32_t state, next_round, last_input_bit, error_code, reserved[4];
};
constexpr __aicore__ __forceinline__ uint64_t combine_recv_workspace_bytes(uint32_t nc)
{
    return 256 + align32(32 * uint64_t(nc));
}
static_assert(sizeof(AFDReturnProgress) == 96);
enum CompletionState : uint32_t {
    COMPLETION_EMPTY = 0,
    ARMED = 1,
    READY = 2
};
struct alignas(kNumUbAlignmentBytes) AFDCompletion {
    uint32_t state, error_code, num_entries, num_members;
    uint32_t num_deltas, reserved[3];
};
constexpr __aicore__ __forceinline__ uint64_t completion_entries_offset()
{
    return 32;
}
constexpr __aicore__ __forceinline__ uint64_t completion_members_offset(uint32_t l)
{
    return 32 + 32 * uint64_t(l);
}
constexpr __aicore__ __forceinline__ uint64_t completion_deltas_offset(uint32_t l)
{
    return 32 + 64 * uint64_t(l);
}
constexpr __aicore__ __forceinline__ uint64_t completion_bytes(uint32_t l, uint32_t r)
{
    return completion_deltas_offset(l) + align32(4 * uint64_t(l) * r);
}
static_assert(sizeof(AFDReturnDirectory) == 32 && sizeof(AFDReturnLane) == 32 && sizeof(AFDCompletion) == 32);
} // namespace deep_ep::afd
// ### PATCH END: AFD reverse-channel directory and local completion ABI
