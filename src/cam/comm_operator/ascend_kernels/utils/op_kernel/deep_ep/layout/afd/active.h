/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2026-2026. All rights reserved.
 * Description: Scheduler-output active-set record layout.
 * Create: 2026-11-03
 * Note: Device header for the CAM DeepEP-compatible operators.
 * History: 2026-11-03 create for the cam_deepep operators
 */
#pragma once
#include <deep_ep/layout/afd/context.h>

// ### PATCH START: shared scheduler-output ABI from AFD common_contract, no scheduler implementation
namespace deep_ep::afd {
enum ActiveKind : uint32_t {
    NOP = 0,
    WORK = 1,
    CONTROL = 2,
    ABORT = 3
};
enum ExecutionStage : uint32_t {
    EMPTY = 0,
    SELECTED = 1,
    INPUT_READY = 2,
    COMPUTE_READY = 3,
    COMMITTED = 4,
    ABORTED = 5
};
enum GrantState : uint32_t {
    NONE = 0,
    HELD = 1,
    FINISHED = 2
};
struct alignas(kNumUbAlignmentBytes) AFDActive {
    uint32_t valid, kind, phase, layer_idx;
    uint32_t num_entries, num_members, num_segments, num_expanded_tokens;
    uint32_t num_padded_tokens, reserved;
    uint64_t entries_offset, members_offset, segments_offset;
};
struct alignas(kNumUbAlignmentBytes) AFDActiveEntry {
    uint32_t pending_idx, member_begin, num_members, segment_begin;
    uint32_t num_segments, num_rows, is_final, grant_state;
};
struct alignas(kNumUbAlignmentBytes) AFDActiveMember {
    uint32_t source_lane_idx, input_bit, return_bit, delta_begin;
    uint32_t num_experts, reserved[3];
};
struct alignas(kNumUbAlignmentBytes) AFDActiveSegment {
    uint32_t entry_idx, source_lane_idx, local_expert_idx, route_begin;
    uint32_t num_routes, dst_row_begin, reserved[2];
};
struct alignas(kNumUbAlignmentBytes) AFDExecutionState {
    uint32_t stage, error_code, num_entries, reserved[5];
};
constexpr __aicore__ __forceinline__ uint64_t active_entries_offset()
{
    return sizeof(AFDActive);
}
constexpr __aicore__ __forceinline__ uint64_t active_members_offset(uint32_t l)
{
    return active_entries_offset() + 32 * uint64_t(l);
}
constexpr __aicore__ __forceinline__ uint64_t active_segments_offset(uint32_t l)
{
    return active_members_offset(l) + 32 * uint64_t(l);
}
constexpr __aicore__ __forceinline__ uint64_t active_bytes(uint32_t l, uint32_t r)
{
    return active_segments_offset(l) + 32 * uint64_t(l) * r;
}
constexpr __aicore__ __forceinline__ uint64_t execution_bytes(uint32_t l)
{
    return 32 + align32(4 * uint64_t(l));
}
constexpr __aicore__ __forceinline__ uint64_t recv_workspace_bytes(uint32_t cores)
{
    return 32 * uint64_t(cores) + 256;
}
// AFD dispatch-only validation indices. Every nonempty Segment contributes at
// least one effective row, so min(L*R,Q) bounds both ping-pong index arrays.
// The communication-only combine kernels retain recv_workspace_bytes(cores).
constexpr __aicore__ __forceinline__ uint64_t recv_segment_capacity(uint32_t l, uint32_t r, uint32_t q)
{
    return uint64_t(l) * r < q ? uint64_t(l) * r : q;
}
constexpr __aicore__ __forceinline__ uint64_t recv_segment_index_bytes(uint32_t l, uint32_t r, uint32_t q)
{
    return align32(4 * recv_segment_capacity(l, r, q));
}
constexpr __aicore__ __forceinline__ uint64_t dispatch_recv_workspace_bytes(uint32_t cores, uint32_t l, uint32_t r,
                                                                            uint32_t q)
{
    return recv_workspace_bytes(cores) + 2 * recv_segment_index_bytes(l, r, q);
}
static_assert(sizeof(AFDActive) == 64 && offsetof(AFDActive, entries_offset) == 40);
static_assert(sizeof(AFDActiveEntry) == 32 && sizeof(AFDActiveMember) == 32 && sizeof(AFDActiveSegment) == 32);
static_assert(sizeof(AFDExecutionState) == 32);
} // namespace deep_ep::afd
// ### PATCH END: shared scheduler-output ABI
