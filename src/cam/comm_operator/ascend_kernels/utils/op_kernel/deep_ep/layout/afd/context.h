/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2026-2026. All rights reserved.
 * Description: Communication context and workspace record layout.
 * Create: 2026-11-03
 * Note: Device header for the CAM DeepEP-compatible operators.
 * History: 2026-11-03 create for the cam_deepep operators
 */
#pragma once
#include <cstdint>
#include <cstddef>
#include <deep_ep/common/compiled.h>

// ### PATCH START: AFD wire ABI, based on DeepEP 3b25377d
namespace deep_ep::afd {
constexpr __aicore__ __forceinline__ uint64_t align32(uint64_t n)
{
    return (n + 31) / 32 * 32;
}
constexpr __aicore__ __forceinline__ uint64_t align512(uint64_t n)
{
    return (n + 511) / 512 * 512;
}
constexpr uint32_t kAbiVersion = 2;
// Current implementation-family bound per lane/physical slot, never a DP aggregate bound.
constexpr uint32_t kMaxLaneTokens = 32768;
enum ReturnProgressMode : uint32_t {
    RETURN_TRANSACTION = 0,
    RETURN_ROUND_STEP = 1
};
enum Error : uint32_t {
    OK = 0,
    BAD_ABI = 1,
    BAD_TASK = 2,
    BAD_LAYER = 3,
    BAD_ROUTE = 4,
    CAPACITY = 5,
    STATE_ORDER = 6,
    TIMEOUT = 7,
    TRANSPORT = 8
};
struct alignas(kNumUbAlignmentBytes) AFDControlBlock {
    uint32_t value, reserved[7];
};
struct alignas(kNumUbAlignmentBytes) AFDTaskInfo {
    uint32_t abi_version, src_rank_idx, payload_slot_idx, microbatch_idx;
    // num_tokens: this transaction logical row extent B_m, including masked-out rows.
    // num_comm_rounds: common DP J_DP=max(1,max_m ceil(B_m/C_m)); exhausted members publish zeros.
    uint32_t layer_idx, num_tokens, num_comm_rounds, reserved[9];
};
struct alignas(kNumUbAlignmentBytes) AFDInbox {
    uint32_t microbatch_idx, layer_idx, round_idx, num_comm_rounds;
    uint32_t num_round_tokens, return_bit, num_recv_records, reserved[9];
};
struct alignas(kNumUbAlignmentBytes) AFDRoundLedger {
    uint32_t state, input_bit, return_bit, round_idx;
    uint32_t token_begin, num_round_tokens, final_round, microbatch_idx, reserved[8];
};
struct alignas(kNumUbAlignmentBytes) AFDSendState {
    uint32_t next_input_bit, next_return_bit, has_published, last_input_bit, reserved[4];
};
// capacity is C_m: raw-token capacity of one communication round in this physical slot.
struct alignas(kNumUbAlignmentBytes) AFDLane {
    uint32_t src_rank_idx, payload_slot_idx, dp_idx, member_idx, phase, capacity;
    uint32_t reserved[2];
};
struct alignas(kNumUbAlignmentBytes) AFDPeer {
    uint32_t domain_rank_idx, peer_idx;
    uint64_t payload_bytes, control_base, control_bytes;
};
struct alignas(kNumUbAlignmentBytes) AFDAddress {
    uint64_t records_offset, route_reference_offset, count_offset, prefix_offset;
    uint64_t inbox_offset, input_ready_offset, consumed_offset, reserved;
};
struct alignas(kNumUbAlignmentBytes) AFDWorkspace {
    uint64_t dst_buffer_slot_idx, metadata_send_buffer, tile_counts, tile_psum;
    uint64_t route_reference_send, expert_counts, expert_prefix, rank_totals;
    uint64_t send_state, error_scratch, num_bytes, reserved;
};
struct alignas(kNumUbAlignmentBytes) AFDContextLayout {
    uint32_t abi_version, num_ranks, num_src_ranks, num_source_lanes;
    uint32_t num_experts, num_topk, num_hidden_bytes, num_sf_packs;
    // num_token_capacity: local full-transaction maxBS (x allocation rows).
    // num_max_tokens_per_rank: legacy native per-call bound, here C_max=max_l lane.capacity.
    // Neither field represents a DP sum; C_max sizes per-window JIT/workspace only.
    uint32_t num_vec_cores, num_token_capacity, num_max_tokens_per_rank, num_tokens_per_tile;
    // Former reserved word: fixed at initialization; mode 1 requires matching new binaries.
    uint32_t num_layers, src_rank_idx, num_slots, return_progress_mode;
    // Endpoint-group channel stride: 0 = legacy single-endpoint table; N = N channels
    // per non-self peer (one local endpoint per (group, AIV)); table index = peer_base + aiv.
    uint32_t channel_stride, reserved_pad0;
    uint64_t lanes_offset, peers_offset, addresses_offset, layers_offset;
    uint64_t context_bytes, payload_bytes, control_bytes, reserved_address;
    AFDWorkspace workspace;
};
static_assert(sizeof(AFDTaskInfo) == 64 && sizeof(AFDInbox) == 64 && sizeof(AFDRoundLedger) == 64);
static_assert(sizeof(AFDControlBlock) == 32 && sizeof(AFDSendState) == 32);
static_assert(sizeof(AFDLane) == 32 && sizeof(AFDPeer) == 32 && sizeof(AFDAddress) == 64);
static_assert(sizeof(AFDWorkspace) == 96 && sizeof(AFDContextLayout) == 256);
static_assert(offsetof(AFDContextLayout, workspace) == 160);
static_assert(offsetof(AFDContextLayout, return_progress_mode) == 60);
static_assert(offsetof(AFDContextLayout, channel_stride) == 64);
constexpr __aicore__ __forceinline__ AFDWorkspace make_workspace(uint32_t c, uint32_t t, uint32_t k, uint32_t e,
                                                                 uint32_t n, uint32_t m, uint32_t slots)
{
    AFDWorkspace w{};
    uint64_t p = 0, j = (uint64_t(c) + t - 1) / t;
    w.dst_buffer_slot_idx = p;
    p += align32(uint64_t(4) * c * k);
    w.metadata_send_buffer = p;
    p += align32(uint64_t(c) * m);
    w.tile_counts = p;
    p += align32(4 * j * (n + e));
    w.tile_psum = p;
    p += align32(4 * j * (n + e));
    w.route_reference_send = p;
    p += align32(uint64_t(4) * c * k);
    w.expert_counts = p;
    p += align32(4 * uint64_t(e));
    w.expert_prefix = p;
    p += align32(4 * uint64_t(e));
    w.rank_totals = p;
    p += align32(4 * uint64_t(n));
    w.send_state = p;
    p += 32 * uint64_t(slots);
    w.error_scratch = p;
    p += 256;
    w.num_bytes = p;
    return w;
}
} // namespace deep_ep::afd
// ### PATCH END: AFD wire ABI
