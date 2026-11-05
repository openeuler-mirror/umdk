/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2026-2026. All rights reserved.
 * Description: runtime-parameterized AFD dispatch_recv body for CAM
 * Create: 2026-11-03
 * Note: derived from deep_ep/impls/afd/dispatch_recv.h. Every
 *       model-dependent dimension (ranks/experts/topk/hidden/sf/lanes/layers/
 *       capacity/alignment/stage) is a runtime field; only dtype-free layout
 *       math stays in the body. UB is carved from a runtime-sized pool so the
 *       host budget formula and the kernel use the same byte accounting.
 * History: 2026-11-03 create runtime port
 */
#pragma once
#include "cam_deepep_rt_common.h"

// Runtime-parameterized bounded AFD receiver epilogue.
namespace deep_ep::afd::rt {
struct DispatchRecvParams {
    uint32_t num_ranks;
    uint32_t num_experts;
    uint32_t experts_per_rank;
    uint32_t num_topk;
    uint32_t num_vec_cores;
    uint32_t num_hidden_bytes;
    uint32_t num_sf_packs;
    uint32_t num_source_lanes;
    uint32_t num_layers;
    uint32_t max_expanded_tokens;
    uint32_t max_padded_tokens;
    uint32_t expert_alignment;
    uint32_t num_tokens_per_stage;
    uint32_t num_ub_bytes;
    uint32_t rank_idx;
    int32_t recv_sf_token_stride;
    int32_t recv_sf_hidden_stride;
    uint64_t payload_bytes;
    uint64_t control_bytes;
    uint64_t context_bytes;
};

// Same phases as dispatch_copy_epilogue_impl: R0 gate, R1 directory preflight,
// R2 parallel metadata preflight, R3-R5 two-stage output pipeline, R6 commit.
__aicore__ inline void dispatch_recv_body(const DispatchRecvParams &p, __gm__ void *buffer,
                                          __gm__ const AFDContextLayout *context, __gm__ const AFDActive *active,
                                          __gm__ AFDExecutionState *execution_state, __gm__ void *workspace,
                                          __gm__ void *recv_x, __gm__ int16_t *recv_sf, __gm__ int *recv_src_metadata,
                                          __gm__ void *control_buffer)
{
    // R0 [REUSE+AFD] Init/layout, then uniform Active/ExecutionState gating.
    AscendC::InitSocState();
    const int num_ranks = int(p.num_ranks), num_experts = int(p.num_experts);
    const int num_topk = int(p.num_topk), num_vec_cores = int(p.num_vec_cores);
    const int num_hidden_bytes = int(p.num_hidden_bytes), num_sf_packs = int(p.num_sf_packs);
    const int num_source_lanes = int(p.num_source_lanes), num_layers = int(p.num_layers);
    const int experts_per_rank = int(p.experts_per_rank);
    const int num_tokens_per_stage = int(p.num_tokens_per_stage);
    const int expert_alignment = int(p.expert_alignment);
    const int rank_idx = int(p.rank_idx);
    const uint32_t max_expanded_tokens = p.max_expanded_tokens;
    const uint32_t max_padded_tokens = p.max_padded_tokens;
    const int recv_sf_token_stride = int(p.recv_sf_token_stride);
    const int recv_sf_hidden_stride = int(p.recv_sf_hidden_stride);
    const uint64_t payload_bytes = p.payload_bytes, control_bytes = p.control_bytes;
    const uint64_t context_bytes = p.context_bytes;

    const TokenLayout token_layout{uint64_t(num_hidden_bytes), uint64_t(num_sf_packs) * 2, uint64_t(num_topk)};
    const int num_token_bytes = int(token_layout.record_stride());
    const int num_metadata_bytes = int(token_layout.metadata_stride());
    EP_DEVICE_ASSERT(num_tokens_per_stage >= 1 && num_tokens_per_stage <= 16);
    EP_DEVICE_ASSERT(experts_per_rank > 0 && experts_per_rank <= 512);
    EP_DEVICE_ASSERT(num_token_bytes > 0 && num_metadata_bytes > 0);

    // UB pool: production DispatchCopyEpilogueUBLayout with runtime strides.
    // Layout: token[2], metadata[2], refs[2], segment[2][32], zero[512], control[256].
    // The host uses the same formula to accept or reject the tiling.
    const uint32_t token_stage_stride = uint32_t(align32(uint64_t(num_token_bytes) * uint32_t(num_tokens_per_stage)));
    const uint32_t metadata_stage_stride = uint32_t(align32(16u * uint32_t(num_tokens_per_stage)));
    const uint32_t refs_stage_stride = uint32_t(align32(4u * uint32_t(num_tokens_per_stage)));
    const uint64_t ub_total =
        2uLL * token_stage_stride + 2uLL * metadata_stage_stride + 2uLL * refs_stage_stride + 64uLL + 512uLL + 256uLL;
    EP_DEVICE_ASSERT(ub_total <= uint64_t(p.num_ub_bytes));
    __ubuf__ uint8_t *const pool = reinterpret_cast<__ubuf__ uint8_t *>(0);
    __ubuf__ uint8_t *const ub_token = pool;
    __ubuf__ uint8_t *const ub_metadata = pool + 2uLL * token_stage_stride;
    __ubuf__ uint8_t *const ub_refs = ub_metadata + 2uLL * metadata_stage_stride;
    auto tmp = ub_refs + 2uLL * refs_stage_stride + 64uLL + 512uLL;

    const int vec_core_idx = AscendC::GetBlockIdx();
    auto words = reinterpret_cast<__ubuf__ uint32_t *>(tmp);
    auto ws = reinterpret_cast<__gm__ uint8_t *>(workspace);
    auto result = reinterpret_cast<__gm__ uint32_t *>(ws + 32 * num_vec_cores);
    recv_load(tmp, active, 64);
    const AFDActive task = recv_read_active_ubuf(tmp);
    // Immutable publication guarantees every launched AIV sees the same gate.
    // NOP/ABORT read no Context directory, Inbox, route or record.
    if (task.kind == ABORT && task.valid == 0) {
        return;
    }
    if (vec_core_idx == 0) {
        uint32_t error = OK;
        recv_load(tmp, execution_state, 32);
        const AFDExecutionState state = recv_read_execution_state_ubuf(tmp);
        if (task.kind == NOP && task.valid == 0) {
            if (task.num_entries || task.num_members || task.num_segments || task.num_expanded_tokens ||
                task.num_padded_tokens || state.stage != EMPTY || state.error_code != OK || state.num_entries) {
                error = STATE_ORDER;
            }
        } else if (task.valid != 1 || (task.kind != WORK && task.kind != CONTROL)) {
            error = BAD_TASK;
        } else if (state.stage != SELECTED || state.error_code != OK || state.num_entries != task.num_entries) {
            error = STATE_ORDER;
        }
        if (error == OK && task.kind != NOP) {
            if (context->abi_version != kAbiVersion || context->num_ranks != p.num_ranks ||
                context->num_experts != p.num_experts || context->num_topk != p.num_topk ||
                context->num_vec_cores != p.num_vec_cores || context->num_hidden_bytes != p.num_hidden_bytes ||
                context->num_sf_packs != p.num_sf_packs || context->num_source_lanes != p.num_source_lanes ||
                context->num_layers != p.num_layers || context->context_bytes != context_bytes ||
                context->payload_bytes != payload_bytes || context->control_bytes != control_bytes || rank_idx < 0 ||
                rank_idx >= num_ranks) {
                error = BAD_ABI;
            }
            if (error == OK &&
                (context->lanes_offset != sizeof(AFDContextLayout) ||
                 context->peers_offset != context->lanes_offset + 32uLL * p.num_source_lanes ||
                 context->addresses_offset != context->peers_offset + 32uLL * p.num_ranks ||
                 context->layers_offset != context->addresses_offset + 64uLL * p.num_source_lanes * p.num_ranks ||
                 !recv_range(context->layers_offset, 4uLL * p.num_layers, context_bytes))) {
                error = BAD_ABI;
            }
            if (error == OK &&
                (task.entries_offset != active_entries_offset() ||
                 task.members_offset != active_members_offset(p.num_source_lanes) ||
                 task.segments_offset != active_segments_offset(p.num_source_lanes) || task.num_entries == 0 ||
                 task.num_entries > p.num_source_lanes || task.num_members > p.num_source_lanes ||
                 task.num_segments > uint64_t(p.num_source_lanes) * uint64_t(experts_per_rank) ||
                 task.num_segments > task.num_expanded_tokens || task.num_expanded_tokens > max_expanded_tokens ||
                 task.num_padded_tokens > max_padded_tokens)) {
                error = CAPACITY;
            }
        }
        // R1 [AFD] Directory/Entry/Member/Segment preflight, before any output.
        // Do not form any untrusted table pointer until the directory is checked.
        if (error == OK && task.kind != NOP) {
            auto base = reinterpret_cast<__gm__ const uint8_t *>(context);
            auto lanes = reinterpret_cast<__gm__ const AFDLane *>(base + context->lanes_offset);
            auto addresses = reinterpret_cast<__gm__ const AFDAddress *>(base + context->addresses_offset);
            auto ab = reinterpret_cast<__gm__ const uint8_t *>(active);
            auto entries = reinterpret_cast<__gm__ const AFDActiveEntry *>(ab + task.entries_offset);
            auto members = reinterpret_cast<__gm__ const AFDActiveMember *>(ab + task.members_offset);
            auto segments = reinterpret_cast<__gm__ const AFDActiveSegment *>(ab + task.segments_offset);
            auto grants =
                reinterpret_cast<__gm__ const uint32_t *>(reinterpret_cast<__gm__ uint8_t *>(execution_state) + 32);
            bool legal_layer = false;
            for (int i = 0; i < num_layers; ++i) {
                legal_layer |=
                    recv_read(reinterpret_cast<__gm__ const uint32_t *>(
                                  reinterpret_cast<__gm__ const uint8_t *>(context) + context->layers_offset) +
                              i) == task.layer_idx;
            }
            if (!legal_layer) {
                error = BAD_LAYER;
            }
            // Freeze the sender's actual contiguous wire directory. Exact offsets also
            // reject aligned aliases/overlapping regions before any count/ref read.
            uint64_t wire_end = 0;
            for (int l = 0; l < num_source_lanes && error == OK; ++l) {
                const auto lane = recv_read(lanes + l);
                if (lane.capacity == 0 || lane.capacity > kMaxLaneTokens ||
                    lane.src_rank_idx >= context->num_src_ranks || lane.payload_slot_idx >= context->num_slots ||
                    uint64_t(lane.capacity) * uint32_t(num_topk) >= UINT32_MAX) {
                    error = BAD_ABI;
                    break;
                }
                const uint64_t record_offset = wire_end;
                wire_end += align512(uint64_t(lane.capacity) * uint64_t(num_token_bytes));
                const uint64_t ref_offset = wire_end;
                wire_end += align32(4uLL * uint64_t(lane.capacity) *
                                    uint64_t(num_topk < experts_per_rank ? num_topk : experts_per_rank));
                const uint64_t count_offset = wire_end;
                wire_end += align32(4uLL * uint64_t(experts_per_rank));
                const uint64_t prefix_offset = wire_end;
                wire_end += align32(4uLL * uint64_t(experts_per_rank));
                if (wire_end > payload_bytes) {
                    error = BAD_ABI;
                    break;
                }
                for (int f = 0; f < num_ranks; ++f) {
                    const auto address = recv_read(addresses + uint64_t(l) * uint32_t(num_ranks) + f);
                    if (address.records_offset != record_offset || address.route_reference_offset != ref_offset ||
                        address.count_offset != count_offset || address.prefix_offset != prefix_offset ||
                        address.inbox_offset != uint64_t(l) * 128 ||
                        address.input_ready_offset != uint64_t(l) * 128 + 64 ||
                        !recv_range(address.inbox_offset, 128, control_bytes)) {
                        error = BAD_ABI;
                    }
                }
            }
            if (error == OK && (wire_end != payload_bytes || control_bytes != 128uLL * uint64_t(num_source_lanes))) {
                error = BAD_ABI;
            }
            uint64_t next_member = 0, next_segment = 0, total = 0;
            for (uint32_t i = 0; i < task.num_entries && error == OK; ++i) {
                const auto entry = recv_read(entries + i);
                if (entry.pending_idx >= uint32_t(num_source_lanes) || entry.member_begin != next_member ||
                    entry.segment_begin != next_segment || entry.num_members == 0 ||
                    entry.num_members > task.num_members - next_member ||
                    entry.num_segments > task.num_segments - next_segment || entry.is_final > 1 ||
                    entry.grant_state > HELD || recv_read(grants + i) != entry.grant_state) {
                    error = BAD_TASK;
                    break;
                }
                if (task.kind == CONTROL && entry.is_final != 1) {
                    error = BAD_TASK;
                    break;
                }
                for (uint32_t j = 0; j < i; ++j) {
                    if (recv_read(entries + j).pending_idx == entry.pending_idx) {
                        error = BAD_TASK;
                    }
                }
                next_member += entry.num_members;
                next_segment += entry.num_segments;
                uint64_t rows = 0;
                uint32_t first_dp = 0, first_mb = 0, first_round = 0, first_rounds = 0;
                for (uint32_t j = entry.member_begin; j < next_member && error == OK; ++j) {
                    const auto member = recv_read(members + j);
                    if (member.source_lane_idx >= uint32_t(num_source_lanes) || member.input_bit > 1 ||
                        member.return_bit > 1 || member.num_experts != uint32_t(experts_per_rank) ||
                        member.delta_begin != j * uint64_t(experts_per_rank)) {
                        error = BAD_TASK;
                        break;
                    }
                    for (uint32_t k = 0; k < j; ++k) {
                        if (recv_read(members + k).source_lane_idx == member.source_lane_idx) {
                            error = BAD_TASK;
                        }
                    }
                    if (error != OK) {
                        break;
                    }
                    const auto lane = recv_read(lanes + member.source_lane_idx);
                    const auto address = recv_read(addresses + uint64_t(member.source_lane_idx) * uint32_t(num_ranks) +
                                                   uint32_t(rank_idx));
                    if (lane.phase != task.phase || lane.capacity == 0 || lane.capacity > kMaxLaneTokens ||
                        !recv_range(address.records_offset, uint64_t(lane.capacity) * uint64_t(num_token_bytes),
                                    payload_bytes) ||
                        !recv_range(address.route_reference_offset,
                                    4uLL * uint64_t(lane.capacity) *
                                        uint64_t(num_topk < experts_per_rank ? num_topk : experts_per_rank),
                                    payload_bytes) ||
                        !recv_range(address.count_offset, 4uLL * uint64_t(experts_per_rank), payload_bytes) ||
                        !recv_range(address.prefix_offset, 4uLL * uint64_t(experts_per_rank), payload_bytes) ||
                        !recv_range(address.inbox_offset, 64, control_bytes) ||
                        !recv_range(address.input_ready_offset, 32, control_bytes)) {
                        error = BAD_ABI;
                        break;
                    }
                    recv_load(tmp, reinterpret_cast<__gm__ uint8_t *>(control_buffer) + address.inbox_offset, 64);
                    const AFDInbox inbox = recv_read_inbox_ubuf(tmp);
                    recv_load(tmp, reinterpret_cast<__gm__ uint8_t *>(control_buffer) + address.input_ready_offset, 32);
                    if (words[0] != member.input_bit || inbox.return_bit != member.return_bit ||
                        inbox.layer_idx != task.layer_idx || inbox.num_round_tokens > lane.capacity ||
                        inbox.num_recv_records > inbox.num_round_tokens || inbox.num_comm_rounds == 0 ||
                        inbox.round_idx >= inbox.num_comm_rounds) {
                        error = BAD_TASK;
                        break;
                    }
                    if (task.kind == CONTROL && inbox.num_recv_records != 0) {
                        error = BAD_TASK;
                        break;
                    }
                    if (j == entry.member_begin) {
                        first_dp = lane.dp_idx;
                        first_mb = inbox.microbatch_idx;
                        first_round = inbox.round_idx;
                        first_rounds = inbox.num_comm_rounds;
                    } else if (first_dp != lane.dp_idx || first_mb != inbox.microbatch_idx ||
                               first_round != inbox.round_idx || first_rounds != inbox.num_comm_rounds) {
                        error = BAD_TASK;
                        break;
                    }
                    auto counts = reinterpret_cast<__gm__ const uint32_t *>(reinterpret_cast<__gm__ uint8_t *>(buffer) +
                                                                            address.count_offset);
                    auto prefix = reinterpret_cast<__gm__ const uint32_t *>(reinterpret_cast<__gm__ uint8_t *>(buffer) +
                                                                            address.prefix_offset);
                    uint64_t previous = 0;
                    for (int e = 0; e < experts_per_rank; ++e) {
                        const uint64_t end = recv_read(prefix + e);
                        if (end < previous || end - previous != recv_read(counts + e) ||
                            end > uint64_t(lane.capacity) *
                                      uint64_t(num_topk < experts_per_rank ? num_topk : experts_per_rank)) {
                            error = BAD_ROUTE;
                            break;
                        }
                        previous = end;
                    }
                    if (error == OK && task.kind == CONTROL && previous != 0) {
                        error = BAD_TASK;
                    }
                }
                for (uint32_t j = entry.segment_begin; j < next_segment && error == OK; ++j) {
                    const auto segment = recv_read(segments + j);
                    if (segment.entry_idx != i || segment.source_lane_idx >= uint32_t(num_source_lanes) ||
                        segment.local_expert_idx >= uint32_t(experts_per_rank) || segment.num_routes == 0) {
                        error = BAD_TASK;
                        break;
                    }
                    bool found = false;
                    for (uint32_t m = entry.member_begin; m < next_member; ++m) {
                        found |= recv_read(members + m).source_lane_idx == segment.source_lane_idx;
                    }
                    if (!found) {
                        error = BAD_TASK;
                        break;
                    }
                    const auto address = recv_read(addresses + uint64_t(segment.source_lane_idx) * uint32_t(num_ranks) +
                                                   uint32_t(rank_idx));
                    auto prefix = reinterpret_cast<__gm__ const uint32_t *>(reinterpret_cast<__gm__ uint8_t *>(buffer) +
                                                                            address.prefix_offset);
                    const uint64_t begin =
                        segment.local_expert_idx == 0 ? 0 : recv_read(prefix + (segment.local_expert_idx - 1));
                    const uint64_t end = recv_read(prefix + segment.local_expert_idx);
                    if (segment.route_begin < begin || segment.route_begin > end ||
                        segment.num_routes > end - segment.route_begin) {
                        error = BAD_ROUTE;
                        break;
                    }
                    rows += segment.num_routes;
                }
                if (error == OK && rows != entry.num_rows) {
                    error = BAD_TASK;
                }
                total += rows;
            }
            if (error == OK && (next_member != task.num_members || next_segment != task.num_segments ||
                                total != task.num_expanded_tokens)) {
                error = BAD_TASK;
            }
            if (error == OK && ((task.kind == WORK && total == 0) ||
                                (task.kind == CONTROL && (total || task.num_segments || task.num_padded_tokens)))) {
                error = BAD_TASK;
            }
            // All Segment addresses/counts are checked before sorting. The
            // first order detects duplicate input intervals; the second proves
            // exact dense expert output intervals, including holes/overlaps.
            // Only this core accesses the indices; output remains untouched.
            if (error == OK) {
                auto index = reinterpret_cast<__gm__ uint32_t *>(ws + recv_workspace_bytes(p.num_vec_cores));
                auto scratch = reinterpret_cast<__gm__ uint32_t *>(
                    reinterpret_cast<__gm__ uint8_t *>(index) +
                    recv_segment_index_bytes(p.num_source_lanes, p.num_experts / p.num_ranks, p.max_expanded_tokens));
                auto ordered = recv_sort_segments<false>(segments, index, scratch, task.num_segments, tmp);
                AFDActiveSegment previous{};
                for (uint32_t j = 0; j < task.num_segments && error == OK; ++j) {
                    const auto segment = recv_read(segments + recv_read(ordered + j));
                    if (j && previous.source_lane_idx == segment.source_lane_idx &&
                        previous.local_expert_idx == segment.local_expert_idx &&
                        uint64_t(segment.route_begin) < uint64_t(previous.route_begin) + previous.num_routes) {
                        error = BAD_ROUTE;
                    }
                    previous = segment;
                }
                if (error == OK) {
                    ordered = recv_sort_segments<true>(segments, index, scratch, task.num_segments, tmp);
                    uint64_t physical = 0;
                    uint32_t next = 0;
                    for (int e = 0; e < experts_per_rank && error == OK; ++e) {
                        uint64_t count = 0;
                        while (next < task.num_segments) {
                            const auto segment = recv_read(segments + recv_read(ordered + next));
                            if (segment.local_expert_idx != uint32_t(e)) {
                                break;
                            }
                            if (segment.dst_row_begin != physical + count) {
                                error = BAD_TASK;
                                break;
                            }
                            count += segment.num_routes;
                            ++next;
                        }
                        const uint64_t padded = (count + uint64_t(expert_alignment) - 1) / uint64_t(expert_alignment) *
                                                uint64_t(expert_alignment);
                        if (physical > max_padded_tokens || padded > uint64_t(max_padded_tokens) - physical) {
                            error = CAPACITY;
                            break;
                        }
                        physical += padded;
                    }
                    if (error == OK && (next != task.num_segments || physical != task.num_padded_tokens)) {
                        error = BAD_TASK;
                    }
                }
            }
        }
        for (int i = 0; i < 8; ++i) {
            words[i] = 0;
        }
        words[0] = error;
        recv_store(result, tmp, 32);
        if (error != OK) {
            recv_load(tmp, execution_state, 32);
            words[0] = ABORTED;
            words[1] = error;
            recv_store(execution_state, tmp, 32);
        }
    }
    recv_join();
    recv_load(tmp, result, 32);
    if (words[0] != OK || task.kind == NOP) {
        return;
    }
    if (task.kind == WORK) {
        auto ab = reinterpret_cast<__gm__ const uint8_t *>(active);
        auto segments = reinterpret_cast<__gm__ const AFDActiveSegment *>(ab + task.segments_offset);
        auto base = reinterpret_cast<__gm__ const uint8_t *>(context);
        auto addresses = reinterpret_cast<__gm__ const AFDAddress *>(base + context->addresses_offset);
        auto lanes = reinterpret_cast<__gm__ const AFDLane *>(base + context->lanes_offset);
        const uint32_t start =
            uint32_t(uint64_t(task.num_padded_tokens) * uint32_t(vec_core_idx) / uint32_t(num_vec_cores));
        const uint32_t end =
            uint32_t(uint64_t(task.num_padded_tokens) * uint32_t(vec_core_idx + 1) / uint32_t(num_vec_cores));
        constexpr auto load_cache = static_cast<uint8_t>(LD_L2CacheType::L2_CACHE_HINT_NOTALLOC_CLEAN);
        constexpr auto store_cache = static_cast<uint8_t>(ST_L2CacheType::L2_CACHE_HINT_NOTALLOC_CI);

        // R2 [AFD] Parallel route/record metadata preflight and all-core error vote.
        // Phase 1 checked every directory and interval before any worker follows
        // a route. Phase 2 is parallel, metadata-only and commits no output.
        // Assign by destination intersection so skewed expert distributions still
        // divide across cores. The existing 32B/core scratch holds error votes.
        uint32_t error = OK;
        for (uint32_t j = 0; j < task.num_segments && error == OK; ++j) {
            const auto segment = recv_read(segments + j);
            const uint32_t begin = segment.dst_row_begin > start ? segment.dst_row_begin : start;
            const uint32_t segment_end = segment.dst_row_begin + segment.num_routes;
            const uint32_t limit = segment_end < end ? segment_end : end;
            if (begin >= limit) {
                continue;
            }
            const auto address =
                recv_read(addresses + uint64_t(segment.source_lane_idx) * uint32_t(num_ranks) + uint32_t(rank_idx));
            const auto lane = recv_read(lanes + segment.source_lane_idx);
            recv_load(tmp, reinterpret_cast<__gm__ uint8_t *>(control_buffer) + address.inbox_offset, 64);
            const auto inbox = recv_read_inbox_ubuf(tmp);
            auto refs = reinterpret_cast<__gm__ const uint32_t *>(reinterpret_cast<__gm__ uint8_t *>(buffer) +
                                                                  address.route_reference_offset);
            for (uint32_t row = begin; row < limit && error == OK;) {
                const uint32_t num_stage_tokens =
                    uint32_t(num_tokens_per_stage) < limit - row ? uint32_t(num_tokens_per_stage) : limit - row;
                recv_load(ub_refs, refs + segment.route_begin + row - segment.dst_row_begin, 4 * num_stage_tokens);
                auto stage_refs = reinterpret_cast<__ubuf__ uint32_t *>(ub_refs);
                // Check ALL addresses before issuing this batch's indirect DMAs.
                for (uint32_t i = 0; i < num_stage_tokens; ++i) {
                    if (stage_refs[i] == UINT32_MAX || stage_refs[i] / uint32_t(num_topk) >= inbox.num_recv_records) {
                        error = BAD_ROUTE;
                    }
                }
                if (error != OK) {
                    break;
                }
                for (uint32_t i = 0; i < num_stage_tokens; ++i) {
                    asc_copy_gm2ub_align(ub_token + uint64_t(i) * uint64_t(num_token_bytes),
                                         reinterpret_cast<__gm__ uint8_t *>(buffer) + address.records_offset +
                                             uint64_t(stage_refs[i] / uint32_t(num_topk)) * uint64_t(num_token_bytes) +
                                             uint64_t(num_hidden_bytes),
                                         1, uint32_t(num_metadata_bytes), 0, 0, false, load_cache,
                                         uint64_t(num_metadata_bytes), uint32_t(num_metadata_bytes));
                }
                asc_sync_notify(PIPE_MTE2, PIPE_S, EVENT_ID0);
                asc_sync_wait(PIPE_MTE2, PIPE_S, EVENT_ID0);
                for (uint32_t i = 0; i < num_stage_tokens; ++i) {
                    const uint32_t slot = stage_refs[i] % uint32_t(num_topk);
                    auto metadata = ub_token + uint64_t(i) * uint64_t(num_token_bytes);
                    const auto idx = reinterpret_cast<__ubuf__ int64_t *>(metadata + token_layout.topk_idx_offset() -
                                                                          uint64_t(num_hidden_bytes))[slot];
                    const auto source = *reinterpret_cast<__ubuf__ uint32_t *>(
                        metadata + token_layout.src_token_idx_offset() - uint64_t(num_hidden_bytes));
                    const auto mask = *reinterpret_cast<__ubuf__ uint32_t *>(
                        metadata + token_layout.valid_topk_mask_offset() - uint64_t(num_hidden_bytes));
                    if (source >= inbox.num_round_tokens || source >= lane.capacity ||
                        !(mask & (uint32_t(1) << slot)) ||
                        idx != int64_t(rank_idx) * int64_t(experts_per_rank) + segment.local_expert_idx) {
                        error = BAD_ROUTE;
                    }
                    if (num_topk < 32 && (mask >> uint32_t(num_topk)) != 0) {
                        error = BAD_ROUTE;
                    }
                }
                row += num_stage_tokens;
            }
        }
        for (int i = 0; i < 8; ++i) {
            words[i] = 0;
        }
        words[0] = error;
        recv_store(ws + 32 * vec_core_idx, tmp, 32);
        recv_join();
        if (vec_core_idx == 0) {
            uint32_t first_error = OK;
            for (int i = 0; i < num_vec_cores; ++i) {
                recv_load(tmp, ws + 32 * i, 32);
                if (first_error == OK) {
                    first_error = words[0];
                }
            }
            for (int i = 0; i < 8; ++i) {
                words[i] = 0;
            }
            words[0] = first_error;
            recv_store(result, tmp, 32);
            if (first_error != OK) {
                recv_load(tmp, execution_state, 32);
                words[0] = ABORTED;
                words[1] = first_error;
                recv_store(execution_state, tmp, 32);
            }
        }
        recv_join();
        recv_load(tmp, result, 32);
        if (words[0] != OK) {
            return;
        }

        // R3 [REUSE+AFD] Native epilogue output stage boundary (kept as lambda).
        // Added four-column metadata and bounded column-major SF conversion.
        // Same stage ownership as the native epilogue: MTE2 -> S publishes a
        // loaded stage, MTE3 -> MTE2 protects refill, and a separate MTE3 -> S
        // event protects the four-column metadata stage from scalar overwrite.
        const auto issue_output = [&](int stage_idx, uint32_t row, uint32_t num_stage_tokens) __aicore__ {
            asc_sync_notify(PIPE_S, PIPE_MTE3, static_cast<event_t>(stage_idx));
            asc_sync_wait(PIPE_S, PIPE_MTE3, static_cast<event_t>(stage_idx));
            __ubuf__ uint8_t *const stage_token = ub_token + uint64_t(stage_idx) * token_stage_stride;
            for (uint32_t i = 0; i < num_stage_tokens; ++i) {
                auto record = stage_token + uint64_t(i) * uint64_t(num_token_bytes);
                asc_copy_ub2gm_align(
                    reinterpret_cast<__gm__ uint8_t *>(recv_x) + uint64_t(row + i) * uint64_t(num_hidden_bytes), record,
                    1, uint32_t(num_hidden_bytes), store_cache, uint64_t(num_hidden_bytes), uint32_t(num_hidden_bytes));
                if (num_sf_packs > 0 && recv_sf_hidden_stride == 1) {
                    asc_copy_ub2gm_align(recv_sf + uint64_t(row + i) * uint64_t(recv_sf_token_stride),
                                         reinterpret_cast<__ubuf__ int16_t *>(record + uint64_t(num_hidden_bytes)), 1,
                                         uint32_t(num_sf_packs) * 2u, store_cache, uint64_t(num_sf_packs) * 2uLL,
                                         uint32_t(align32(uint64_t(num_sf_packs) * 2u)));
                }
            }
            if (num_sf_packs > 0 && recv_sf_hidden_stride != 1) {
                // Native EP performs column conversion on host. AFD cannot add
                // a piece-sized HBM mirror: recycle the first record's DEAD
                // hidden area after hidden MTE3 completion, retaining all SF.
                // Each column has a 32B-aligned source and contains <= T packs.
                // The other token stage can be loading throughout this phase.
                EP_DEVICE_ASSERT(num_hidden_bytes >= 32);
                const int num_columns_per_stage = num_hidden_bytes / 32;
                asc_sync_notify(PIPE_MTE3, PIPE_S, static_cast<event_t>(4 + stage_idx));
                asc_sync_wait(PIPE_MTE3, PIPE_S, static_cast<event_t>(4 + stage_idx));
                for (int sf_begin = 0; sf_begin < num_sf_packs; sf_begin += num_columns_per_stage) {
                    const int columns = num_columns_per_stage < num_sf_packs - sf_begin ? num_columns_per_stage
                                                                                        : num_sf_packs - sf_begin;
                    for (int q = 0; q < columns; ++q) {
                        auto column = reinterpret_cast<__ubuf__ int16_t *>(stage_token + 32 * q);
                        for (uint32_t i = 0; i < num_stage_tokens; ++i) {
                            column[i] = reinterpret_cast<__ubuf__ int16_t *>(stage_token +
                                                                             uint64_t(i) * uint64_t(num_token_bytes) +
                                                                             uint64_t(num_hidden_bytes))[sf_begin + q];
                        }
                    }
                    asc_sync_notify(PIPE_S, PIPE_MTE3, static_cast<event_t>(4 + stage_idx));
                    asc_sync_wait(PIPE_S, PIPE_MTE3, static_cast<event_t>(4 + stage_idx));
                    // 950 C API strides are head-to-head BYTES, not the C++
                    // DataCopyPad gap/32B-unit fields. One multi-burst transfer
                    // emits the whole UB column block, retaining 32B UB sources.
                    // Host validation guarantees column-major token stride == 1.
                    asc_copy_ub2gm_align(recv_sf + uint64_t(row) * uint64_t(recv_sf_token_stride) +
                                             uint64_t(sf_begin) * uint64_t(recv_sf_hidden_stride),
                                         reinterpret_cast<__ubuf__ int16_t *>(stage_token), uint32_t(columns),
                                         2u * num_stage_tokens, store_cache,
                                         uint64_t(2) * uint64_t(recv_sf_hidden_stride), 32);
                    asc_sync_notify(PIPE_MTE3, PIPE_S, static_cast<event_t>(4 + stage_idx));
                    asc_sync_wait(PIPE_MTE3, PIPE_S, static_cast<event_t>(4 + stage_idx));
                }
            }
            asc_copy_ub2gm_align(
                recv_src_metadata + uint64_t(row) * 4,
                reinterpret_cast<__ubuf__ int32_t *>(ub_metadata + uint64_t(stage_idx) * metadata_stage_stride), 1,
                16u * num_stage_tokens, store_cache, uint64_t(16) * uint64_t(num_stage_tokens),
                uint32_t(align32(16uLL * uint32_t(num_stage_tokens))));
            asc_sync_notify(PIPE_MTE3, PIPE_MTE2, static_cast<event_t>(stage_idx));
            asc_sync_notify(PIPE_MTE3, PIPE_S, static_cast<event_t>(2 + stage_idx));
        };

        // R4 [REUSE+AFD] Native preload -> consume -> refill progression.
        // AFD Segment intersection replaces PSumIterator; do not call this the
        // native record-once/topk fanout: records can repeat across Segments.
        // Segment-major traversal replaces O(padded_rows * segments). Segment
        // order is arbitrary; validated disjoint destination intervals allow
        // independent output. A segment crossing cores is clipped, not dropped.
        for (uint32_t j = 0; j < task.num_segments; ++j) {
            const auto segment = recv_read(segments + j);
            const uint32_t begin = segment.dst_row_begin > start ? segment.dst_row_begin : start;
            const uint32_t segment_end = segment.dst_row_begin + segment.num_routes;
            const uint32_t limit = segment_end < end ? segment_end : end;
            if (begin >= limit) {
                continue;
            }
            const auto address =
                recv_read(addresses + uint64_t(segment.source_lane_idx) * uint32_t(num_ranks) + uint32_t(rank_idx));
            auto refs = reinterpret_cast<__gm__ const uint32_t *>(reinterpret_cast<__gm__ uint8_t *>(buffer) +
                                                                  address.route_reference_offset);
            uint32_t issue_row = begin;
            uint32_t stage_num_tokens[2] = {0, 0}, stage_token_base_idx[2] = {0, 0};
            bool stage_has_output[2] = {false, false};
            // Native issue_load name and stage lifetime; AFD indirect refs/gather.
            // Refs fetch precedes record-refill wait to preserve existing overlap.
            const auto issue_load = [&](int load_stage_idx, bool is_preload) __aicore__ {
                if (issue_row == limit) {
                    return false;
                }
                const uint32_t num_stage_tokens = uint32_t(num_tokens_per_stage) < limit - issue_row
                                                      ? uint32_t(num_tokens_per_stage)
                                                      : limit - issue_row;
                __ubuf__ uint8_t *const stage_refs_ub = ub_refs + uint64_t(load_stage_idx) * refs_stage_stride;
                recv_load(stage_refs_ub, refs + segment.route_begin + issue_row - segment.dst_row_begin,
                          4 * num_stage_tokens);
                auto stage_refs = reinterpret_cast<__ubuf__ uint32_t *>(stage_refs_ub);
                // refs have no MTE3 consumer: fetch them BEFORE gating record
                // refill. A synchronous ref fetch behind this event would stall
                // S until current output completed and destroy stage overlap.
                if (!is_preload) {
                    asc_sync_wait(PIPE_MTE3, PIPE_MTE2, static_cast<event_t>(load_stage_idx));
                }
                // AFD Active is an indirect gather, unlike native PSumIterator's
                // contiguous stream. Coalesce adjacent record IDs when possible.
                __ubuf__ uint8_t *const load_token = ub_token + uint64_t(load_stage_idx) * token_stage_stride;
                for (uint32_t i = 0; i < num_stage_tokens;) {
                    uint32_t run = 1;
                    while (i + run < num_stage_tokens &&
                           stage_refs[i + run] / uint32_t(num_topk) == stage_refs[i] / uint32_t(num_topk) + run) {
                        ++run;
                    }
                    // Internal record padding is the cost of coalescing; skip
                    // the final record's padding (and all padding for run == 1).
                    const uint32_t num_bytes = (run - 1) * uint32_t(num_token_bytes) + uint32_t(num_hidden_bytes) +
                                               uint32_t(num_metadata_bytes);
                    asc_copy_gm2ub_align(load_token + uint64_t(i) * uint64_t(num_token_bytes),
                                         reinterpret_cast<__gm__ uint8_t *>(buffer) + address.records_offset +
                                             uint64_t(stage_refs[i] / uint32_t(num_topk)) * uint64_t(num_token_bytes),
                                         1, num_bytes, 0, 0, false, load_cache, uint64_t(num_bytes), num_bytes);
                    i += run;
                }
                asc_sync_notify(PIPE_MTE2, PIPE_S, static_cast<event_t>(load_stage_idx));
                stage_num_tokens[load_stage_idx] = num_stage_tokens;
                stage_token_base_idx[load_stage_idx] = issue_row;
                issue_row += num_stage_tokens;
                return true;
            };
            issue_load(0, true);
            issue_load(1, true);
            int stage_idx = 0;
            uint32_t consumed = begin;
            while (consumed < limit) {
                asc_sync_wait(PIPE_MTE2, PIPE_S, static_cast<event_t>(stage_idx));
                if (stage_has_output[stage_idx]) {
                    asc_sync_wait(PIPE_MTE3, PIPE_S, static_cast<event_t>(2 + stage_idx));
                }
                const uint32_t num_stage_tokens = stage_num_tokens[stage_idx];
                auto stage_refs =
                    reinterpret_cast<__ubuf__ uint32_t *>(ub_refs + uint64_t(stage_idx) * refs_stage_stride);
                __ubuf__ uint8_t *const stage_token = ub_token + uint64_t(stage_idx) * token_stage_stride;
                __ubuf__ int32_t *const stage_metadata =
                    reinterpret_cast<__ubuf__ int32_t *>(ub_metadata + uint64_t(stage_idx) * metadata_stage_stride);
                for (uint32_t i = 0; i < num_stage_tokens; ++i) {
                    auto out = stage_metadata + 4 * i;
                    out[0] = int32_t(segment.source_lane_idx);
                    out[1] = *reinterpret_cast<__ubuf__ int32_t *>(
                        stage_token + uint64_t(i) * uint64_t(num_token_bytes) + token_layout.src_token_idx_offset());
                    out[2] = int32_t(stage_refs[i] % uint32_t(num_topk));
                    out[3] = int32_t(segment.entry_idx);
                }
                issue_output(stage_idx, stage_token_base_idx[stage_idx], num_stage_tokens);
                stage_has_output[stage_idx] = true;
                consumed += num_stage_tokens;
                // A completed stage's release event is consumed either by refill
                // here or the drain below, never twice and never left pending.
                if (!issue_load(stage_idx, false)) {
                    asc_sync_wait(PIPE_MTE3, PIPE_MTE2, static_cast<event_t>(stage_idx));
                }
                stage_idx ^= 1;
            }
            for (int i = 0; i < 2; ++i) {
                if (stage_has_output[i]) {
                    asc_sync_wait(PIPE_MTE3, PIPE_S, static_cast<event_t>(2 + i));
                }
            }
        }

        // R5 [REUSE+AFD] Native vector fill; AFD piece-local expert padding ranges.
        // Padding is derived once per expert, rather than rediscovered for each
        // output row. Native vector fill is retained; no route or record is read.
        bool padding_initialized = false;
        uint32_t physical = 0;
        for (int e = 0; e < experts_per_rank; ++e) {
            uint32_t count = 0;
            for (uint32_t j = 0; j < task.num_segments; ++j) {
                const auto segment = recv_read(segments + j);
                if (segment.local_expert_idx == uint32_t(e)) {
                    count += segment.num_routes;
                }
            }
            const uint32_t aligned = uint32_t(expert_alignment);
            const uint32_t padded = (count + aligned - 1) / aligned * aligned;
            uint32_t row = physical + count > start ? physical + count : start;
            const uint32_t limit = physical + padded < end ? physical + padded : end;
            while (row < limit) {
                if (!padding_initialized) {
                    asc_sync_notify(PIPE_MTE3, PIPE_V, EVENT_ID0);
                    asc_sync_wait(PIPE_MTE3, PIPE_V, EVENT_ID0);
                    asc_sync_notify(PIPE_MTE2, PIPE_V, EVENT_ID0);
                    asc_sync_wait(PIPE_MTE2, PIPE_V, EVENT_ID0);
                    fill_ubuf(reinterpret_cast<__ubuf__ int *>(ub_token),
                              int(uint64_t(num_token_bytes) * uint32_t(num_tokens_per_stage) / 4u), 0);
                    fill_ubuf(reinterpret_cast<__ubuf__ int *>(ub_metadata), int(metadata_stage_stride / 4u), -1);
                    asc_sync_notify(PIPE_V, PIPE_S, EVENT_ID0);
                    asc_sync_wait(PIPE_V, PIPE_S, EVENT_ID0);
                    asc_sync_notify(PIPE_V, PIPE_MTE3, EVENT_ID0);
                    asc_sync_wait(PIPE_V, PIPE_MTE3, EVENT_ID0);
                    padding_initialized = true;
                }
                const uint32_t num_stage_tokens =
                    uint32_t(num_tokens_per_stage) < limit - row ? uint32_t(num_tokens_per_stage) : limit - row;
                issue_output(0, row, num_stage_tokens);
                asc_sync_wait(PIPE_MTE3, PIPE_MTE2, EVENT_ID0);
                asc_sync_wait(PIPE_MTE3, PIPE_S, EVENT_ID2);
                row += num_stage_tokens;
            }
            physical += padded;
        }
    }
    // R6 [AFD] Commit INPUT_READY after all output DMAs. No ACK, credit,
    // scheduler selection or remote poll is performed by this operator.
    recv_join(); // every output DMA has completed before INPUT_READY is published
    if (vec_core_idx == 0) {
        recv_load(tmp, execution_state, 32);
        words[0] = INPUT_READY;
        words[1] = OK;
        recv_store(execution_state, tmp, 32);
    }
}
} // namespace deep_ep::afd::rt
