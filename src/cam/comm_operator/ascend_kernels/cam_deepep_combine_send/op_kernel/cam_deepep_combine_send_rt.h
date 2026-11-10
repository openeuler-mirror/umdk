/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2026-2026. All rights reserved.
 * Description: runtime-parameterized AFD combine_send body for CAM
 * Create: 2026-11-03
 * Note: derived from deep_ep/impls/afd/combine_send.h. Every
 *       model-dependent dimension is a runtime field; H stays the hidden element
 *       count because the payload view is `__gm__ bfloat16_t*`. The UB view is
 *       laid out at run time from the shape, as in dispatch_send_rt.h: the
 *       ABI-maxima static view put ub_sqe at 36 KiB, and the SIMT write path
 *       (issue_write_wqe) then tripped aivec 341. jetty_info's V dimension is
 *       dropped (only [GetBlockIdx()][a] is ever addressed).
 * History: 2026-11-03 create runtime port
 */
#pragma once
#include <deep_ep/layout/afd/return.h>
#include "cam_deepep_rt_common.h"

// Runtime-parameterized reverse transport.
namespace deep_ep::afd::rt {
constexpr uint32_t kMaxTokensPerTile = 128;
constexpr uint32_t kMaxSourceLanes = 256;
constexpr uint32_t kMaxExpertsPerRank = 512;

struct CombineSendParams {
    uint32_t num_src_ranks;
    uint32_t num_ranks;
    uint32_t experts_per_rank;
    uint32_t num_topk;
    uint32_t num_hidden; // hidden elements (bf16), payload is 2*num_hidden bytes
    uint32_t num_vec_cores;
    uint32_t num_source_lanes;
    uint32_t num_layers;
    uint32_t max_padded_tokens;
    uint32_t num_tokens_per_tile;
    uint32_t num_ub_bytes;
    uint32_t rank_idx;
    uint64_t timeout_cycles;
};

// Byte offsets from UB address 0, sized by the actual shape instead of the ABI
// maxima. The SIMT write path hands ub_sqe and the peer rows to the vector
// unit, so both regions sit at the bottom of the view.
struct UBOffsets {
    uint32_t ub_sqe, peer_info, jetty_info, metadata, lane_to_entry, lane_to_member, control;
    uint32_t total;
};

__aicore__ inline uint32_t align32_up(uint32_t v)
{
    return (v + 31u) & ~31u;
}

// Reserve `bytes` at `at` and move the cursor to the next 32-byte boundary.
__aicore__ inline uint32_t reserve_region(uint32_t &at, uint32_t bytes)
{
    const uint32_t here = at;
    at = align32_up(at + bytes);
    return here;
}

__aicore__ inline UBOffsets make_ub_offsets(const CombineSendParams &p)
{
    UBOffsets o{};
    uint32_t at = 0;
    o.ub_sqe = reserve_region(at, 512u);
    o.peer_info = reserve_region(at, uint32_t(sizeof(handle::HcommPeerInfo)) * p.num_src_ranks);
    o.jetty_info = reserve_region(at, 96u * p.num_src_ranks);
    o.metadata = reserve_region(at, 2u * align32_up(16u * p.num_tokens_per_tile));
    o.lane_to_entry = reserve_region(at, 4u * p.num_source_lanes);
    o.lane_to_member = reserve_region(at, 4u * p.num_source_lanes);
    o.control = reserve_region(at, 256u);
    o.total = at;
    return o;
}

// Same phases as combine_send_impl: gate, directory/entry preflight, parallel
// metadata preflight, per source-peer URMA writes, completion snapshot + ACKs.
__aicore__ inline void combine_send_body(const CombineSendParams &p, __gm__ bfloat16_t *x, __gm__ int *src_metadata,
                                         __gm__ const AFDContextLayout *context, __gm__ const AFDActive *active,
                                         __gm__ void *control_buffer, __gm__ AFDExecutionState *execution_state,
                                         __gm__ void *workspace, __gm__ void *jetty_ptrs,
                                         __gm__ AFDCompletion *completion)
{
    AscendC::InitSocState();
    const int num_src_ranks = int(p.num_src_ranks), num_ranks = int(p.num_ranks);
    const int experts_per_rank = int(p.experts_per_rank), num_topk = int(p.num_topk);
    const int num_hidden = int(p.num_hidden), num_vec_cores = int(p.num_vec_cores);
    const int num_source_lanes = int(p.num_source_lanes), num_layers = int(p.num_layers);
    const int num_tokens_per_tile = int(p.num_tokens_per_tile);
    const int rank_idx = int(p.rank_idx);
    const uint32_t max_padded_tokens = p.max_padded_tokens;
    const uint64_t timeout_cycles = p.timeout_cycles;

    static_assert(kMaxTokensPerTile <= 128 && kMaxExpertsPerRank <= 512);
    EP_DEVICE_ASSERT(num_tokens_per_tile > 0 && num_tokens_per_tile <= int(kMaxTokensPerTile));
    EP_DEVICE_ASSERT(num_source_lanes > 0 && num_source_lanes <= int(kMaxSourceLanes));
    EP_DEVICE_ASSERT(num_src_ranks > 0 && num_src_ranks <= int(kNumMaxRanks));

    const int vec_core_idx = AscendC::GetBlockIdx();
    const auto o = make_ub_offsets(p);
    EP_DEVICE_ASSERT(o.total <= p.num_ub_bytes);
    auto ub = reinterpret_cast<__ubuf__ uint8_t *>(0);
    auto ub_sqe = ub + o.ub_sqe;
    auto peer_infos = reinterpret_cast<__ubuf__ handle::HcommPeerInfo *>(ub + o.peer_info);
    auto jetty_info = ub + o.jetty_info;
    auto metadata = reinterpret_cast<__ubuf__ int *>(ub + o.metadata);
    auto lane_to_entry = reinterpret_cast<__ubuf__ int *>(ub + o.lane_to_entry);
    auto lane_to_member = reinterpret_cast<__ubuf__ int *>(ub + o.lane_to_member);
    const int md_stage_ints = 4 * num_tokens_per_tile;
    auto tmp = ub + o.control;
    auto words = reinterpret_cast<__ubuf__ uint32_t *>(tmp);
    auto ws = reinterpret_cast<__gm__ uint8_t *>(workspace);
    auto result = reinterpret_cast<__gm__ uint32_t *>(ws + 32 * num_vec_cores);
    const auto task = recv_read(active);
    if (task.valid == 0 && task.kind == ABORT) {
        return;
    }
    // No source access for inactive work. The scheduler owns the EMPTY contract.
    if (task.valid == 0 && task.kind == NOP) {
        if (vec_core_idx == 0) {
            const auto state = recv_read(execution_state);
            if (task.num_entries || task.num_members || task.num_segments || task.num_expanded_tokens ||
                task.num_padded_tokens || state.stage != EMPTY || state.error_code || state.num_entries) {
                for (int i = 0; i < 8; ++i) {
                    words[i] = 0;
                }
                words[0] = ABORTED;
                words[1] = STATE_ORDER;
                recv_store(execution_state, tmp, 32);
            }
        }
        recv_join();
        return;
    }
    auto base = reinterpret_cast<__gm__ const uint8_t *>(context);
    auto ab = reinterpret_cast<__gm__ const uint8_t *>(active);
    auto controls = reinterpret_cast<__gm__ uint8_t *>(control_buffer);
    auto grants = reinterpret_cast<__gm__ uint32_t *>(reinterpret_cast<__gm__ uint8_t *>(execution_state) + 32);
    if (vec_core_idx == 0) {
        uint32_t error = OK;
        const auto state = recv_read(execution_state);
        const auto done = recv_read(completion);
        if (task.valid != 1 || (task.kind != WORK && task.kind != CONTROL)) {
            error = BAD_TASK;
        } else if (state.error_code != OK || state.num_entries != task.num_entries ||
                   state.stage != (task.kind == WORK ? COMPUTE_READY : INPUT_READY) ||
                   (done.state != ARMED || done.error_code != OK || done.num_entries != task.num_entries ||
                    done.num_members != task.num_members ||
                    done.num_deltas != uint64_t(task.num_members) * uint32_t(experts_per_rank))) {
            error = STATE_ORDER;
        }
        if (context->abi_version != kAbiVersion || context->num_src_ranks != p.num_src_ranks ||
            context->num_ranks != p.num_ranks || context->num_source_lanes != p.num_source_lanes ||
            context->num_experts != uint32_t(num_ranks) * uint32_t(experts_per_rank) ||
            context->num_topk != p.num_topk || context->num_vec_cores != p.num_vec_cores ||
            context->num_layers != p.num_layers || rank_idx < 0 || rank_idx >= num_ranks) {
            error = BAD_ABI;
        }
        if (task.num_entries == 0 || task.num_entries > uint32_t(num_source_lanes) ||
            task.num_members > uint32_t(num_source_lanes) ||
            task.num_segments > uint64_t(num_source_lanes) * uint32_t(experts_per_rank) ||
            task.num_padded_tokens > max_padded_tokens || task.num_expanded_tokens > task.num_padded_tokens ||
            task.entries_offset != active_entries_offset() ||
            task.members_offset != active_members_offset(p.num_source_lanes) ||
            task.segments_offset != active_segments_offset(p.num_source_lanes)) {
            error = BAD_TASK;
        }
        if (!recv_range(context->reserved_address, 32, context->context_bytes) || context->reserved_address == 0) {
            error = BAD_ABI;
        }
        if (error == OK) {
            const auto directory =
                recv_read(reinterpret_cast<__gm__ const AFDReturnDirectory *>(base + context->reserved_address));
            if (directory.version != 1 || directory.return_stride < 2uLL * uint64_t(num_hidden) ||
                directory.return_stride % 512 ||
                !recv_range(directory.source_peers_offset, 32uLL * p.num_src_ranks, context->context_bytes) ||
                !recv_range(directory.lanes_offset, 32uLL * p.num_source_lanes, context->context_bytes) ||
                !recv_range(context->lanes_offset, 32uLL * p.num_source_lanes, context->context_bytes) ||
                !recv_range(context->addresses_offset, 64uLL * p.num_source_lanes * p.num_ranks,
                            context->context_bytes) ||
                !recv_range(context->layers_offset, 4uLL * p.num_layers, context->context_bytes)) {
                error = BAD_ABI;
            }
            bool found = false;
            if (error == OK) {
                for (int i = 0; i < num_layers; ++i) {
                    found |= recv_read(reinterpret_cast<__gm__ const uint32_t *>(base + context->layers_offset) + i) ==
                             task.layer_idx;
                }
            }
            if (error == OK && !found) {
                error = BAD_LAYER;
            }
        }
        for (int i = 0; i < 8; ++i) {
            words[i] = 0;
        }
        words[0] = error;
        recv_store(result, tmp, 32);
    }
    recv_join();
    auto abort_if_error = [&]() __aicore__ {
        const uint32_t error = recv_read(result);
        if (error != OK && vec_core_idx == 0) {
            for (int i = 0; i < 8; ++i) {
                words[i] = 0;
            }
            words[0] = ABORTED;
            words[1] = error;
            recv_store(execution_state, tmp, 32);
        }
        return error != OK;
    };
    if (abort_if_error()) {
        return;
    }
    const auto directory =
        recv_read(reinterpret_cast<__gm__ const AFDReturnDirectory *>(base + context->reserved_address));
    auto lanes = reinterpret_cast<__gm__ const AFDLane *>(base + context->lanes_offset);
    auto addresses = reinterpret_cast<__gm__ const AFDAddress *>(base + context->addresses_offset);
    auto source_peers = reinterpret_cast<__gm__ const AFDPeer *>(base + directory.source_peers_offset);
    auto return_lanes = reinterpret_cast<__gm__ const AFDReturnLane *>(base + directory.lanes_offset);
    auto entries = reinterpret_cast<__gm__ const AFDActiveEntry *>(ab + task.entries_offset);
    auto members = reinterpret_cast<__gm__ const AFDActiveMember *>(ab + task.members_offset);
    auto segments = reinterpret_cast<__gm__ const AFDActiveSegment *>(ab + task.segments_offset);
    uint32_t error = OK;
    for (int l = 0; l < num_source_lanes; ++l) {
        lane_to_entry[l] = lane_to_member[l] = -1;
    }
    uint64_t next_member = 0, next_segment = 0, total = 0;
    for (uint32_t i = 0; i < task.num_entries && error == OK; ++i) {
        const auto entry = recv_read(entries + i);
        if (entry.member_begin != next_member || entry.num_members == 0 ||
            entry.num_members > task.num_members - next_member || entry.segment_begin != next_segment ||
            entry.num_segments > task.num_segments - next_segment || entry.pending_idx >= uint32_t(num_source_lanes) ||
            entry.is_final > 1 || entry.grant_state > HELD || recv_read(grants + i) != entry.grant_state) {
            error = BAD_TASK;
            break;
        }
        next_member += entry.num_members;
        next_segment += entry.num_segments;
        if (task.kind == CONTROL && (!entry.is_final || entry.num_rows || entry.num_segments)) {
            error = BAD_TASK;
        }
        for (uint32_t m = entry.member_begin; m < next_member && error == OK; ++m) {
            const auto member = recv_read(members + m);
            const uint32_t l = member.source_lane_idx;
            if (l >= uint32_t(num_source_lanes) || member.input_bit > 1 || member.return_bit > 1 ||
                member.num_experts != uint32_t(experts_per_rank) ||
                member.delta_begin != m * uint64_t(experts_per_rank) || lane_to_entry[l] != -1) {
                error = BAD_TASK;
                break;
            }
            lane_to_entry[l] = i;
            lane_to_member[l] = m;
            const auto lane = recv_read(lanes + l);
            const auto ret = recv_read(return_lanes + l);
            if (lane.src_rank_idx >= uint32_t(num_src_ranks) || lane.capacity == 0 || lane.capacity > kMaxLaneTokens ||
                lane.phase != task.phase) {
                error = BAD_ABI;
                break;
            }
            const auto peer = recv_read(source_peers + lane.src_rank_idx);
            if (!recv_range(ret.return_offset, uint64_t(lane.capacity) * uint64_t(num_topk) * directory.return_stride,
                            peer.payload_bytes) ||
                !recv_range(ret.credit_offset, 32, context->control_bytes) ||
                !recv_range(ret.done_offset + uint64_t(rank_idx) * 64, 32, peer.control_bytes) ||
                !recv_range(addresses[uint64_t(l) * uint32_t(num_ranks) + uint32_t(rank_idx)].consumed_offset, 32,
                            peer.control_bytes)) {
                error = BAD_ABI;
            }
        }
        uint64_t rows = 0;
        for (uint32_t s = entry.segment_begin; s < next_segment && error == OK; ++s) {
            const auto segment = recv_read(segments + s);
            if (segment.entry_idx != i || segment.source_lane_idx >= uint32_t(num_source_lanes) ||
                segment.local_expert_idx >= uint32_t(experts_per_rank) ||
                lane_to_entry[segment.source_lane_idx] != int(i) || segment.num_routes == 0 ||
                uint64_t(segment.dst_row_begin) + segment.num_routes > task.num_padded_tokens) {
                error = BAD_TASK;
            }
            rows += segment.num_routes;
        }
        if (rows != entry.num_rows) {
            error = BAD_TASK;
        }
        total += rows;
    }
    if (next_member != task.num_members || next_segment != task.num_segments || total != task.num_expanded_tokens ||
        (task.kind == CONTROL && task.num_padded_tokens)) {
        error = BAD_TASK;
    }
    // Native two metadata stages: prefetch the next task while consuming current.
    const uint32_t begin = uint64_t(task.num_padded_tokens) * uint32_t(vec_core_idx) / uint32_t(num_vec_cores);
    const uint32_t end = uint64_t(task.num_padded_tokens) * uint32_t(vec_core_idx + 1) / uint32_t(num_vec_cores);
    auto issue_load = [&](uint32_t row, int stage_idx) __aicore__ {
        const uint32_t count = end - row < uint32_t(num_tokens_per_tile) ? end - row : uint32_t(num_tokens_per_tile);
        asc_sync_notify(PIPE_S, PIPE_MTE2, static_cast<event_t>(EVENT_ID2 + stage_idx));
        asc_sync_wait(PIPE_S, PIPE_MTE2, static_cast<event_t>(EVENT_ID2 + stage_idx));
        auto stage_md = metadata + int(stage_idx) * md_stage_ints;
        asc_copy_gm2ub_align(reinterpret_cast<__ubuf__ uint8_t *>(stage_md),
                             reinterpret_cast<__gm__ uint8_t *>(src_metadata + uint64_t(row) * 4), 1, 16 * count, 0, 0,
                             false, static_cast<uint8_t>(LD_L2CacheType::L2_CACHE_HINT_NOTALLOC_CLEAN),
                             uint64_t(16 * count), align32(16 * count));
        asc_sync_notify(PIPE_MTE2, PIPE_S, static_cast<event_t>(EVENT_ID2 + stage_idx));
    };
    // Parallel preflight before any payload: bad metadata cannot leave partial writes.
    uint32_t num_valid = 0;
    if (begin < end && error == OK) {
        issue_load(begin, 0);
        for (uint32_t row = begin, t = 0; row < end; row += num_tokens_per_tile, ++t) {
            const int stage_idx = t % 2;
            asc_sync_wait(PIPE_MTE2, PIPE_S, static_cast<event_t>(EVENT_ID2 + stage_idx));
            if (row + uint32_t(num_tokens_per_tile) < end) {
                issue_load(row + uint32_t(num_tokens_per_tile), 1 - stage_idx);
            }
            for (uint32_t j = 0; j < uint32_t(num_tokens_per_tile) && row + j < end; ++j) {
                const auto md = metadata + int(stage_idx) * md_stage_ints + int(j) * 4;
                if (md[0] == -1) {
                    if (md[1] != -1 || md[2] != -1 || md[3] != -1) {
                        error = BAD_ROUTE;
                    }
                    continue;
                }
                if (md[0] < 0 || md[0] >= num_source_lanes || md[1] < 0 || md[2] < 0 || md[2] >= num_topk ||
                    md[3] < 0 || md[3] >= int(task.num_entries)) {
                    error = BAD_ROUTE;
                    continue;
                }
                if (lane_to_entry[md[0]] != md[3] || uint32_t(md[1]) >= lanes[md[0]].capacity) {
                    error = BAD_ROUTE;
                }
                ++num_valid;
            }
        }
    }
    for (int i = 0; i < 8; ++i) {
        words[i] = 0;
    }
    words[0] = error;
    words[1] = num_valid;
    recv_store(ws + 32 * vec_core_idx, tmp, 32);
    recv_join();
    if (vec_core_idx == 0) {
        uint64_t rows = 0;
        error = OK;
        for (int c = 0; c < num_vec_cores; ++c) {
            recv_load(tmp, ws + 32 * c, 32);
            if (words[0]) {
                error = words[0];
            }
            rows += words[1];
        }
        if (error == OK && rows != task.num_expanded_tokens) {
            error = BAD_ROUTE;
        }
        words[0] = error;
        recv_store(result, tmp, 32);
    }
    recv_join();
    if (abort_if_error()) {
        return;
    }
    if (vec_core_idx == 0) {
        for (uint32_t i = 0; i < task.num_entries && error == OK; ++i) {
            const auto entry = recv_read(entries + i);
            if (entry.grant_state == HELD) {
                continue;
            }
            for (uint32_t m = entry.member_begin; m < entry.member_begin + entry.num_members; ++m) {
                const auto member = recv_read(members + m);
                if (!wait_control(tmp, controls + return_lanes[member.source_lane_idx].credit_offset, member.return_bit,
                                  timeout_cycles)) {
                    error = TIMEOUT;
                    break;
                }
            }
            if (error == OK) {
                AscendC::WriteGmByPassDCache(grants + i, uint32_t(HELD));
            }
        }
        words[0] = error;
        recv_store(result, tmp, 32);
    }
    recv_join();
    if (abort_if_error()) {
        return;
    }
    // [group B] Local SQ and source-peer metadata come from the same (peer, AIV) channel entry.
    const bool channel_grouped = context->channel_stride != 0;
    constexpr uint32_t kNumPollCQThreshold = 10;
    {
        handle::HcommJetty j0(reinterpret_cast<__ubuf__ handle::HcommJettyInfo *>(jetty_info), ub_sqe, jetty_ptrs,
                              channel_grouped ? int(source_peers[0].peer_idx) + vec_core_idx : vec_core_idx);
        EP_DEVICE_ASSERT(j0.jetty_info->cq_depth > kNumMaxPendingWrites + kNumPollCQThreshold &&
                         (j0.jetty_info->cq_depth & (j0.jetty_info->cq_depth - 1)) == 0 &&
                         j0.jetty_info->num_wqebb_bytes == handle::kNumWQEBBBytes);
    }
    handle::HcommPeer peer(peer_infos, jetty_ptrs, source_peers[0].peer_idx + (channel_grouped ? vec_core_idx : 0));
    for (int a = 1; a < num_src_ranks; ++a) {
        handle::HcommPeer preload_peer(peer_infos + a, jetty_ptrs,
                                       source_peers[a].peer_idx + (channel_grouped ? vec_core_idx : 0));
    }
    // [group B] Write per source peer on its own queue; drain every queue before ACKs.
    for (int a = 0; a < num_src_ranks; ++a) {
        handle::HcommJetty jetty_a(reinterpret_cast<__ubuf__ handle::HcommJettyInfo *>(jetty_info + 96u * uint32_t(a)),
                                   ub_sqe, jetty_ptrs,
                                   channel_grouped ? int(source_peers[a].peer_idx) + vec_core_idx : vec_core_idx);
        EP_DEVICE_ASSERT(jetty_a.jetty_info->cq_depth > kNumMaxPendingWrites + kNumPollCQThreshold &&
                         (jetty_a.jetty_info->cq_depth & (jetty_a.jetty_info->cq_depth - 1)) == 0 &&
                         jetty_a.jetty_info->num_wqebb_bytes == handle::kNumWQEBBBytes);
        uint32_t inflight = 0, num_task_tokens = 0;
        if (begin < end) {
            issue_load(begin, 0);
            for (uint32_t row = begin, t = 0; row < end; row += num_tokens_per_tile, ++t) {
                const int stage_idx = t % 2;
                asc_sync_wait(PIPE_MTE2, PIPE_S, static_cast<event_t>(EVENT_ID2 + stage_idx));
                if (row + uint32_t(num_tokens_per_tile) < end) {
                    issue_load(row + uint32_t(num_tokens_per_tile), 1 - stage_idx);
                }
                for (uint32_t j = 0; j < uint32_t(num_tokens_per_tile) && row + j < end; ++j) {
                    const auto md = metadata + int(stage_idx) * md_stage_ints + int(j) * 4;
                    if (md[0] < 0) {
                        continue;
                    }
                    const auto lane = recv_read(lanes + md[0]);
                    if (int(lane.src_rank_idx) != a) {
                        continue;
                    }
                    peer.peer_info = peer_infos + lane.src_rank_idx;
                    const uint64_t offset =
                        return_lanes[md[0]].return_offset +
                        (uint64_t(md[1]) * uint32_t(num_topk) + uint32_t(md[2])) * directory.return_stride;
                    append_write_task<1>(jetty_a, peer, offset, x + uint64_t(row + j) * uint32_t(num_hidden), nullptr,
                                         uint32_t(2 * num_hidden), 0, num_task_tokens, inflight);
                }
            }
        }
        issue_write_task<1>(jetty_a, num_task_tokens, inflight);
        flush_writes(jetty_a, inflight);
    }
    recv_join();
    // Full independent snapshot precedes all ACKs. Nothing below reads Inbox.
    if (vec_core_idx == 0) {
        auto cb = reinterpret_cast<__gm__ uint8_t *>(completion);
        auto ce = reinterpret_cast<__gm__ AFDActiveEntry *>(cb + completion_entries_offset());
        auto cm = reinterpret_cast<__gm__ AFDActiveMember *>(cb + completion_members_offset(p.num_source_lanes));
        auto delta = reinterpret_cast<__gm__ uint32_t *>(cb + completion_deltas_offset(p.num_source_lanes));
        for (uint32_t m = 0; m < task.num_members; ++m) {
            recv_load(tmp, members + m, 32);
            recv_store(cm + m, tmp, 32);
        }
        fill_ubuf(reinterpret_cast<__ubuf__ int *>(tmp), 64, 0);
        asc_sync_notify(PIPE_V, PIPE_MTE3, EVENT_ID4);
        asc_sync_wait(PIPE_V, PIPE_MTE3, EVENT_ID4);
        const uint64_t total_deltas = align32(uint64_t(task.num_members) * uint32_t(experts_per_rank) * 4);
        for (uint64_t d = 0; d < total_deltas; d += 256) {
            const uint32_t bytes = uint32_t(total_deltas - d < 256 ? total_deltas - d : 256);
            recv_store(reinterpret_cast<__gm__ uint8_t *>(delta) + d, tmp, bytes);
        }
        for (uint32_t s = 0; s < task.num_segments; ++s) {
            const auto segment = recv_read(segments + s);
            const auto member = recv_read(members + lane_to_member[segment.source_lane_idx]);
            auto dst = delta + member.delta_begin + segment.local_expert_idx;
            AscendC::WriteGmByPassDCache(dst, recv_read(dst) + segment.num_routes);
        }
        for (uint32_t i = 0; i < task.num_entries; ++i) {
            recv_load(tmp, entries + i, 32);
            reinterpret_cast<__ubuf__ AFDActiveEntry *>(tmp)->grant_state =
                recv_read(entries + i).is_final ? FINISHED : HELD;
            recv_store(ce + i, tmp, 32);
        }
        AscendC::DataSyncBarrier<AscendC::MemDsbT::DDR>();
        for (uint32_t i = 0; i < task.num_entries; ++i) {
            const auto entry = recv_read(ce + i);
            if (!entry.is_final) {
                continue;
            }
            for (uint32_t m = entry.member_begin; m < entry.member_begin + entry.num_members; ++m) {
                const auto member = recv_read(cm + m);
                const auto l = member.source_lane_idx;
                for (int w = 0; w < 8; ++w) {
                    words[w] = 0;
                }
                words[0] = member.return_bit;
                store_control(reinterpret_cast<__gm__ uint8_t *>(source_peers[lanes[l].src_rank_idx].control_base) +
                                  return_lanes[l].done_offset + uint64_t(rank_idx) * 64,
                              tmp);
            }
            for (uint32_t m = entry.member_begin; m < entry.member_begin + entry.num_members; ++m) {
                const auto member = recv_read(cm + m);
                const auto l = member.source_lane_idx;
                for (int w = 0; w < 8; ++w) {
                    words[w] = 0;
                }
                words[0] = member.input_bit;
                store_control(reinterpret_cast<__gm__ uint8_t *>(source_peers[lanes[l].src_rank_idx].control_base) +
                                  addresses[uint64_t(l) * uint32_t(num_ranks) + uint32_t(rank_idx)].consumed_offset,
                              tmp);
            }
        }
        for (int w = 0; w < 8; ++w) {
            words[w] = 0;
        }
        words[0] = READY;
        words[2] = task.num_entries;
        words[3] = task.num_members;
        words[4] = task.num_members * uint32_t(experts_per_rank);
        recv_store(completion, tmp, 32);
        words[0] = COMMITTED;
        words[1] = OK;
        words[2] = task.num_entries;
        for (int w = 3; w < 8; ++w) {
            words[w] = 0;
        }
        recv_store(execution_state, tmp, 32);
    }
    recv_join();
}
} // namespace deep_ep::afd::rt
