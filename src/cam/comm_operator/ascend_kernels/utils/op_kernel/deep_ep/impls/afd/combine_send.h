/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2026-2026. All rights reserved.
 * Description: Combine send device implementation.
 * Create: 2026-11-03
 * Note: Device header for the CAM DeepEP-compatible operators.
 * History: 2026-11-03 create for the cam_deepep operators
 */
#pragma once
#include <deep_ep/impls/afd/dispatch_send.h>
#include <deep_ep/impls/afd/dispatch_recv.h>
#include <deep_ep/layout/afd/return.h>

// Upstream: impls/ep/combine.hpp (3b25377d), single-slot x-direct branch.
// ### PATCH START: AFD reverse transport without collective/rank partial reduction
namespace deep_ep::afd {
template <int NA, int L, int T, int NC> struct alignas(kNumUbAlignmentBytes) CombineSendUB {
    alignas(kNumUbAlignmentBytes) handle::HcommPeerInfo peer_infos[NA];
    alignas(kNumUbAlignmentBytes) uint8_t jetty_info[NC][NA][96], ub_sqe[512];
    alignas(kNumUbAlignmentBytes) int metadata[2][T][4];
    alignas(kNumUbAlignmentBytes) int lane_to_entry[L], lane_to_member[L];
    alignas(kNumUbAlignmentBytes) uint8_t control[256];
};

// Added source-lane/entry metadata replaces native K+2 local-rank partials.
// Payload remains the original registered x pointer, with native SQ/CQ accounting.
template <int NA, int N, int R, int K, int H, int NC, int L, int NL, int QA, int T, int U, int64_t Timeout>
__aicore__ void combine_send_impl(__gm__ bfloat16_t *x, __gm__ int *src_metadata,
                                  __gm__ const AFDContextLayout *context, __gm__ const AFDActive *active,
                                  __gm__ void *control_buffer, __gm__ AFDExecutionState *execution_state,
                                  __gm__ void *workspace, __gm__ void *jetty_ptrs, __gm__ AFDCompletion *completion,
                                  const int rank_idx)
{
    AscendC::InitSocState();
    using UB = CombineSendUB<NA, L, T, NC>;
    static_assert(sizeof(UB) <= U && T > 0 && T <= 128 && R <= 512);
    const int vec_core_idx = AscendC::GetBlockIdx();
    auto ub = reinterpret_cast<__ubuf__ UB *>(0);
    auto tmp = ub->control;
    auto words = reinterpret_cast<__ubuf__ uint32_t *>(tmp);
    auto ws = reinterpret_cast<__gm__ uint8_t *>(workspace);
    auto result = reinterpret_cast<__gm__ uint32_t *>(ws + 32 * NC);
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
                    done.num_members != task.num_members || done.num_deltas != uint64_t(task.num_members) * R)) {
            error = STATE_ORDER;
        }
        if (context->abi_version != kAbiVersion || context->num_src_ranks != NA || context->num_ranks != N ||
            context->num_source_lanes != L || context->num_experts != N * R || context->num_topk != K ||
            context->num_vec_cores != NC || context->num_layers != NL || rank_idx < 0 || rank_idx >= N) {
            error = BAD_ABI;
        }
        if (task.num_entries == 0 || task.num_entries > L || task.num_members > L ||
            task.num_segments > uint64_t(L) * R || task.num_padded_tokens > QA ||
            task.num_expanded_tokens > task.num_padded_tokens || task.entries_offset != active_entries_offset() ||
            task.members_offset != active_members_offset(L) || task.segments_offset != active_segments_offset(L)) {
            error = BAD_TASK;
        }
        if (!recv_range(context->reserved_address, 32, context->context_bytes) || context->reserved_address == 0) {
            error = BAD_ABI;
        }
        if (error == OK) {
            const auto directory =
                recv_read(reinterpret_cast<__gm__ const AFDReturnDirectory *>(base + context->reserved_address));
            if (directory.version != 1 || directory.return_stride < 2 * H || directory.return_stride % 512 ||
                !recv_range(directory.source_peers_offset, 32 * uint64_t(NA), context->context_bytes) ||
                !recv_range(directory.lanes_offset, 32 * uint64_t(L), context->context_bytes) ||
                !recv_range(context->lanes_offset, 32 * uint64_t(L), context->context_bytes) ||
                !recv_range(context->addresses_offset, 64 * uint64_t(L) * N, context->context_bytes) ||
                !recv_range(context->layers_offset, 4 * uint64_t(NL), context->context_bytes)) {
                error = BAD_ABI;
            }
            bool found = false;
            if (error == OK) {
                for (int i = 0; i < NL; ++i) {
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
    for (int l = 0; l < L; ++l) {
        ub->lane_to_entry[l] = ub->lane_to_member[l] = -1;
    }
    uint64_t next_member = 0, next_segment = 0, total = 0;
    for (uint32_t i = 0; i < task.num_entries && error == OK; ++i) {
        const auto entry = recv_read(entries + i);
        if (entry.member_begin != next_member || entry.num_members == 0 ||
            entry.num_members > task.num_members - next_member || entry.segment_begin != next_segment ||
            entry.num_segments > task.num_segments - next_segment || entry.pending_idx >= L || entry.is_final > 1 ||
            entry.grant_state > HELD || recv_read(grants + i) != entry.grant_state) {
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
            if (l >= L || member.input_bit > 1 || member.return_bit > 1 || member.num_experts != R ||
                member.delta_begin != m * uint64_t(R) || ub->lane_to_entry[l] != -1) {
                error = BAD_TASK;
                break;
            }
            ub->lane_to_entry[l] = i;
            ub->lane_to_member[l] = m;
            const auto lane = recv_read(lanes + l);
            const auto ret = recv_read(return_lanes + l);
            if (lane.src_rank_idx >= NA || lane.capacity == 0 || lane.capacity > kMaxLaneTokens ||
                lane.phase != task.phase) {
                error = BAD_ABI;
                break;
            }
            const auto peer = recv_read(source_peers + lane.src_rank_idx);
            if (!recv_range(ret.return_offset, uint64_t(lane.capacity) * K * directory.return_stride,
                            peer.payload_bytes) ||
                !recv_range(ret.credit_offset, 32, context->control_bytes) ||
                !recv_range(ret.done_offset + uint64_t(rank_idx) * 64, 32, peer.control_bytes) ||
                !recv_range(addresses[uint64_t(l) * N + rank_idx].consumed_offset, 32, peer.control_bytes)) {
                error = BAD_ABI;
            }
        }
        uint64_t rows = 0;
        for (uint32_t s = entry.segment_begin; s < next_segment && error == OK; ++s) {
            const auto segment = recv_read(segments + s);
            if (segment.entry_idx != i || segment.source_lane_idx >= L || segment.local_expert_idx >= R ||
                ub->lane_to_entry[segment.source_lane_idx] != int(i) || segment.num_routes == 0 ||
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
    const uint32_t begin = uint64_t(task.num_padded_tokens) * vec_core_idx / NC;
    const uint32_t end = uint64_t(task.num_padded_tokens) * (vec_core_idx + 1) / NC;
    auto issue_load = [&](uint32_t row, int stage_idx) __aicore__ {
        const uint32_t count = end - row < T ? end - row : T;
        asc_sync_notify(PIPE_S, PIPE_MTE2, static_cast<event_t>(EVENT_ID2 + stage_idx));
        asc_sync_wait(PIPE_S, PIPE_MTE2, static_cast<event_t>(EVENT_ID2 + stage_idx));
        asc_copy_gm2ub_align(reinterpret_cast<__ubuf__ uint8_t *>(ub->metadata[stage_idx]),
                             reinterpret_cast<__gm__ uint8_t *>(src_metadata + uint64_t(row) * 4), 1, 16 * count, 0, 0,
                             false, static_cast<uint8_t>(LD_L2CacheType::L2_CACHE_HINT_NOTALLOC_CLEAN),
                             uint64_t(16 * count), align32(16 * count));
        asc_sync_notify(PIPE_MTE2, PIPE_S, static_cast<event_t>(EVENT_ID2 + stage_idx));
    };
    // Parallel preflight before any payload: bad metadata cannot leave partial writes.
    uint32_t num_valid = 0;
    if (begin < end && error == OK) {
        issue_load(begin, 0);
        for (uint32_t row = begin, t = 0; row < end; row += T, ++t) {
            const int stage_idx = t % 2;
            asc_sync_wait(PIPE_MTE2, PIPE_S, static_cast<event_t>(EVENT_ID2 + stage_idx));
            if (row + T < end) {
                issue_load(row + T, 1 - stage_idx);
            }
            for (uint32_t j = 0; j < T && row + j < end; ++j) {
                const auto md = ub->metadata[stage_idx][j];
                if (md[0] == -1) {
                    if (md[1] != -1 || md[2] != -1 || md[3] != -1) {
                        error = BAD_ROUTE;
                    }
                    continue;
                }
                if (md[0] < 0 || md[0] >= L || md[1] < 0 || md[2] < 0 || md[2] >= K || md[3] < 0 ||
                    md[3] >= int(task.num_entries)) {
                    error = BAD_ROUTE;
                    continue;
                }
                if (ub->lane_to_entry[md[0]] != md[3] || uint32_t(md[1]) >= lanes[md[0]].capacity) {
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
        for (int c = 0; c < NC; ++c) {
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
                if (!wait_control<Timeout>(tmp, controls + return_lanes[member.source_lane_idx].credit_offset,
                                           member.return_bit)) {
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
        handle::HcommJetty j0(reinterpret_cast<__ubuf__ handle::HcommJettyInfo *>(ub->jetty_info[vec_core_idx][0]),
                              ub->ub_sqe, jetty_ptrs,
                              channel_grouped ? int(source_peers[0].peer_idx) + vec_core_idx : vec_core_idx);
        EP_DEVICE_ASSERT(j0.jetty_info->cq_depth > kNumMaxPendingWrites + kNumPollCQThreshold &&
                         (j0.jetty_info->cq_depth & (j0.jetty_info->cq_depth - 1)) == 0 &&
                         j0.jetty_info->num_wqebb_bytes == handle::kNumWQEBBBytes);
    }
    handle::HcommPeer peer(ub->peer_infos, jetty_ptrs, source_peers[0].peer_idx + (channel_grouped ? vec_core_idx : 0));
    for (int a = 1; a < NA; ++a) {
        handle::HcommPeer preload_peer(ub->peer_infos + a, jetty_ptrs,
                                       source_peers[a].peer_idx + (channel_grouped ? vec_core_idx : 0));
    }
    // [group B] Write per source peer on its own queue; drain every queue before ACKs.
    for (int a = 0; a < NA; ++a) {
        handle::HcommJetty jetty_a(reinterpret_cast<__ubuf__ handle::HcommJettyInfo *>(ub->jetty_info[vec_core_idx][a]),
                                   ub->ub_sqe, jetty_ptrs,
                                   channel_grouped ? int(source_peers[a].peer_idx) + vec_core_idx : vec_core_idx);
        EP_DEVICE_ASSERT(jetty_a.jetty_info->cq_depth > kNumMaxPendingWrites + kNumPollCQThreshold &&
                         (jetty_a.jetty_info->cq_depth & (jetty_a.jetty_info->cq_depth - 1)) == 0 &&
                         jetty_a.jetty_info->num_wqebb_bytes == handle::kNumWQEBBBytes);
        uint32_t inflight = 0, num_task_tokens = 0;
        if (begin < end) {
            issue_load(begin, 0);
            for (uint32_t row = begin, t = 0; row < end; row += T, ++t) {
                const int stage_idx = t % 2;
                asc_sync_wait(PIPE_MTE2, PIPE_S, static_cast<event_t>(EVENT_ID2 + stage_idx));
                if (row + T < end) {
                    issue_load(row + T, 1 - stage_idx);
                }
                for (uint32_t j = 0; j < T && row + j < end; ++j) {
                    const auto md = ub->metadata[stage_idx][j];
                    if (md[0] < 0) {
                        continue;
                    }
                    const auto lane = recv_read(lanes + md[0]);
                    if (int(lane.src_rank_idx) != a) {
                        continue;
                    }
                    peer.peer_info = ub->peer_infos + lane.src_rank_idx;
                    const uint64_t offset =
                        return_lanes[md[0]].return_offset + (uint64_t(md[1]) * K + md[2]) * directory.return_stride;
                    append_write_task<1, Timeout>(jetty_a, peer, offset, x + uint64_t(row + j) * H, nullptr, 2 * H, 0,
                                                  num_task_tokens, inflight);
                }
            }
        }
        issue_write_task<1, Timeout>(jetty_a, num_task_tokens, inflight);
        flush_writes<Timeout>(jetty_a, inflight);
    }
    recv_join();
    // Full independent snapshot precedes all ACKs. Nothing below reads Inbox.
    if (vec_core_idx == 0) {
        auto cb = reinterpret_cast<__gm__ uint8_t *>(completion);
        auto ce = reinterpret_cast<__gm__ AFDActiveEntry *>(cb + completion_entries_offset());
        auto cm = reinterpret_cast<__gm__ AFDActiveMember *>(cb + completion_members_offset(L));
        auto delta = reinterpret_cast<__gm__ uint32_t *>(cb + completion_deltas_offset(L));
        for (uint32_t m = 0; m < task.num_members; ++m) {
            recv_load(tmp, members + m, 32);
            recv_store(cm + m, tmp, 32);
        }
        fill_ubuf(reinterpret_cast<__ubuf__ int *>(tmp), 64, 0);
        asc_sync_notify(PIPE_V, PIPE_MTE3, EVENT_ID4);
        asc_sync_wait(PIPE_V, PIPE_MTE3, EVENT_ID4);
        for (uint64_t d = 0; d < align32(uint64_t(task.num_members) * R * 4); d += 256) {
            const uint32_t bytes = align32(uint64_t(task.num_members) * R * 4) - d < 256
                                       ? align32(uint64_t(task.num_members) * R * 4) - d
                                       : 256;
            recv_store(reinterpret_cast<__gm__ uint8_t *>(delta) + d, tmp, bytes);
        }
        for (uint32_t s = 0; s < task.num_segments; ++s) {
            const auto segment = recv_read(segments + s);
            const auto member = recv_read(members + ub->lane_to_member[segment.source_lane_idx]);
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
                                  addresses[uint64_t(l) * N + rank_idx].consumed_offset,
                              tmp);
            }
        }
        for (int w = 0; w < 8; ++w) {
            words[w] = 0;
        }
        words[0] = READY;
        words[2] = task.num_entries;
        words[3] = task.num_members;
        words[4] = task.num_members * R;
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
} // namespace deep_ep::afd
// ### PATCH END: AFD reverse transport
