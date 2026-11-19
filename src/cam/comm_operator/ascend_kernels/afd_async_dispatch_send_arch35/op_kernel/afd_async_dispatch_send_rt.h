/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2026-2026. All rights reserved.
 * Description: runtime-parameterized AFD dispatch_send body for CAM
 * Create: 2026-11-03
 * Note: model-dependent sizes are tiling fields; only dtype/path stay
 *       compile-time. Derived from afd_async/impls/afd/dispatch_send.h.
 * History: 2026-11-03 create runtime port
 *
 * CAM source: afd_async/impls/afd/dispatch_send.h (upstream and AFD sources
 * are recorded in that header).
 * CAM modifications: Takes shape from tiling and supports per-source
 * communication rounds with matching ledger entries.
 */
#pragma once
#include <climits>
#include <kernel_operator.h>
#include <simt_api/device_atomic_functions.h>
#include <simt_api/device_sync_functions.h>
#include <simt_api/device_warp_functions.h>
#include <c_api/sync/sync.h>
#include <c_api/vector_datamove/vector_datamove.h>
#include <afd_async/common/compiled.h>
#include <afd_async/comm/handle.h>
#include <afd_async/common/simt.h>
#include <afd_async/layout/afd/token.h>
#include <afd_async/impls/afd/dispatch_recv.h>
#include "afd_async_rt_common.h"

// Runtime-parameterized bounded AFD sender.
// Same phases and ordering as dispatch_send.h; every model-dependent dimension
// (ranks/experts/topk/hidden/sf/tokens/tile/cores) comes from Params at runtime.
namespace afd_async::afd::rt {
// One binary serves every model shape, so the UB regions are laid out at run
// time from Params instead of from static maxima: the contract domain (2048
// experts, topk 32, 16 KiB hidden) would need more UB than an A5 vector core
// owns. Every region starts 32-byte aligned, mirroring the native AFD layout.
struct alignas(kNumUbAlignmentBytes) Params {
    uint32_t num_ranks;
    uint32_t num_experts;
    uint32_t experts_per_rank;
    uint32_t num_topk;
    uint32_t num_tokens_per_tile;
    uint32_t num_vec_cores;
    uint32_t num_hidden_bytes;
    uint32_t num_sf_packs;
    uint32_t num_ub_bytes;
    uint64_t timeout_cycles;
};

// Byte offsets from UB address 0. The layout order matches dispatch_send.h:
// routing scratch, peer directory, per-AIV jetty rows, SQE staging, control
// staging, metadata staging.
constexpr uint32_t kSqeStagingBytes = 512;
struct UBOffsets {
    uint32_t expert_histogram, expert_cursor, rank_histogram, rank_psum;
    uint32_t dst_rank_idx, dst_slot_idx;
    uint32_t peer_info, jetty_info, ub_sqe, control_stage, metadata;
    uint32_t total;
};

__aicore__ inline uint32_t align32_up(uint32_t v)
{
    return (v + 31u) & ~31u;
}

__aicore__ inline uint32_t reserve_dispatch_region(uint32_t &at, uint32_t bytes)
{
    const uint32_t start = at;
    at = align32_up(at + bytes);
    return start;
}

__aicore__ inline void reserve_transport(UBOffsets &o, uint32_t &at, uint32_t ranks)
{
    // Transport staging (peer directory, jetty rows, SQE staging) goes first: it
    // is the only region the SIMT vector functions dereference through a runtime
    // pointer, and the VF UB window on this build is narrow, so it must stay at
    // the bottom of UB regardless of how wide the routing arrays grow.
    o.peer_info = reserve_dispatch_region(at, uint32_t(sizeof(handle::HcommPeerInfo)) * ranks);
    // Each AIV only touches its own UB, so one 96-byte jetty row per peer is
    // enough; the native layout also carried a kNumVecCores dimension.
    o.jetty_info = reserve_dispatch_region(at, 96u * ranks);
    o.ub_sqe = reserve_dispatch_region(at, kSqeStagingBytes);
}

__aicore__ inline void reserve_routing(UBOffsets &o, uint32_t &at, const Params &p)
{
    o.expert_histogram = reserve_dispatch_region(at, 4u * p.num_experts);
    o.expert_cursor = reserve_dispatch_region(at, 4u * p.num_experts);
    o.rank_histogram = reserve_dispatch_region(at, 4u * p.num_ranks);
    o.rank_psum = reserve_dispatch_region(at, 4u * p.num_ranks);
    o.dst_rank_idx = reserve_dispatch_region(at, 4u * p.num_tokens_per_tile * p.num_topk);
    o.dst_slot_idx = reserve_dispatch_region(at, 4u * p.num_tokens_per_tile * p.num_topk);
}

__aicore__ inline UBOffsets make_ub_offsets(const Params &p, uint32_t metadata_bytes)
{
    UBOffsets o{};
    uint32_t at = align32_up(uint32_t(sizeof(Params)));
    reserve_transport(o, at, p.num_ranks);
    reserve_routing(o, at, p);
    o.control_stage = reserve_dispatch_region(at, 256u);
    o.metadata = reserve_dispatch_region(at, 2u * align32_up(4u * metadata_bytes));
    o.total = at;
    return o;
}

// log2 of the largest supported rank count: 2^9 covers kNumMaxRanks = 256.
constexpr uint32_t kNumDedupRounds = 9;
constexpr int kRoutingThreads = 512;
constexpr int kRecordSges = 2; // payload and route metadata

// Runtime-bound dedup: unrolled to the max rank count, exits early at num_ranks.
__simt_callee__ __forceinline__ bool deduplicate_rt(const int &value, const int &lane_idx, const uint32_t lane_mask,
                                                    const int num_ranks)
{
    auto peers = lane_mask;
// 9 rounds cover the kNumMaxRanks=256 bound of simt::deduplicate; the guard
// keeps break out of the unrolled body so the trip count stays static.
#pragma unroll
    for (int i = 0; i < int(kNumDedupRounds); ++i) {
        if ((1 << i) <= num_ranks) {
            const auto current_bit = (static_cast<unsigned>(value) >> i) & 1u;
            const auto ones = asc_ballot(current_bit);
            peers &= ones ^ (current_bit - 1u);
        }
    }
    return (peers >> lane_idx) == 1u;
}

struct RoutingLane {
    int lane_idx, width, gl;
};

struct RouteOutputs {
    __ubuf__ int *dst_rank_idx, *dst_slot_idx;
    __gm__ uint32_t *tile_psum, *expert_prefix, *route_reference;
    __gm__ int32_t *dst_slots;
};

__simt_callee__ __forceinline__ int read_tile_expert(const RoutingLane &lane, bool live, uint64_t token,
                                                     int num_experts, int num_topk, __gm__ int64_t *topk_idx,
                                                     __gm__ uint32_t *error)
{
    int expert = -1;
    if (live && lane.gl < num_topk) {
        const int64_t value = topk_idx[(token)*num_topk + lane.gl];
        if (value < 0 || value >= int64_t(num_experts)) {
            asc_atomic_max(error, uint32_t(BAD_ROUTE));
        } else {
            expert = int(value);
        }
    }
    // Check distinct experts without truncating invalid int64 values into legal IDs.
    for (int k = 0; k < num_topk; ++k) {
        const int other = asc_shfl(expert, lane.lane_idx / lane.width * lane.width + k);
        if (live && lane.gl < num_topk && k < lane.gl && expert >= 0 && other == expert) {
            asc_atomic_max(error, uint32_t(BAD_ROUTE));
        }
    }
    return expert;
}

__simt_callee__ __forceinline__ void store_tile_route(const RouteOutputs &out, const RoutingLane &lane,
                                                      uint32_t tile_begin, uint32_t num_tokens, int num_ranks,
                                                      int num_topk, int i, int expert, int rank, bool representative,
                                                      int slot, int ordinal)
{
    if (slot >= 0) {
        slot += asc_ldcg(out.tile_psum + rank);
    }
    int record = -1;
    for (int k = 0; k < num_topk; ++k) {
        const int peer = asc_shfl(representative ? rank : -1, lane.lane_idx / lane.width * lane.width + k);
        const int value = asc_shfl(slot, lane.lane_idx / lane.width * lane.width + k);
        if (rank >= 0 && peer == rank) {
            record = value;
        }
    }
    if (i < int(num_tokens) && lane.gl < num_topk) {
        out.dst_rank_idx[i * num_topk + lane.gl] = representative ? rank : -1;
        out.dst_slot_idx[i * num_topk + lane.gl] = record;
        asc_stcg(out.dst_slots + uint64_t(tile_begin + i) * num_topk + lane.gl, record);
        if (expert >= 0) {
            const uint64_t row =
                uint64_t(asc_ldcg(out.expert_prefix + expert)) + asc_ldcg(out.tile_psum + num_ranks + expert) + ordinal;
            asc_stcg(out.route_reference + row, uint32_t(record * num_topk + lane.gl));
        }
    }
}

__simt_callee__ __forceinline__ void publish_tile_counts(int thread_idx, int num_ranks, int num_experts,
                                                         __ubuf__ const int *rank_histogram,
                                                         __ubuf__ const int *expert_histogram, __gm__ uint32_t *counts)
{
    if (thread_idx < num_ranks) {
        asc_stcg(counts + thread_idx, uint32_t(rank_histogram[thread_idx]));
    }
    if (thread_idx < num_experts) {
        asc_stcg(counts + num_ranks + thread_idx, uint32_t(expert_histogram[thread_idx]));
    }
}

template <bool kEmitRoutes>
__simt_vf__ __aicore__ __launch_bounds__(kRoutingThreads) void route_tile_rt(
    __ubuf__ Params *params, __ubuf__ int *expert_histogram, __ubuf__ int *rank_histogram, __ubuf__ int *dst_rank_idx,
    __ubuf__ int *dst_slot_idx, __gm__ int64_t *topk_idx, __gm__ uint8_t *token_mask, __gm__ uint32_t *counts,
    __gm__ uint32_t *tile_psum, __gm__ uint32_t *expert_prefix, __gm__ int32_t *dst_slots,
    __gm__ uint32_t *route_reference, __gm__ uint32_t *error, uint32_t token_begin, uint32_t tile_begin,
    uint32_t num_tokens)
{
    const int num_ranks = int(params->num_ranks), num_experts = int(params->num_experts);
    const int num_topk = int(params->num_topk), experts_per_rank = int(params->experts_per_rank);
    const int thread_idx = threadIdx.x, lane_idx = thread_idx % 32;
    // G is the routing group width, a power of two; keep shift/mask form so the
    // hot path does not pay a runtime divide.
    const int shift = num_topk <= 1 ? 0 : (32 - __builtin_clz(unsigned(num_topk - 1)));
    const int G = 1 << shift, groups = kRoutingThreads / G;
    const int g = thread_idx >> shift, gl = thread_idx & (G - 1);
    const uint32_t mask = (0xffffffffu >> (32u - uint32_t(G))) << ((uint32_t(lane_idx) >> shift) << shift);
    const RoutingLane lane{lane_idx, G, gl};
    const RouteOutputs out{dst_rank_idx, dst_slot_idx, tile_psum, expert_prefix, route_reference, dst_slots};
    if (thread_idx < num_experts) {
        expert_histogram[thread_idx] = 0;
    }
    if (thread_idx < num_ranks) {
        rank_histogram[thread_idx] = 0;
    }
    asc_syncthreads();
    const int total = ((int(num_tokens) + groups - 1) / groups) * groups;
    for (int i = g; i < total; i += groups) {
        const bool live =
            i < int(num_tokens) && (token_mask == nullptr || token_mask[uint64_t(token_begin) + tile_begin + i]);
        const int expert = read_tile_expert(lane, live, uint64_t(token_begin) + tile_begin + i, num_experts, num_topk,
                                            topk_idx, error);
        const int rank = expert < 0 ? -1 : expert / experts_per_rank;
        const bool representative = deduplicate_rt(rank, lane_idx, mask, num_ranks);
        int slot = -1;
        if (rank >= 0 && representative) {
            slot = asc_atomic_add(rank_histogram + rank, 1);
        }
        const int ordinal = expert >= 0 ? asc_atomic_add(expert_histogram + expert, 1) : -1;
        if constexpr (kEmitRoutes) {
            store_tile_route(out, lane, tile_begin, num_tokens, num_ranks, num_topk, i, expert, rank, representative,
                             slot, ordinal);
        }
    }
    asc_syncthreads();
    if constexpr (!kEmitRoutes) {
        publish_tile_counts(thread_idx, num_ranks, num_experts, rank_histogram, expert_histogram, counts);
    }
    asc_threadfence();
}

// [AFD] Runtime-parameterized orchestration boundary; same phases as dispatch_impl.
// The FP8 scale-factor gather lowers to the nddma intrinsics and takes its
// descriptor from runtime fields, so it is selected by num_sf_packs at run time
// instead of by a template argument: a BF16 launch (num_sf_packs==0) must never
// touch an empty nddma descriptor, which faults on the vector pipe.
namespace {
struct DispatchSender {
    const Params &p;
    __gm__ void *x;
    __gm__ sf_pack_t *sf;
    __gm__ int64_t *topk_idx;
    __gm__ float *topk_weights;
    __gm__ uint8_t *token_mask;
    __gm__ const AFDTaskInfo *task_info;
    __gm__ const AFDContextLayout *context;
    __gm__ void *control_buffer;
    __gm__ AFDRoundLedger *round_ledger;
    __gm__ void *workspace;
    __gm__ void *jetty_ptrs;
    __gm__ uint32_t *send_status;
    const int sf_token_stride;
    const int sf_hidden_stride;

    const int num_ranks = int(p.num_ranks), num_experts = int(p.num_experts);
    const int num_topk = int(p.num_topk), num_vec_cores = int(p.num_vec_cores);
    const int num_tokens_per_tile = int(p.num_tokens_per_tile);
    const int num_hidden_bytes = int(p.num_hidden_bytes), num_sf_packs = int(p.num_sf_packs);
    const int experts_per_rank = int(p.experts_per_rank);
    const TokenLayout token_layout{uint64_t(num_hidden_bytes), uint64_t(num_sf_packs) * 2, uint64_t(num_topk)};
    const int num_metadata_bytes = int(token_layout.metadata_stride());

    int vec_core_idx;
    uint32_t metadata_stage_bytes;
    __ubuf__ Params *params;
    __ubuf__ int *expert_histogram, *rank_histogram, *dst_rank_idx, *dst_slot_idx;
    __ubuf__ handle::HcommPeerInfo *peer_info;
    __ubuf__ uint8_t *jetty_info, *ub_sqe, *metadata, *stage;
    __ubuf__ uint32_t *words;
    __gm__ const AFDLane *lanes;
    __gm__ const AFDPeer *peers;
    __gm__ const AFDAddress *addresses;
    __gm__ const uint32_t *layers;
    __gm__ uint8_t *ws, *controls;
    AFDWorkspace w;
    __gm__ uint32_t *error, *counts, *psum, *ecounts, *eprefix, *rtotals, *refs;
    __gm__ int32_t *dst_slots;
    uint32_t lane_idx;
    AFDLane lane;
    __gm__ AFDSendState *state;
    bool channel_grouped;
    static constexpr uint32_t kNumPollCQThreshold = 10;
    static constexpr int kNumTokensPerMetadataMTE = 4;
    static constexpr int kNumMetadataMTEStages = 2;

    __aicore__ void run()
    {
        AscendC::InitSocState();
        bind_core_buffers();
        bind_directory();
        if (vec_core_idx == 0) {
            publish_admission(check_lane());
        }
        local_join();
        if (AscendC::ReadGmByPassDCache(error) != OK) {
            if (vec_core_idx == 0) {
                clear_control_words<AFDControlBlock>(words);
                words[kStatusState] = kTransferFailed;
                words[kStatusError] = AscendC::ReadGmByPassDCache(error);
                store_control(send_status, stage);
            }
            return; // all launched AIVs take this branch after the same join
        }
        bind_peer_queue();
        // Like native dispatch's peer_info preload, decode each peer once per AIV.
        // HcommPeer is a view of peer_info; rebinding the view below does not reload GM.
        handle::HcommPeer peer(peer_info, jetty_ptrs, peers[0].peer_idx + (channel_grouped ? vec_core_idx : 0));
        for (int f = 1; f < num_ranks; ++f) {
            handle::HcommPeer preload_peer(peer_info + f, jetty_ptrs,
                                           peers[f].peer_idx + (channel_grouped ? vec_core_idx : 0));
        }
        // S2 [AFD] Communication rounds, bounded by this physical lane capacity.
        // Each round: acquire slot -> route/count -> prefix -> emit/transfer -> publish.
        // Do not hoist slot waits or publish Ready across this loop.
        uint32_t current_round = 0;
        for (uint32_t round = 0; round < task_info->num_comm_rounds; ++round) {
            current_round = round;
            if (!send_round(round, peer)) {
                break;
            }
        }
        if (vec_core_idx == 0) {
            publish_status(current_round);
        }
    }

    __aicore__ void bind_core_buffers()
    {
        const auto offsets = make_ub_offsets(p, uint32_t(num_metadata_bytes));
        EP_DEVICE_ASSERT(offsets.total <= p.num_ub_bytes && handle::HcommJetty::kNumMaxSQEBytes <= kSqeStagingBytes);
        vec_core_idx = AscendC::GetBlockIdx();
        // Region 0 is the parameter block the vector functions read back.
        const auto ub = reinterpret_cast<__ubuf__ uint8_t *>(0);
        params = reinterpret_cast<__ubuf__ Params *>(ub);
        expert_histogram = reinterpret_cast<__ubuf__ int *>(ub + offsets.expert_histogram);
        rank_histogram = reinterpret_cast<__ubuf__ int *>(ub + offsets.rank_histogram);
        dst_rank_idx = reinterpret_cast<__ubuf__ int *>(ub + offsets.dst_rank_idx);
        dst_slot_idx = reinterpret_cast<__ubuf__ int *>(ub + offsets.dst_slot_idx);
        peer_info = reinterpret_cast<__ubuf__ handle::HcommPeerInfo *>(ub + offsets.peer_info);
        jetty_info = ub + offsets.jetty_info;
        ub_sqe = ub + offsets.ub_sqe;
        metadata = ub + offsets.metadata;
        // Field-by-field: a struct copy across address spaces (GM/scalar -> __ubuf__)
        // has no viable overload; scalars lower to plain UB stores on PIPE_S.
        params->num_ranks = p.num_ranks;
        params->num_experts = p.num_experts;
        params->experts_per_rank = p.experts_per_rank;
        params->num_topk = p.num_topk;
        params->num_tokens_per_tile = p.num_tokens_per_tile;
        params->num_vec_cores = p.num_vec_cores;
        params->num_hidden_bytes = p.num_hidden_bytes;
        params->num_sf_packs = p.num_sf_packs;
        params->num_ub_bytes = p.num_ub_bytes;
        params->timeout_cycles = p.timeout_cycles;
        asc_sync_notify(PIPE_S, PIPE_V, EVENT_ID7);
        asc_sync_wait(PIPE_S, PIPE_V, EVENT_ID7);
        stage = ub + offsets.control_stage;
        metadata_stage_bytes = align32_up(4u * uint32_t(num_metadata_bytes));
        words = reinterpret_cast<__ubuf__ uint32_t *>(stage);
    }

    __aicore__ void bind_directory()
    {
        const auto base = reinterpret_cast<__gm__ uint8_t *>(const_cast<__gm__ AFDContextLayout *>(context));
        lanes = reinterpret_cast<__gm__ const AFDLane *>(base + context->lanes_offset);
        peers = reinterpret_cast<__gm__ const AFDPeer *>(base + context->peers_offset);
        addresses = reinterpret_cast<__gm__ const AFDAddress *>(base + context->addresses_offset);
        layers = reinterpret_cast<__gm__ const uint32_t *>(base + context->layers_offset);
        ws = static_cast<__gm__ uint8_t *>(workspace);
        controls = static_cast<__gm__ uint8_t *>(control_buffer);
        w = recv_read(&context->workspace);
        error = reinterpret_cast<__gm__ uint32_t *>(ws + w.error_scratch);
        counts = reinterpret_cast<__gm__ uint32_t *>(ws + w.tile_counts);
        psum = reinterpret_cast<__gm__ uint32_t *>(ws + w.tile_psum);
        ecounts = reinterpret_cast<__gm__ uint32_t *>(ws + w.expert_counts);
        eprefix = reinterpret_cast<__gm__ uint32_t *>(ws + w.expert_prefix);
        rtotals = reinterpret_cast<__gm__ uint32_t *>(ws + w.rank_totals);
        dst_slots = reinterpret_cast<__gm__ int32_t *>(ws + w.dst_buffer_slot_idx);
        refs = reinterpret_cast<__gm__ uint32_t *>(ws + w.route_reference_send);
        lane_idx = context->num_source_lanes;
        for (uint32_t l = 0; l < context->num_source_lanes; ++l) {
            if (lanes[l].src_rank_idx == task_info->src_rank_idx &&
                lanes[l].payload_slot_idx == task_info->payload_slot_idx) {
                lane_idx = l;
            }
        }
    }

    __aicore__ uint32_t check_lane()
    {
        uint32_t code = OK;
        if (context->abi_version != kAbiVersion || task_info->abi_version != kAbiVersion ||
            context->return_progress_mode > RETURN_ROUND_STEP || context->comm_round_mode > kLocalCommRounds ||
            task_info->reserved[0] != context->comm_round_mode) {
            code = BAD_ABI;
        } else if (lane_idx == context->num_source_lanes || task_info->src_rank_idx != context->src_rank_idx ||
                   task_info->num_tokens > context->num_token_capacity || task_info->num_comm_rounds == 0) {
            code = BAD_TASK;
        } else {
            const uint32_t c = lanes[lane_idx].capacity;
            const uint64_t minimum = c ? (uint64_t(task_info->num_tokens) + c - 1) / c : 0;
            const uint64_t local = minimum ? minimum : 1;
            if (!c || task_info->num_comm_rounds < minimum ||
                (context->comm_round_mode == kLocalCommRounds && task_info->num_comm_rounds != local)) {
                code = BAD_TASK;
            }
            // [AFD] A blocking per-transaction recv cannot fairly release other slots.
            // Reject the unsafe family before any payload, Inbox or Ready publication.
            uint32_t num_local_lanes = 0;
            for (uint32_t l = 0; l < context->num_source_lanes; ++l) {
                num_local_lanes += lanes[l].src_rank_idx == context->src_rank_idx;
            }
            if (code == OK && context->return_progress_mode == RETURN_TRANSACTION && num_local_lanes > 1 &&
                task_info->num_comm_rounds > 1) {
                code = BAD_TASK;
            }
            bool valid_layer = false;
            for (uint32_t i = 0; i < context->num_layers; ++i) {
                valid_layer |= layers[i] == task_info->layer_idx;
            }
            if (!valid_layer) {
                code = BAD_LAYER;
            }
        }
        return code;
    }

    __aicore__ void publish_admission(uint32_t code)
    {
        AscendC::WriteGmByPassDCache(error, code);
        clear_control_words<AFDControlBlock>(words);
        words[kStatusState] = kTransferRunning;
        store_control(send_status, stage);
    }

    __aicore__ void bind_peer_queue()
    {
        // S1 [REUSE] Per-AIV HcommJetty/peer preload; asymmetric AFD peer directory.
        lane = recv_read(lanes + lane_idx);
        state = reinterpret_cast<__gm__ AFDSendState *>(ws + w.send_state) + lane.payload_slot_idx;
        // [group B] Local SQ and peer metadata come from the same (peer, AIV) channel entry.
        channel_grouped = context->channel_stride != 0;
        // Original Hcomm SQ encoder assumes kSQDepth=32768 WQEBBs. Host validates that contract.
        // Native poll_cq_when_sq_overflow starts reclaim 10 completions before wrap;
        // keep an unpublished batch strictly below that threshold (minimum CQ=64).
        {
            handle::HcommJetty j0(reinterpret_cast<__ubuf__ handle::HcommJettyInfo *>(jetty_info), ub_sqe, jetty_ptrs,
                                  channel_grouped ? int(peers[0].peer_idx) + vec_core_idx : vec_core_idx);
            EP_DEVICE_ASSERT(j0.jetty_info->cq_depth > kNumMaxPendingWrites + kNumPollCQThreshold &&
                             (j0.jetty_info->cq_depth & (j0.jetty_info->cq_depth - 1)) == 0 &&
                             j0.jetty_info->num_wqebb_bytes == handle::kNumWQEBBBytes);
        }
    }

    __aicore__ bool wait_for_slot(__gm__ AFDRoundLedger *ledger)
    {
        if (vec_core_idx == 0) {
            load_control(stage, state);
            const auto previous = recv_read_send_state_ubuf(stage);
            bool ready = true;
            if (previous.has_published) {
                for (int f = 0; f < num_ranks; ++f) {
                    ready = wait_control(stage, controls + addresses[lane_idx * num_ranks + f].consumed_offset,
                                         previous.last_input_bit, p.timeout_cycles) &&
                            ready;
                }
            }
            ready = wait_control(stage, ledger, 0, p.timeout_cycles) && ready;
            if (!ready) {
                AscendC::WriteGmByPassDCache(error, uint32_t(TIMEOUT));
            }
        }
        local_join();
        return AscendC::ReadGmByPassDCache(error) == OK;
    }

    __aicore__ void count_routes(uint32_t tiles, uint32_t length, uint32_t begin)
    {
        for (uint32_t tile = uint32_t(vec_core_idx); tile < tiles; tile += uint32_t(num_vec_cores)) {
            // S2.2 [REUSE+AFD] Warp rank dedup/histogram; AFD mask and route validation.
            AscendC::Simt::VF_CALL<route_tile_rt<false>>(
                AscendC::Simt::Dim3(kRoutingThreads, 1, 1), params, expert_histogram, rank_histogram, dst_rank_idx,
                dst_slot_idx, topk_idx, token_mask, counts + tile * uint32_t(num_ranks + num_experts),
                psum + tile * uint32_t(num_ranks + num_experts), eprefix, dst_slots, refs, error, begin,
                tile * uint32_t(num_tokens_per_tile),
                math::min(uint32_t(num_tokens_per_tile), length - tile * uint32_t(num_tokens_per_tile)));
            asc_sync_notify(PIPE_V, PIPE_S, EVENT_ID0);
            asc_sync_wait(PIPE_V, PIPE_S, EVENT_ID0);
        }
        local_join();
    }

    __aicore__ void prefix_routes(uint32_t tiles)
    {
        // S2.3 [REUSE+AFD] Histogram/prefix logic, now bounded tile columns rather than collective counts.
        // Independent prefix columns need no extra workspace. Only the final
        // expert-major exclusive prefix is ordered after all column totals exist.
        for (int column = vec_core_idx; column < num_ranks + num_experts; column += num_vec_cores) {
            uint32_t total = 0;
            for (uint32_t tile = 0; tile < tiles; ++tile) {
                AscendC::WriteGmByPassDCache(psum + tile * uint32_t(num_ranks + num_experts) + uint32_t(column), total);
                total +=
                    AscendC::ReadGmByPassDCache(counts + tile * uint32_t(num_ranks + num_experts) + uint32_t(column));
            }
            if (column < num_ranks) {
                AscendC::WriteGmByPassDCache(rtotals + column, total);
            } else {
                AscendC::WriteGmByPassDCache(ecounts + column - num_ranks, total);
            }
        }
        local_join();
        if (vec_core_idx == 0) {
            uint32_t expert_base = 0;
            for (int expert = 0; expert < num_experts; ++expert) {
                AscendC::WriteGmByPassDCache(eprefix + expert, expert_base);
                expert_base += AscendC::ReadGmByPassDCache(ecounts + expert);
            }
        }
        local_join();
    }

    __aicore__ void init_metadata_stages(int num_active_stages)
    {
        for (int stage_idx = 0; stage_idx < num_active_stages; ++stage_idx) {
            const auto ub_metadata = metadata + uint64_t(stage_idx) * uint64_t(metadata_stage_bytes);
            for (int b = 0; b < kNumTokensPerMetadataMTE * num_metadata_bytes; ++b) {
                ub_metadata[b] = 0;
            }
            const auto event = static_cast<event_t>(EVENT_ID2 + stage_idx);
            asc_sync_notify(PIPE_S, PIPE_MTE2, event);
            asc_sync_wait(PIPE_S, PIPE_MTE2, event);
            asc_sync_notify(PIPE_MTE3, PIPE_MTE2, event);
        }
    }

    __aicore__ void preload_metadata(uint32_t begin, uint32_t tile, uint32_t size, int token_idx, int stage_idx)
    {
        const auto ub_metadata = metadata + uint64_t(stage_idx) * uint64_t(metadata_stage_bytes);
        const auto event = static_cast<event_t>(EVENT_ID2 + stage_idx);
        const int num_tokens_in_stage = math::min(kNumTokensPerMetadataMTE, int(size) - token_idx);
        const uint64_t global = uint64_t(begin) + tile * uint32_t(num_tokens_per_tile) + uint64_t(token_idx);
        asc_sync_wait(PIPE_MTE3, PIPE_MTE2, event);
        if (num_sf_packs > 0) {
            const auto gm_sf = sf + global * sf_token_stride;
            if (sf_hidden_stride == 1) {
                asc_copy_gm2ub_align(reinterpret_cast<__ubuf__ sf_pack_t *>(ub_metadata), gm_sf,
                                     static_cast<uint16_t>(num_tokens_in_stage),
                                     uint32_t(num_sf_packs) * sizeof(sf_pack_t), 0, 0, false,
                                     static_cast<uint8_t>(LD_L2CacheType::L2_CACHE_HINT_NORMAL_FV),
                                     uint64_t(sf_token_stride) * sizeof(sf_pack_t), uint32_t(num_metadata_bytes));
            } else {
                const nddma_desc sf_desc(nddma_desc::loop_desc(num_tokens_in_stage,
                                                               uint32_t(num_metadata_bytes) / sizeof(sf_pack_t),
                                                               uint32_t(sf_token_stride)),
                                         nddma_desc::loop_desc(uint32_t(num_sf_packs), 1, uint32_t(sf_hidden_stride)));
                nddma_out_to_ub(reinterpret_cast<__ubuf__ sf_pack_t *>(ub_metadata), gm_sf, 0, sf_desc, 0,
                                CONSTANT_PADDING, static_cast<uint8_t>(LD_L2CacheType::L2_CACHE_HINT_NORMAL_FV));
            }
        }
        asc_copy_gm2ub_align(ub_metadata + token_layout.topk_idx_offset() - uint64_t(num_hidden_bytes),
                             reinterpret_cast<__gm__ uint8_t *>(topk_idx + global * uint64_t(num_topk)),
                             static_cast<uint16_t>(num_tokens_in_stage), uint32_t(num_topk) * 8, 0, 0, false,
                             static_cast<uint8_t>(LD_L2CacheType::L2_CACHE_HINT_NORMAL_FV), uint64_t(num_topk) * 8,
                             uint32_t(num_metadata_bytes));
        asc_copy_gm2ub_align(ub_metadata + token_layout.topk_weights_offset() - uint64_t(num_hidden_bytes),
                             reinterpret_cast<__gm__ uint8_t *>(topk_weights + global * uint64_t(num_topk)),
                             static_cast<uint16_t>(num_tokens_in_stage), uint32_t(num_topk) * 4, 0, 0, false,
                             static_cast<uint8_t>(LD_L2CacheType::L2_CACHE_HINT_NORMAL_FV), uint64_t(num_topk) * 4,
                             uint32_t(num_metadata_bytes));
        asc_sync_notify(PIPE_MTE2, PIPE_S, event);
    }

    __aicore__ void store_metadata_batch(uint32_t tile, uint32_t size, int batch_idx)
    {
        const int stage_idx = batch_idx % kNumMetadataMTEStages;
        const int first_metadata_idx = batch_idx * kNumTokensPerMetadataMTE;
        const int num_tokens_in_stage = math::min(kNumTokensPerMetadataMTE, int(size) - first_metadata_idx);
        const auto event = static_cast<event_t>(EVENT_ID2 + stage_idx);
        const auto ub_metadata = metadata + uint64_t(stage_idx) * uint64_t(metadata_stage_bytes);
        asc_sync_wait(PIPE_MTE2, PIPE_S, event);
        for (int i = 0; i < num_tokens_in_stage; ++i) {
            const auto meta = ub_metadata + i * num_metadata_bytes;
            *reinterpret_cast<__ubuf__ uint32_t *>(meta + token_layout.src_token_idx_offset() -
                                                   uint64_t(num_hidden_bytes)) =
                tile * uint32_t(num_tokens_per_tile) + uint32_t(first_metadata_idx + i);
            *reinterpret_cast<__ubuf__ uint32_t *>(meta + token_layout.valid_topk_mask_offset() -
                                                   uint64_t(num_hidden_bytes)) =
                num_topk == 32 ? UINT32_MAX : (uint32_t(1) << num_topk) - 1;
        }
        asc_sync_notify(PIPE_S, PIPE_MTE3, event);
        asc_sync_wait(PIPE_S, PIPE_MTE3, event);
        // Unlike gathered fields, completed metadata records are contiguous
        // in both UB and GM; one burst avoids any inter-burst stride/gap.
        const uint32_t num_metadata_bytes_burst = uint32_t(num_tokens_in_stage) * uint32_t(num_metadata_bytes);
        asc_copy_ub2gm_align(ws + w.metadata_send_buffer +
                                 uint64_t(tile * uint32_t(num_tokens_per_tile) + uint32_t(first_metadata_idx)) *
                                     uint64_t(num_metadata_bytes),
                             ub_metadata, 1, num_metadata_bytes_burst, asc_store_l2_cache_mode::NOTALLOC_CLEAN,
                             uint64_t(num_metadata_bytes_burst), num_metadata_bytes_burst);
        asc_sync_notify(PIPE_MTE3, PIPE_MTE2, event);
    }

    __aicore__ void stage_metadata(uint32_t begin, uint32_t tile, uint32_t size)
    {
        // Native preload_metadata / batch_idx / stage_idx progression, restricted
        // to this fixed routing tile. Metadata remains in existing GM scratch
        // until all WRITEs drain; no hidden mirror or additional workspace.
        const int num_metadata_batches = (int(size) + kNumTokensPerMetadataMTE - 1) / kNumTokensPerMetadataMTE;
        const int num_active_stages = math::min(num_metadata_batches, kNumMetadataMTEStages);
        init_metadata_stages(num_active_stages);
        for (int stage_idx = 0; stage_idx < num_active_stages; ++stage_idx) {
            preload_metadata(begin, tile, size, stage_idx * kNumTokensPerMetadataMTE, stage_idx);
        }
        for (int batch_idx = 0; batch_idx < num_metadata_batches; ++batch_idx) {
            store_metadata_batch(tile, size, batch_idx);
            const int stage_idx = batch_idx % kNumMetadataMTEStages;
            const int next_batch_idx = batch_idx + kNumMetadataMTEStages;
            if (next_batch_idx < num_metadata_batches) {
                preload_metadata(begin, tile, size, next_batch_idx * kNumTokensPerMetadataMTE, stage_idx);
            }
        }
        // Last release for each stage is consumed exactly once, including tails.
        for (int stage_idx = 0; stage_idx < num_active_stages; ++stage_idx) {
            asc_sync_wait(PIPE_MTE3, PIPE_MTE2, static_cast<event_t>(EVENT_ID2 + stage_idx));
        }
        asc_sync_notify(PIPE_MTE2, PIPE_S, EVENT_ID0);
        asc_sync_wait(PIPE_MTE2, PIPE_S, EVENT_ID0);
    }

    __aicore__ void write_tile_records(uint32_t begin, uint32_t tile, uint32_t size, handle::HcommPeer &peer)
    {
        // S2.4b [REUSE+AFD] Native combine warp-per-WQE encoding, AFD record SGEs.
        // All metadata MTE3 reads/writes above must finish before SQ publication.
        // One local queue per (AIV, peer): write per peer and drain that queue
        // before switching to the next peer, so no two queues share staging.
        for (int f = 0; f < num_ranks; ++f) {
            handle::HcommJetty jetty_f(
                reinterpret_cast<__ubuf__ handle::HcommJettyInfo *>(jetty_info + uint64_t(f) * 96u), ub_sqe, jetty_ptrs,
                channel_grouped ? int(peers[f].peer_idx) + vec_core_idx : vec_core_idx);
            EP_DEVICE_ASSERT(jetty_f.jetty_info->cq_depth > kNumMaxPendingWrites + kNumPollCQThreshold &&
                             (jetty_f.jetty_info->cq_depth & (jetty_f.jetty_info->cq_depth - 1)) == 0 &&
                             jetty_f.jetty_info->num_wqebb_bytes == handle::kNumWQEBBBytes);
            uint32_t inflight = 0;
            uint32_t num_task_tokens = 0;
            // [PERF] Fixed record base of this (lane, peer) pair: one GM read
            // per peer segment instead of one per emitted record.
            const uint64_t records_offset = addresses[lane_idx * num_ranks + f].records_offset;
            for (uint32_t i = 0; i < size; ++i) {
                const uint32_t row = tile * uint32_t(num_tokens_per_tile) + i;
                const uint32_t global = begin + row;
                const auto gm_meta = ws + w.metadata_send_buffer + uint64_t(row) * uint64_t(num_metadata_bytes);
                for (int k = 0; k < num_topk; ++k) {
                    if (dst_rank_idx[int(i) * num_topk + k] != f) {
                        continue;
                    }
                    peer.peer_info = peer_info + f;
                    const uint64_t off =
                        records_offset + uint64_t(dst_slot_idx[int(i) * num_topk + k]) * token_layout.record_stride();
                    append_write_task<kRecordSges>(
                        jetty_f, peer, off,
                        static_cast<__gm__ uint8_t *>(x) + uint64_t(global) * uint64_t(num_hidden_bytes), gm_meta,
                        uint32_t(num_hidden_bytes), uint32_t(num_metadata_bytes), num_task_tokens, inflight);
                }
            }
            issue_write_task<kRecordSges>(jetty_f, num_task_tokens, inflight);
            flush_writes(jetty_f, inflight);
        }
    }

    __aicore__ void emit_tiles(uint32_t tiles, uint32_t length, uint32_t begin, handle::HcommPeer &peer)
    {
        // S2.4 [REUSE+AFD] Second route pass and metadata/payload production per tile.
        for (uint32_t tile = uint32_t(vec_core_idx); tile < tiles; tile += uint32_t(num_vec_cores)) {
            const uint32_t size =
                math::min(uint32_t(num_tokens_per_tile), length - tile * uint32_t(num_tokens_per_tile));
            AscendC::Simt::VF_CALL<route_tile_rt<true>>(
                AscendC::Simt::Dim3(kRoutingThreads, 1, 1), params, expert_histogram, rank_histogram, dst_rank_idx,
                dst_slot_idx, topk_idx, token_mask, counts + tile * uint32_t(num_ranks + num_experts),
                psum + tile * uint32_t(num_ranks + num_experts), eprefix, dst_slots, refs, error, begin,
                tile * uint32_t(num_tokens_per_tile), size);
            asc_sync_notify(PIPE_V, PIPE_S, EVENT_ID0);
            asc_sync_wait(PIPE_V, PIPE_S, EVENT_ID0);
            stage_metadata(begin, tile, size);
            write_tile_records(begin, tile, size, peer);
        }
    }

    __aicore__ void publish_route_tables(handle::HcommPeer &peer)
    {
        // S2.5 [AFD] After all AIV payload drains: route tables -> Inbox ->
        // Ledger -> InputReady -> next bits. No early InputReady/slot release.
        // [group B] Route tables also use per-(AIV, peer) queues; drain each before publish.
        uint64_t route_base = 0;
        for (int f = 0; f < num_ranks; ++f) {
            uint32_t routes = 0;
            for (int e = 0; e < experts_per_rank; ++e) {
                routes += AscendC::ReadGmByPassDCache(ecounts + f * experts_per_rank + e);
                AscendC::WriteGmByPassDCache(eprefix + f * experts_per_rank + e, routes);
            }
            AscendC::DataSyncBarrier<AscendC::MemDsbT::DDR>();
            peer.peer_info = peer_info + f;
            handle::HcommJetty jetty_f(
                reinterpret_cast<__ubuf__ handle::HcommJettyInfo *>(jetty_info + uint64_t(f) * 96u), ub_sqe, jetty_ptrs,
                channel_grouped ? int(peers[f].peer_idx) + vec_core_idx : vec_core_idx);
            EP_DEVICE_ASSERT(jetty_f.jetty_info->cq_depth > kNumMaxPendingWrites + kNumPollCQThreshold &&
                             (jetty_f.jetty_info->cq_depth & (jetty_f.jetty_info->cq_depth - 1)) == 0 &&
                             jetty_f.jetty_info->num_wqebb_bytes == handle::kNumWQEBBBytes);
            uint32_t inflight = 0;
            const auto address = recv_read(addresses + lane_idx * num_ranks + f);
            if (routes) {
                put_at_offset(jetty_f, peer, address.route_reference_offset, refs + route_base,
                              uint64_t(routes) * sizeof(*refs), inflight);
            }
            put_at_offset(jetty_f, peer, address.count_offset, ecounts + f * experts_per_rank,
                          uint64_t(experts_per_rank) * sizeof(*ecounts), inflight);
            put_at_offset(jetty_f, peer, address.prefix_offset, eprefix + f * experts_per_rank,
                          uint64_t(experts_per_rank) * sizeof(*ecounts), inflight);
            flush_writes(jetty_f, inflight);
            route_base += routes;
        }
    }

    __aicore__ void publish_inboxes(uint32_t round, uint32_t length, const AFDSendState &saved)
    {
        for (int f = 0; f < num_ranks; ++f) {
            clear_control_words<AFDInbox>(words);
            auto inbox = reinterpret_cast<__ubuf__ AFDInbox *>(stage);
            inbox->microbatch_idx = task_info->microbatch_idx;
            inbox->layer_idx = task_info->layer_idx;
            inbox->round_idx = round;
            inbox->num_comm_rounds = task_info->num_comm_rounds;
            inbox->reserved[0] = context->comm_round_mode;
            inbox->num_round_tokens = length;
            inbox->return_bit = saved.next_return_bit;
            inbox->num_recv_records = AscendC::ReadGmByPassDCache(rtotals + f);
            store_control(reinterpret_cast<__gm__ void *>(peers[f].control_base +
                                                          addresses[lane_idx * num_ranks + f].inbox_offset),
                          stage, 64);
        }
    }

    __aicore__ void publish_ledger(__gm__ AFDRoundLedger *ledger, uint32_t round, uint32_t begin, uint32_t length,
                                   const AFDSendState &saved)
    {
        clear_control_words<AFDRoundLedger>(words);
        auto out = reinterpret_cast<__ubuf__ AFDRoundLedger *>(stage);
        out->input_bit = saved.next_input_bit;
        out->return_bit = saved.next_return_bit;
        out->round_idx = round;
        out->token_begin = begin;
        out->num_round_tokens = length;
        out->final_round = round + 1 == task_info->num_comm_rounds;
        out->microbatch_idx = task_info->microbatch_idx;
        store_control(ledger, stage, 64);
        words[0] = 1;
        store_control(ledger, stage);
    }

    __aicore__ void publish_ready(const AFDSendState &saved)
    {
        for (int f = 0; f < num_ranks; ++f) {
            clear_control_words<AFDControlBlock>(words);
            words[0] = saved.next_input_bit;
            store_control(reinterpret_cast<__gm__ void *>(peers[f].control_base +
                                                          addresses[lane_idx * num_ranks + f].input_ready_offset),
                          stage);
        }
        clear_control_words<AFDControlBlock>(words);
        auto next = reinterpret_cast<__ubuf__ AFDSendState *>(stage);
        next->next_input_bit = saved.next_input_bit ^ 1;
        next->next_return_bit = saved.next_return_bit ^ 1;
        next->has_published = 1;
        next->last_input_bit = saved.next_input_bit;
        store_control(state, stage);
    }

    __aicore__ bool send_round(uint32_t round, handle::HcommPeer &peer)
    {
        // S2.1 [AFD] Previous input Consumed + free Ledger before slot reuse.
        const auto ledger = round_ledger + uint64_t(lane.payload_slot_idx) * 2 + (round % 2);
        if (!wait_for_slot(ledger)) {
            return false;
        }
        const uint32_t begin = uint32_t(math::min(uint64_t(task_info->num_tokens), uint64_t(round) * lane.capacity));
        const uint32_t length = math::min(lane.capacity, task_info->num_tokens - begin);
        const uint32_t tiles = (length + uint32_t(num_tokens_per_tile) - 1) / uint32_t(num_tokens_per_tile);
        count_routes(tiles, length, begin);
        if (AscendC::ReadGmByPassDCache(error) != OK) {
            return false;
        }
        prefix_routes(tiles);
        emit_tiles(tiles, length, begin, peer);
        local_join();
        if (AscendC::ReadGmByPassDCache(error) != OK) {
            return false;
        }
        if (vec_core_idx == 0) {
            publish_route_tables(peer);
            load_control(stage, state);
            const AFDSendState saved = recv_read_send_state_ubuf(stage);
            publish_inboxes(round, length, saved);
            publish_ledger(ledger, round, begin, length, saved);
            publish_ready(saved);
        }
        local_join();
        return true;
    }

    __aicore__ void publish_status(uint32_t current_round)
    {
        // S3 [AFD] Publication status only, not permission to reuse the input slot.
        const uint32_t code = AscendC::ReadGmByPassDCache(error);
        clear_control_words<AFDControlBlock>(words);
        words[kStatusState] = code == OK ? kTransferComplete : kTransferFailed;
        words[kStatusError] = code;
        words[kStatusRound] = current_round;
        store_control(send_status, stage);
    }
};
} // namespace

__aicore__ inline void dispatch_body(const Params &p, __gm__ void *x, __gm__ sf_pack_t *sf, __gm__ int64_t *topk_idx,
                                     __gm__ float *topk_weights, __gm__ uint8_t *token_mask,
                                     __gm__ const AFDTaskInfo *task_info, __gm__ const AFDContextLayout *context,
                                     __gm__ void *control_buffer, __gm__ AFDRoundLedger *round_ledger,
                                     __gm__ void *workspace, __gm__ void *jetty_ptrs, __gm__ uint32_t *send_status,
                                     const int sf_token_stride, const int sf_hidden_stride)
{
    DispatchSender worker{p,          x,          sf,          topk_idx,        topk_weights,
                          token_mask, task_info,  context,     control_buffer,  round_ledger,
                          workspace,  jetty_ptrs, send_status, sf_token_stride, sf_hidden_stride};
    worker.run();
}
} // namespace afd_async::afd::rt
