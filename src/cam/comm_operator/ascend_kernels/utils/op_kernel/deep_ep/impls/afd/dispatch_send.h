/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2026-2026. All rights reserved.
 * Description: Dispatch send device implementation.
 * Create: 2026-11-03
 * Note: Device header for the CAM DeepEP-compatible operators.
 * History: 2026-11-03 create for the cam_deepep operators
 */
#pragma once
#include <climits>
#include <kernel_operator.h>
#include <simt_api/device_atomic_functions.h>
#include <simt_api/device_sync_functions.h>
#include <simt_api/device_warp_functions.h>
#include <c_api/sync/sync.h>
#include <c_api/vector_datamove/vector_datamove.h>
#include <deep_ep/common/compiled.h>
#include <deep_ep/comm/handle.h>
#include <deep_ep/common/simt.h>
#include <deep_ep/layout/afd/token.h>
#include <deep_ep/impls/afd/dispatch_recv.h>

// ### PATCH START: bounded AFD sender, adapted from impls/ep/dispatch.hpp at 3b25377d
namespace deep_ep::afd {
// Reading order (native 3b25377d -> AFD):
// DispatchUBLayout -> route_tile -> queue helpers -> dispatch_impl.
// [REUSE] means adapted upstream logic, not byte-identical code unless stated.
// [AFD] means a new contract/phase with no equivalent collective semantics.
// route_tile is NOT simt_persistent_worker: it runs twice per bounded tile.
// Public dispatchSend/launcher names and template argument order remain stable.
constexpr uint32_t kNumMaxPendingWrites = 32;
// [REUSE+AFD] Native DispatchUBLayout naming; AFD bounded tiles and control scratch.
template <int kNumExperts, int kNumRanks, int kNumTopk, int kNumTokensPerTile, int kNumMetadataBytes, int kNumVecCores>
struct alignas(kNumUbAlignmentBytes) DispatchUBLayout {
    alignas(kNumUbAlignmentBytes) int expert_histogram[kNumExperts], expert_cursor[kNumExperts];
    alignas(kNumUbAlignmentBytes) int rank_histogram[kNumRanks], rank_psum[kNumRanks];
    alignas(kNumUbAlignmentBytes) int dst_rank_idx[kNumTokensPerTile * kNumTopk],
        dst_slot_idx[kNumTokensPerTile * kNumTopk];
    alignas(kNumUbAlignmentBytes) handle::HcommPeerInfo peer_info[kNumRanks];
    alignas(kNumUbAlignmentBytes) uint8_t jetty_info[kNumVecCores][kNumRanks][96];
    alignas(kNumUbAlignmentBytes) uint8_t ub_sqe[512];
    alignas(kNumUbAlignmentBytes) uint8_t control_stage[256];
    alignas(kNumUbAlignmentBytes) uint8_t metadata[2][4 * kNumMetadataBytes];
};

// Original warp grouping, deduplicate and atomic histogram logic; no peer-rank self-copy.
// Added fixed tiles, full int64 validation, optional masks, and a second route-emission pass.
template <int kNumExperts, int kNumRanks, int kNumTopk, int kNumTokensPerTile, int kNumMetadataBytes, int kNumVecCores,
          bool kEmitRoutes>
__simt_vf__ __aicore__ __launch_bounds__(512) void route_tile(
    __ubuf__ DispatchUBLayout<kNumExperts, kNumRanks, kNumTopk, kNumTokensPerTile, kNumMetadataBytes, kNumVecCores> *ub,
    __gm__ int64_t *topk_idx, __gm__ uint8_t *token_mask, __gm__ uint32_t *counts, __gm__ uint32_t *tile_psum,
    __gm__ uint32_t *expert_prefix, __gm__ int32_t *dst_slots, __gm__ uint32_t *route_reference, __gm__ uint32_t *error,
    uint32_t token_begin, uint32_t tile_begin, uint32_t num_tokens)
{
    const int thread_idx = threadIdx.x, lane_idx = thread_idx % 32;
    constexpr int G = kNumTopk == 1 ? 1 : 1 << (32 - __builtin_clz(unsigned(kNumTopk - 1)));
    constexpr int groups = 512 / G;
    const int g = thread_idx / G, gl = thread_idx % G;
    const uint32_t mask = (0xffffffffu >> (32 - G)) << (lane_idx / G * G);
    if (thread_idx < kNumExperts) {
        ub->expert_histogram[thread_idx] = 0;
    }
    if (thread_idx < kNumRanks) {
        ub->rank_histogram[thread_idx] = 0;
    }
    asc_syncthreads();
    for (int i = g; i < ((num_tokens + groups - 1) / groups) * groups; i += groups) {
        const bool live =
            i < num_tokens && (token_mask == nullptr || token_mask[uint64_t(token_begin) + tile_begin + i]);
        int expert = -1;
        if (live && gl < kNumTopk) {
            const int64_t value = topk_idx[(uint64_t(token_begin) + tile_begin + i) * kNumTopk + gl];
            if (value < 0 || value >= kNumExperts) {
                asc_atomic_max(error, uint32_t(BAD_ROUTE));
            } else {
                expert = int(value);
            }
        }
        // Check distinct experts without truncating invalid int64 values into legal IDs.
        for (int k = 0; k < kNumTopk; ++k) {
            const int other = asc_shfl(expert, lane_idx / G * G + k);
            if (live && gl < kNumTopk && k < gl && expert >= 0 && other == expert) {
                asc_atomic_max(error, uint32_t(BAD_ROUTE));
            }
        }
        const int rank = expert < 0 ? -1 : expert / (kNumExperts / kNumRanks);
        const bool representative = simt::deduplicate<kNumRanks>(rank, lane_idx, mask);
        int slot = -1;
        if (rank >= 0 && representative) {
            slot = asc_atomic_add(ub->rank_histogram + rank, 1);
        }
        const int ordinal = expert >= 0 ? asc_atomic_add(ub->expert_histogram + expert, 1) : -1;
        if constexpr (kEmitRoutes) {
            if (slot >= 0) {
                slot += asc_ldcg(tile_psum + rank);
            }
            int record = -1;
            for (int k = 0; k < kNumTopk; ++k) {
                const int peer = asc_shfl(representative ? rank : -1, lane_idx / G * G + k);
                const int value = asc_shfl(slot, lane_idx / G * G + k);
                if (rank >= 0 && peer == rank) {
                    record = value;
                }
            }
            if (i < num_tokens && gl < kNumTopk) {
                ub->dst_rank_idx[i * kNumTopk + gl] = representative ? rank : -1;
                ub->dst_slot_idx[i * kNumTopk + gl] = record;
                asc_stcg(dst_slots + uint64_t(tile_begin + i) * kNumTopk + gl, record);
                if (expert >= 0) {
                    const uint64_t row =
                        uint64_t(asc_ldcg(expert_prefix + expert)) + asc_ldcg(tile_psum + kNumRanks + expert) + ordinal;
                    asc_stcg(route_reference + row, uint32_t(record * kNumTopk + gl));
                }
            }
        }
    }
    asc_syncthreads();
    if constexpr (!kEmitRoutes) {
        if (thread_idx < kNumRanks) {
            asc_stcg(counts + thread_idx, uint32_t(ub->rank_histogram[thread_idx]));
        }
        if (thread_idx < kNumExperts) {
            asc_stcg(counts + kNumRanks + thread_idx, uint32_t(ub->expert_histogram[thread_idx]));
        }
    }
    asc_threadfence();
}

// [AFD] Local AIV join only; never substitute the native all-rank barrier here.
__aicore__ inline void local_join()
{
    asc_sync_notify(PIPE_MTE3, PIPE_V, EVENT_ID0);
    asc_sync_wait(PIPE_MTE3, PIPE_V, EVENT_ID0);
    AscendC::DataSyncBarrier<AscendC::MemDsbT::DDR>();
    AscendC::SyncAll<true>();
}
// [AFD] Consumer-local control loads/stores and alternating-bit polling helpers.
__aicore__ inline void load_control(__ubuf__ uint8_t *ub, __gm__ void *src)
{
    asc_copy_gm2ub_align(ub, static_cast<__gm__ uint8_t *>(src), 1, 32, 0, 0, false,
                         static_cast<uint8_t>(LD_L2CacheType::L2_CACHE_HINT_NORMAL_FV), uint64_t(32), 32);
    asc_sync_notify(PIPE_MTE2, PIPE_S, EVENT_ID1);
    asc_sync_wait(PIPE_MTE2, PIPE_S, EVENT_ID1);
}
__aicore__ inline void store_control(__gm__ void *dst, __ubuf__ uint8_t *ub, uint32_t bytes = 32)
{
    asc_sync_notify(PIPE_S, PIPE_MTE3, EVENT_ID1);
    asc_sync_wait(PIPE_S, PIPE_MTE3, EVENT_ID1);
    asc_copy_ub2gm_align(static_cast<__gm__ uint8_t *>(dst), ub, 1, bytes, asc_store_l2_cache_mode::NOTALLOC_CLEAN,
                         uint64_t(bytes), bytes);
    asc_sync_notify(PIPE_MTE3, PIPE_S, EVENT_ID1);
    asc_sync_wait(PIPE_MTE3, PIPE_S, EVENT_ID1);
}
template <int64_t kNumTimeoutCycles>
__aicore__ inline bool wait_control(__ubuf__ uint8_t *ub, __gm__ void *src, uint32_t wanted)
{
    const uint64_t start = asc_get_system_cycle();
    do {
        load_control(ub, src);
        if (*reinterpret_cast<__ubuf__ uint32_t *>(ub) == wanted) {
            return true;
        }
    } while (uint64_t(asc_get_system_cycle()) - start < uint64_t(kNumTimeoutCycles));
    return false;
}
// Integer-only offset token: build_write_sqe never dereferences the synthetic destination.
// Reuses original bounds checks, strong ordering/fence/CQE, SQ wrap and completion accounting.
// Commit a bounded group before drain: drain must never wait for unpublished SQEs.
template <int64_t kNumTimeoutCycles> __aicore__ inline void flush_writes(handle::HcommJetty &jetty, uint32_t &inflight)
{
    if (inflight == 0) {
        return;
    }
    jetty.ring_doorbell();
    jetty.template drain<kNumTimeoutCycles>();
    inflight = 0;
}
template <int64_t kNumTimeoutCycles>
__aicore__ inline void put_at_offset(handle::HcommJetty &jetty, const handle::HcommPeer &peer, uint64_t offset,
                                     __gm__ void *src, uint64_t bytes, uint32_t &inflight)
{
    EP_DEVICE_ASSERT(bytes > 0 && bytes <= UINT32_MAX);
    EP_DEVICE_ASSERT(offset <= peer.peer_info->rmt_buffer_size && bytes <= peer.peer_info->rmt_buffer_size - offset);
    jetty.template put<kNumTimeoutCycles, false>(peer, nullptr, reinterpret_cast<__gm__ void *>(offset), src, bytes);
    if (++inflight == kNumMaxPendingWrites) {
        flush_writes<kNumTimeoutCycles>(jetty, inflight);
    }
}

// Upstream: ep/combine.hpp::load_meta_issue_wqe, one warp constructs one WQE.
// AFD differences: explicit destination offsets, 1/2 SGEs, bounded tasks and
// per-WR strong ordering/CQE retained from HcommJetty::build_write_sqe.
// Descriptors overlay the existing 512B SQE scratch; no payload/HBM mirror.
constexpr uint32_t kNumWritesPerTask = 8;
struct WriteTask {
    uint64_t peer_info_addr, remote_offset, src_addr, metadata_addr;
    uint32_t num_hidden_bytes, num_metadata_bytes;
};
static_assert(sizeof(WriteTask) == 40);
static_assert(offsetof(WriteTask, peer_info_addr) == 0);
static_assert(offsetof(WriteTask, remote_offset) == 8);
static_assert(offsetof(WriteTask, src_addr) == 16);
static_assert(offsetof(WriteTask, metadata_addr) == 24);
static_assert(offsetof(WriteTask, num_hidden_bytes) == 32);
static_assert(offsetof(WriteTask, num_metadata_bytes) == 36);
static_assert(sizeof(WriteTask) * kNumWritesPerTask <= 512);

template <int kNumSGEs>
__simt_vf__ __aicore__ __launch_bounds__(kNumWritesPerTask *warpSize) void issue_write_wqe(
    __ubuf__ const WriteTask *tasks, const uint64_t sq_base_addr, const uint32_t task_sqebb_idx,
    const uint32_t num_tokens)
{
    static_assert(kNumSGEs == 1 || kNumSGEs == 2);
    static_assert(sizeof(AscendC::HcommUrmaSqeCtx) == 48);
    static_assert(sizeof(AscendC::HcommUrmaSgeCtx) == 16);
    constexpr uint32_t kNumWQEBBsPerToken = (48 + 16 * kNumSGEs + 63) / 64;
    constexpr uint32_t kNumWQEWords = kNumWQEBBsPerToken * 8;
    const auto thread_idx = static_cast<uint32_t>(threadIdx.x);
    const auto token_idx = thread_idx / warpSize;
    const auto lane_idx = thread_idx % warpSize;
    if (token_idx < num_tokens && lane_idx < kNumWQEWords) {
        WriteTask task{};
        task.peer_info_addr = tasks[token_idx].peer_info_addr;
        task.remote_offset = tasks[token_idx].remote_offset;
        task.src_addr = tasks[token_idx].src_addr;
        task.metadata_addr = tasks[token_idx].metadata_addr;
        task.num_hidden_bytes = tasks[token_idx].num_hidden_bytes;
        task.num_metadata_bytes = tasks[token_idx].num_metadata_bytes;
        const auto peer_info_words = reinterpret_cast<__ubuf__ const uint64_t *>(task.peer_info_addr);
        const auto token_sqebb_idx = task_sqebb_idx + token_idx * kNumWQEBBsPerToken;
        uint64_t wqe_word = 0;
        if (lane_idx == 0) {
            wqe_word = handle::kWriteSQEHeaderTemplate | handle::kWriteSQEFinalFlags;
            wqe_word |= static_cast<uint64_t>((token_sqebb_idx & handle::kSQDepth) == 0) << 31;
            wqe_word |= token_sqebb_idx & (handle::kSQDepth - 1);
        }
        if (lane_idx > 0 && lane_idx < 6) {
            wqe_word = peer_info_words[lane_idx - 1];
        }
        if (lane_idx == 1) {
            wqe_word |= uint64_t(kNumSGEs) << 24;
        }
        if (lane_idx == 5) {
            wqe_word = peer_info_words[4] + task.remote_offset;
        }
        if (lane_idx == 6) {
            wqe_word = task.num_hidden_bytes;
        }
        if (lane_idx == 7) {
            wqe_word = task.src_addr;
        }
        if constexpr (kNumSGEs == 2) {
            if (lane_idx == 8) {
                wqe_word = task.num_metadata_bytes;
            }
            if (lane_idx == 9) {
                wqe_word = task.metadata_addr;
            }
        }
        // A two-BB record can straddle SQ end after an odd scalar control WR.
        // Wrap each BB, including the second BB of the same WQE.
        const auto bb_idx = (token_sqebb_idx + lane_idx / 8) & (handle::kSQDepth - 1);
        auto gm_wqe = reinterpret_cast<__gm__ uint64_t *>(sq_base_addr + uint64_t(bb_idx) * handle::kNumWQEBBBytes);
        asc_stcg(gm_wqe + lane_idx % 8, wqe_word);
    }
    asc_threadfence();
}

template <int kNumSGEs, int64_t kNumTimeoutCycles>
__aicore__ inline void issue_write_task(handle::HcommJetty &jetty, uint32_t &num_tokens, uint32_t &inflight)
{
    if (num_tokens == 0) {
        return;
    }
    constexpr uint32_t kNumWQEBBsPerToken = (48 + 16 * kNumSGEs + 63) / 64;
    static_assert(kNumMaxPendingWrites * kNumWQEBBsPerToken < handle::kSQDepth);
    if (inflight + num_tokens > kNumMaxPendingWrites) {
        flush_writes<kNumTimeoutCycles>(jetty, inflight);
    }
    // Each preceding group has drained; at most 32 CQEs/64 SQ BBs are live.
    // Existing caller checks cq_depth > 32+10, so no poll of unpublished WRs.
    const auto current_head = static_cast<uint32_t>(jetty.jetty_info->packed_head);
    asc_sync_notify(PIPE_S, PIPE_V, EVENT_ID4);
    asc_sync_wait(PIPE_S, PIPE_V, EVENT_ID4);
    AscendC::Simt::VF_CALL<issue_write_wqe<kNumSGEs>>(AscendC::Simt::Dim3(kNumWritesPerTask * warpSize, 1, 1),
                                                      reinterpret_cast<__ubuf__ const WriteTask *>(jetty.ub_sqe),
                                                      jetty.jetty_info->sq_base_addr, current_head, num_tokens);
    asc_sync_notify(PIPE_V, PIPE_S, EVENT_ID4);
    asc_sync_wait(PIPE_V, PIPE_S, EVENT_ID4);
    const auto completions = static_cast<uint32_t>(jetty.jetty_info->packed_head >> kNumHighHalfShiftBits) + num_tokens;
    jetty.jetty_info->packed_head = uint64_t(uint32_t(current_head + num_tokens * kNumWQEBBsPerToken)) |
                                    (uint64_t(completions) << kNumHighHalfShiftBits);
    inflight += num_tokens;
    num_tokens = 0;
    if (inflight == kNumMaxPendingWrites) {
        flush_writes<kNumTimeoutCycles>(jetty, inflight);
    }
}

template <int kNumSGEs, int64_t kNumTimeoutCycles>
__aicore__ inline void append_write_task(handle::HcommJetty &jetty, const handle::HcommPeer &peer, uint64_t offset,
                                         __gm__ void *x, __gm__ void *metadata_send_buffer, uint32_t num_hidden_bytes,
                                         uint32_t num_metadata_bytes, uint32_t &num_tokens, uint32_t &inflight)
{
    const uint64_t bytes = uint64_t(num_hidden_bytes) + num_metadata_bytes;
    EP_DEVICE_ASSERT(num_hidden_bytes > 0 && bytes <= UINT32_MAX);
    EP_DEVICE_ASSERT(offset <= peer.peer_info->rmt_buffer_size && bytes <= peer.peer_info->rmt_buffer_size - offset);
    auto tasks = reinterpret_cast<__ubuf__ WriteTask *>(jetty.ub_sqe);
    auto task = tasks + num_tokens;
    task->peer_info_addr = reinterpret_cast<uint64_t>(peer.peer_info);
    task->remote_offset = offset;
    task->src_addr = reinterpret_cast<uint64_t>(x);
    task->metadata_addr = reinterpret_cast<uint64_t>(metadata_send_buffer);
    task->num_hidden_bytes = num_hidden_bytes;
    task->num_metadata_bytes = num_metadata_bytes;
    ++num_tokens;
    if (num_tokens == kNumWritesPerTask) {
        issue_write_task<kNumSGEs, kNumTimeoutCycles>(jetty, num_tokens, inflight);
    }
}

// [REUSE+AFD] Native dispatch_impl orchestration boundary. Added parameters:
// token_mask, task_info, context, control_buffer, round_ledger and send_status.
// No native persistent worker/collective: keep the tiled phases below in order.
template <int kNumRanks, int kNumExperts, int kNumTopk, int kNumVecCores, int kNumHiddenBytes, int kNumSFPacks,
          int kNumMaxTokensPerRank, int kNumTokensPerTile, int kNumUbBytes, int64_t kNumTimeoutCycles>
__aicore__ void dispatch_impl(__gm__ void *x, __gm__ sf_pack_t *sf, __gm__ int64_t *topk_idx,
                              __gm__ float *topk_weights, __gm__ uint8_t *token_mask,
                              __gm__ const AFDTaskInfo *task_info, __gm__ const AFDContextLayout *context,
                              __gm__ void *control_buffer, __gm__ AFDRoundLedger *round_ledger, __gm__ void *workspace,
                              __gm__ void *jetty_ptrs, __gm__ uint32_t *send_status, const int sf_token_stride,
                              const int sf_hidden_stride)
{
    // S0 [REUSE+AFD] Init/layout, then AFD task/lane/layer validation and uniform exit.
    AscendC::InitSocState();
    constexpr TokenLayout token_layout{kNumHiddenBytes, kNumSFPacks * 2, kNumTopk};
    constexpr int kNumMetadataBytes = token_layout.metadata_stride();
    using UBLayout =
        DispatchUBLayout<kNumExperts, kNumRanks, kNumTopk, kNumTokensPerTile, kNumMetadataBytes, kNumVecCores>;
    static_assert(sizeof(UBLayout) <= kNumUbBytes && handle::HcommJetty::kNumMaxSQEBytes <= 512);
    const int vec_core_idx = AscendC::GetBlockIdx();
    const auto ub = reinterpret_cast<__ubuf__ UBLayout *>(0);
    const auto stage = ub->control_stage;
    const auto words = reinterpret_cast<__ubuf__ uint32_t *>(stage);
    const auto base = reinterpret_cast<__gm__ uint8_t *>(const_cast<__gm__ AFDContextLayout *>(context));
    const auto lanes = reinterpret_cast<__gm__ const AFDLane *>(base + context->lanes_offset);
    const auto peers = reinterpret_cast<__gm__ const AFDPeer *>(base + context->peers_offset);
    const auto addresses = reinterpret_cast<__gm__ const AFDAddress *>(base + context->addresses_offset);
    const auto layers = reinterpret_cast<__gm__ const uint32_t *>(base + context->layers_offset);
    const auto ws = static_cast<__gm__ uint8_t *>(workspace);
    const auto controls = static_cast<__gm__ uint8_t *>(control_buffer);
    const auto w = recv_read(&context->workspace);
    const auto error = reinterpret_cast<__gm__ uint32_t *>(ws + w.error_scratch);
    const auto counts = reinterpret_cast<__gm__ uint32_t *>(ws + w.tile_counts);
    const auto psum = reinterpret_cast<__gm__ uint32_t *>(ws + w.tile_psum);
    const auto ecounts = reinterpret_cast<__gm__ uint32_t *>(ws + w.expert_counts);
    const auto eprefix = reinterpret_cast<__gm__ uint32_t *>(ws + w.expert_prefix);
    const auto rtotals = reinterpret_cast<__gm__ uint32_t *>(ws + w.rank_totals);
    const auto dst_slots = reinterpret_cast<__gm__ int32_t *>(ws + w.dst_buffer_slot_idx);
    const auto refs = reinterpret_cast<__gm__ uint32_t *>(ws + w.route_reference_send);
    uint32_t lane_idx = context->num_source_lanes;
    for (uint32_t l = 0; l < context->num_source_lanes; ++l) {
        if (lanes[l].src_rank_idx == task_info->src_rank_idx &&
            lanes[l].payload_slot_idx == task_info->payload_slot_idx) {
            lane_idx = l;
        }
    }
    if (vec_core_idx == 0) {
        uint32_t code = OK;
        if (context->abi_version != kAbiVersion || task_info->abi_version != kAbiVersion ||
            context->return_progress_mode > RETURN_ROUND_STEP) {
            code = BAD_ABI;
        } else if (lane_idx == context->num_source_lanes || task_info->src_rank_idx != context->src_rank_idx ||
                   task_info->num_tokens > context->num_token_capacity || task_info->num_comm_rounds == 0) {
            code = BAD_TASK;
        } else {
            const uint32_t c = lanes[lane_idx].capacity;
            if (task_info->num_comm_rounds < (uint64_t(task_info->num_tokens) + c - 1) / c) {
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
        AscendC::WriteGmByPassDCache(error, code);
        for (int i = 0; i < 8; ++i) {
            words[i] = 0;
        }
        words[0] = 1;
        store_control(send_status, stage);
    }
    local_join();
    if (AscendC::ReadGmByPassDCache(error) != OK) {
        if (vec_core_idx == 0) {
            for (int i = 0; i < 8; ++i) {
                words[i] = 0;
            }
            words[0] = 3;
            words[1] = AscendC::ReadGmByPassDCache(error);
            store_control(send_status, stage);
        }
        return; // all launched AIVs take this branch after the same join
    }
    // S1 [REUSE] Per-AIV HcommJetty/peer preload; asymmetric AFD peer directory.
    const auto lane = recv_read(lanes + lane_idx);
    const auto state = reinterpret_cast<__gm__ AFDSendState *>(ws + w.send_state) + lane.payload_slot_idx;
    // [group B] Local SQ and peer metadata come from the same (peer, AIV) channel entry.
    const bool channel_grouped = context->channel_stride != 0;
    // Original Hcomm SQ encoder assumes kSQDepth=32768 WQEBBs. Host validates that contract.
    // Native poll_cq_when_sq_overflow starts reclaim 10 completions before wrap;
    // keep an unpublished batch strictly below that threshold (minimum CQ=64).
    constexpr uint32_t kNumPollCQThreshold = 10;
    {
        handle::HcommJetty j0(reinterpret_cast<__ubuf__ handle::HcommJettyInfo *>(ub->jetty_info[vec_core_idx][0]),
                              ub->ub_sqe, jetty_ptrs,
                              channel_grouped ? int(peers[0].peer_idx) + vec_core_idx : vec_core_idx);
        EP_DEVICE_ASSERT(j0.jetty_info->cq_depth > kNumMaxPendingWrites + kNumPollCQThreshold &&
                         (j0.jetty_info->cq_depth & (j0.jetty_info->cq_depth - 1)) == 0 &&
                         j0.jetty_info->num_wqebb_bytes == handle::kNumWQEBBBytes);
    }
    // Like native dispatch's peer_info preload, decode each peer once per AIV.
    // HcommPeer is a view of peer_info; rebinding the view below does not reload GM.
    handle::HcommPeer peer(ub->peer_info, jetty_ptrs, peers[0].peer_idx + (channel_grouped ? vec_core_idx : 0));
    for (int f = 1; f < kNumRanks; ++f) {
        handle::HcommPeer preload_peer(ub->peer_info + f, jetty_ptrs,
                                       peers[f].peer_idx + (channel_grouped ? vec_core_idx : 0));
    }
    // S2 [AFD] Communication rounds, bounded by this physical lane capacity.
    // Each round: acquire slot -> route/count -> prefix -> emit/transfer -> publish.
    // Do not hoist slot waits or publish Ready across this loop.
    uint32_t current_round = 0;
    for (uint32_t round = 0; round < task_info->num_comm_rounds; ++round) {
        current_round = round;
        // S2.1 [AFD] Previous input Consumed + free Ledger before slot reuse.
        const auto ledger = round_ledger + uint64_t(lane.payload_slot_idx) * 2 + (round % 2);
        if (vec_core_idx == 0) {
            load_control(stage, state);
            const auto previous = recv_read_send_state_ubuf(stage);
            bool ready = true;
            if (previous.has_published) {
                for (int f = 0; f < kNumRanks; ++f) {
                    ready = wait_control<kNumTimeoutCycles>(
                                stage, controls + addresses[lane_idx * kNumRanks + f].consumed_offset,
                                previous.last_input_bit) &&
                            ready;
                }
            }
            ready = wait_control<kNumTimeoutCycles>(stage, ledger, 0) && ready;
            if (!ready) {
                AscendC::WriteGmByPassDCache(error, uint32_t(TIMEOUT));
            }
        }
        local_join();
        if (AscendC::ReadGmByPassDCache(error) != OK) {
            break;
        }
        const uint32_t begin = uint32_t(math::min(uint64_t(task_info->num_tokens), uint64_t(round) * lane.capacity));
        const uint32_t length = math::min(lane.capacity, task_info->num_tokens - begin);
        const uint32_t tiles = (length + kNumTokensPerTile - 1) / kNumTokensPerTile;
        for (uint32_t tile = vec_core_idx; tile < tiles; tile += kNumVecCores) {
            // S2.2 [REUSE+AFD] Warp rank dedup/histogram; AFD mask and route validation.
            AscendC::Simt::VF_CALL<route_tile<kNumExperts, kNumRanks, kNumTopk, kNumTokensPerTile, kNumMetadataBytes,
                                              kNumVecCores, false>>(
                AscendC::Simt::Dim3(512, 1, 1), ub, topk_idx, token_mask, counts + tile * (kNumRanks + kNumExperts),
                psum + tile * (kNumRanks + kNumExperts), eprefix, dst_slots, refs, error, begin,
                tile * kNumTokensPerTile, math::min(uint32_t(kNumTokensPerTile), length - tile * kNumTokensPerTile));
            asc_sync_notify(PIPE_V, PIPE_S, EVENT_ID0);
            asc_sync_wait(PIPE_V, PIPE_S, EVENT_ID0);
        }
        local_join();
        if (AscendC::ReadGmByPassDCache(error) != OK) {
            break;
        }
        // S2.3 [REUSE+AFD] Histogram/prefix logic, now bounded tile columns rather than collective counts.
        // Independent prefix columns need no extra workspace. Only the final
        // expert-major exclusive prefix is ordered after all column totals exist.
        for (int column = vec_core_idx; column < kNumRanks + kNumExperts; column += kNumVecCores) {
            uint32_t total = 0;
            for (uint32_t tile = 0; tile < tiles; ++tile) {
                AscendC::WriteGmByPassDCache(psum + tile * (kNumRanks + kNumExperts) + column, total);
                total += AscendC::ReadGmByPassDCache(counts + tile * (kNumRanks + kNumExperts) + column);
            }
            if (column < kNumRanks) {
                AscendC::WriteGmByPassDCache(rtotals + column, total);
            } else {
                AscendC::WriteGmByPassDCache(ecounts + column - kNumRanks, total);
            }
        }
        local_join();
        if (vec_core_idx == 0) {
            uint32_t expert_base = 0;
            for (int expert = 0; expert < kNumExperts; ++expert) {
                AscendC::WriteGmByPassDCache(eprefix + expert, expert_base);
                expert_base += AscendC::ReadGmByPassDCache(ecounts + expert);
            }
        }
        local_join();
        // S2.4 [REUSE+AFD] Second route pass and metadata/payload production per tile.
        for (uint32_t tile = vec_core_idx; tile < tiles; tile += kNumVecCores) {
            const uint32_t size = math::min(uint32_t(kNumTokensPerTile), length - tile * kNumTokensPerTile);
            AscendC::Simt::VF_CALL<
                route_tile<kNumExperts, kNumRanks, kNumTopk, kNumTokensPerTile, kNumMetadataBytes, kNumVecCores, true>>(
                AscendC::Simt::Dim3(512, 1, 1), ub, topk_idx, token_mask, counts + tile * (kNumRanks + kNumExperts),
                psum + tile * (kNumRanks + kNumExperts), eprefix, dst_slots, refs, error, begin,
                tile * kNumTokensPerTile, size);
            asc_sync_notify(PIPE_V, PIPE_S, EVENT_ID0);
            asc_sync_wait(PIPE_V, PIPE_S, EVENT_ID0);
            // Native preload_metadata / batch_idx / stage_idx progression, restricted
            // to this fixed routing tile. Metadata remains in existing GM scratch
            // until all WRITEs drain; no hidden mirror or additional workspace.
            constexpr int kNumTokensPerMetadataMTE = 4;
            constexpr int kNumMetadataMTEStages = 2;
            const int num_metadata_batches = (size + kNumTokensPerMetadataMTE - 1) / kNumTokensPerMetadataMTE;
            const int num_active_stages = math::min(num_metadata_batches, kNumMetadataMTEStages);
            for (int stage_idx = 0; stage_idx < num_active_stages; ++stage_idx) {
                const auto ub_metadata = ub->metadata[stage_idx];
                for (int b = 0; b < kNumTokensPerMetadataMTE * kNumMetadataBytes; ++b) {
                    ub_metadata[b] = 0;
                }
                const auto event = static_cast<event_t>(stage_idx + 2);
                asc_sync_notify(PIPE_S, PIPE_MTE2, event);
                asc_sync_wait(PIPE_S, PIPE_MTE2, event);
                asc_sync_notify(PIPE_MTE3, PIPE_MTE2, event);
            }
            auto preload_metadata = [&](const int token_idx, const int stage_idx) __aicore__ {
                const auto ub_metadata = ub->metadata[stage_idx];
                const auto event = static_cast<event_t>(stage_idx + 2);
                const int num_tokens_in_stage = math::min(kNumTokensPerMetadataMTE, int(size) - token_idx);
                const uint64_t global = uint64_t(begin) + tile * kNumTokensPerTile + token_idx;
                asc_sync_wait(PIPE_MTE3, PIPE_MTE2, event);
                if constexpr (kNumSFPacks > 0) {
                    const auto gm_sf = sf + global * sf_token_stride;
                    if (sf_hidden_stride == 1) {
                        asc_copy_gm2ub_align(reinterpret_cast<__ubuf__ sf_pack_t *>(ub_metadata), gm_sf,
                                             static_cast<uint16_t>(num_tokens_in_stage),
                                             kNumSFPacks * sizeof(sf_pack_t), 0, 0, false,
                                             static_cast<uint8_t>(LD_L2CacheType::L2_CACHE_HINT_NORMAL_FV),
                                             uint64_t(sf_token_stride) * sizeof(sf_pack_t), kNumMetadataBytes);
                    } else {
                        const nddma_desc sf_desc(nddma_desc::loop_desc(num_tokens_in_stage,
                                                                       kNumMetadataBytes / sizeof(sf_pack_t),
                                                                       uint32_t(sf_token_stride)),
                                                 nddma_desc::loop_desc(kNumSFPacks, 1, uint32_t(sf_hidden_stride)));
                        nddma_out_to_ub(reinterpret_cast<__ubuf__ sf_pack_t *>(ub_metadata), gm_sf, 0, sf_desc, 0,
                                        CONSTANT_PADDING,
                                        static_cast<uint8_t>(LD_L2CacheType::L2_CACHE_HINT_NORMAL_FV));
                    }
                }
                asc_copy_gm2ub_align(ub_metadata + token_layout.topk_idx_offset() - kNumHiddenBytes,
                                     reinterpret_cast<__gm__ uint8_t *>(topk_idx + global * kNumTopk),
                                     static_cast<uint16_t>(num_tokens_in_stage), kNumTopk * 8, 0, 0, false,
                                     static_cast<uint8_t>(LD_L2CacheType::L2_CACHE_HINT_NORMAL_FV),
                                     uint64_t(kNumTopk * 8), kNumMetadataBytes);
                asc_copy_gm2ub_align(ub_metadata + token_layout.topk_weights_offset() - kNumHiddenBytes,
                                     reinterpret_cast<__gm__ uint8_t *>(topk_weights + global * kNumTopk),
                                     static_cast<uint16_t>(num_tokens_in_stage), kNumTopk * 4, 0, 0, false,
                                     static_cast<uint8_t>(LD_L2CacheType::L2_CACHE_HINT_NORMAL_FV),
                                     uint64_t(kNumTopk * 4), kNumMetadataBytes);
                asc_sync_notify(PIPE_MTE2, PIPE_S, event);
            };
            for (int stage_idx = 0; stage_idx < num_active_stages; ++stage_idx) {
                preload_metadata(stage_idx * kNumTokensPerMetadataMTE, stage_idx);
            }
            for (int batch_idx = 0; batch_idx < num_metadata_batches; ++batch_idx) {
                const int stage_idx = batch_idx % kNumMetadataMTEStages;
                const int first_metadata_idx = batch_idx * kNumTokensPerMetadataMTE;
                const int num_tokens_in_stage = math::min(kNumTokensPerMetadataMTE, int(size) - first_metadata_idx);
                const auto event = static_cast<event_t>(stage_idx + 2);
                const auto ub_metadata = ub->metadata[stage_idx];
                asc_sync_wait(PIPE_MTE2, PIPE_S, event);
                for (int i = 0; i < num_tokens_in_stage; ++i) {
                    const auto meta = ub_metadata + i * kNumMetadataBytes;
                    *reinterpret_cast<__ubuf__ uint32_t *>(meta + token_layout.src_token_idx_offset() -
                                                           kNumHiddenBytes) =
                        tile * kNumTokensPerTile + first_metadata_idx + i;
                    *reinterpret_cast<__ubuf__ uint32_t *>(meta + token_layout.valid_topk_mask_offset() -
                                                           kNumHiddenBytes) =
                        kNumTopk == 32 ? UINT32_MAX : (uint32_t(1) << kNumTopk) - 1;
                }
                asc_sync_notify(PIPE_S, PIPE_MTE3, event);
                asc_sync_wait(PIPE_S, PIPE_MTE3, event);
                // Unlike gathered fields, completed metadata records are contiguous
                // in both UB and GM; one burst avoids any inter-burst stride/gap.
                const uint32_t num_metadata_bytes = num_tokens_in_stage * kNumMetadataBytes;
                asc_copy_ub2gm_align(ws + w.metadata_send_buffer +
                                         uint64_t(tile * kNumTokensPerTile + first_metadata_idx) * kNumMetadataBytes,
                                     ub_metadata, 1, num_metadata_bytes, asc_store_l2_cache_mode::NOTALLOC_CLEAN,
                                     uint64_t(num_metadata_bytes), num_metadata_bytes);
                asc_sync_notify(PIPE_MTE3, PIPE_MTE2, event);
                const int next_batch_idx = batch_idx + kNumMetadataMTEStages;
                if (next_batch_idx < num_metadata_batches) {
                    preload_metadata(next_batch_idx * kNumTokensPerMetadataMTE, stage_idx);
                }
            }
            // Last release for each stage is consumed exactly once, including tails.
            for (int stage_idx = 0; stage_idx < num_active_stages; ++stage_idx) {
                asc_sync_wait(PIPE_MTE3, PIPE_MTE2, static_cast<event_t>(stage_idx + 2));
            }
            asc_sync_notify(PIPE_MTE2, PIPE_S, EVENT_ID0);
            asc_sync_wait(PIPE_MTE2, PIPE_S, EVENT_ID0);
            // S2.4b [REUSE+AFD] Native combine warp-per-WQE encoding, AFD record SGEs.
            // All metadata MTE3 reads/writes above must finish before SQ publication.
            // One local queue per (AIV, peer): write per peer and drain that queue
            // before switching to the next peer, so no two queues share staging.
            for (int f = 0; f < kNumRanks; ++f) {
                handle::HcommJetty jetty_f(
                    reinterpret_cast<__ubuf__ handle::HcommJettyInfo *>(ub->jetty_info[vec_core_idx][f]), ub->ub_sqe,
                    jetty_ptrs, channel_grouped ? int(peers[f].peer_idx) + vec_core_idx : vec_core_idx);
                EP_DEVICE_ASSERT(jetty_f.jetty_info->cq_depth > kNumMaxPendingWrites + kNumPollCQThreshold &&
                                 (jetty_f.jetty_info->cq_depth & (jetty_f.jetty_info->cq_depth - 1)) == 0 &&
                                 jetty_f.jetty_info->num_wqebb_bytes == handle::kNumWQEBBBytes);
                uint32_t inflight = 0, num_task_tokens = 0;
                for (uint32_t i = 0; i < size; ++i) {
                    const uint32_t row = tile * kNumTokensPerTile + i, global = begin + row;
                    const auto gm_meta = ws + w.metadata_send_buffer + uint64_t(row) * kNumMetadataBytes;
                    for (int k = 0; k < kNumTopk; ++k) {
                        if (ub->dst_rank_idx[i * kNumTopk + k] != f) {
                            continue;
                        }
                        peer.peer_info = ub->peer_info + f;
                        const uint64_t off =
                            addresses[lane_idx * kNumRanks + f].records_offset +
                            uint64_t(ub->dst_slot_idx[i * kNumTopk + k]) * token_layout.record_stride();
                        append_write_task<2, kNumTimeoutCycles>(
                            jetty_f, peer, off, static_cast<__gm__ uint8_t *>(x) + uint64_t(global) * kNumHiddenBytes,
                            gm_meta, kNumHiddenBytes, kNumMetadataBytes, num_task_tokens, inflight);
                    }
                }
                issue_write_task<2, kNumTimeoutCycles>(jetty_f, num_task_tokens, inflight);
                flush_writes<kNumTimeoutCycles>(jetty_f, inflight);
            }
        }
        local_join();
        if (AscendC::ReadGmByPassDCache(error) != OK) {
            break;
        }
        if (vec_core_idx == 0) {
            // S2.5 [AFD] After all AIV payload drains: route tables -> Inbox ->
            // Ledger -> InputReady -> next bits. No early InputReady/slot release.
            // [group B] Route tables also use per-(AIV, peer) queues; drain each before publish.
            uint64_t route_base = 0;
            for (int f = 0; f < kNumRanks; ++f) {
                uint32_t routes = 0;
                for (int e = 0; e < kNumExperts / kNumRanks; ++e) {
                    routes += AscendC::ReadGmByPassDCache(ecounts + f * (kNumExperts / kNumRanks) + e);
                    AscendC::WriteGmByPassDCache(eprefix + f * (kNumExperts / kNumRanks) + e, routes);
                }
                AscendC::DataSyncBarrier<AscendC::MemDsbT::DDR>();
                peer.peer_info = ub->peer_info + f;
                handle::HcommJetty jetty_f(
                    reinterpret_cast<__ubuf__ handle::HcommJettyInfo *>(ub->jetty_info[vec_core_idx][f]), ub->ub_sqe,
                    jetty_ptrs, channel_grouped ? int(peers[f].peer_idx) + vec_core_idx : vec_core_idx);
                EP_DEVICE_ASSERT(jetty_f.jetty_info->cq_depth > kNumMaxPendingWrites + kNumPollCQThreshold &&
                                 (jetty_f.jetty_info->cq_depth & (jetty_f.jetty_info->cq_depth - 1)) == 0 &&
                                 jetty_f.jetty_info->num_wqebb_bytes == handle::kNumWQEBBBytes);
                uint32_t inflight = 0;
                const auto address = recv_read(addresses + lane_idx * kNumRanks + f);
                if (routes) {
                    put_at_offset<kNumTimeoutCycles>(jetty_f, peer, address.route_reference_offset, refs + route_base,
                                                     uint64_t(routes) * 4, inflight);
                }
                put_at_offset<kNumTimeoutCycles>(jetty_f, peer, address.count_offset,
                                                 ecounts + f * (kNumExperts / kNumRanks), (kNumExperts / kNumRanks) * 4,
                                                 inflight);
                put_at_offset<kNumTimeoutCycles>(jetty_f, peer, address.prefix_offset,
                                                 eprefix + f * (kNumExperts / kNumRanks), (kNumExperts / kNumRanks) * 4,
                                                 inflight);
                flush_writes<kNumTimeoutCycles>(jetty_f, inflight);
                route_base += routes;
            }
            load_control(stage, state);
            const AFDSendState saved = recv_read_send_state_ubuf(stage);
            for (int f = 0; f < kNumRanks; ++f) {
                for (int i = 0; i < 16; ++i) {
                    words[i] = 0;
                }
                auto inbox = reinterpret_cast<__ubuf__ AFDInbox *>(stage);
                inbox->microbatch_idx = task_info->microbatch_idx;
                inbox->layer_idx = task_info->layer_idx;
                inbox->round_idx = round;
                inbox->num_comm_rounds = task_info->num_comm_rounds;
                inbox->num_round_tokens = length;
                inbox->return_bit = saved.next_return_bit;
                inbox->num_recv_records = AscendC::ReadGmByPassDCache(rtotals + f);
                store_control(reinterpret_cast<__gm__ void *>(peers[f].control_base +
                                                              addresses[lane_idx * kNumRanks + f].inbox_offset),
                              stage, 64);
            }
            for (int i = 0; i < 16; ++i) {
                words[i] = 0;
            }
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
            for (int f = 0; f < kNumRanks; ++f) {
                for (int i = 0; i < 8; ++i) {
                    words[i] = 0;
                }
                words[0] = saved.next_input_bit;
                store_control(reinterpret_cast<__gm__ void *>(peers[f].control_base +
                                                              addresses[lane_idx * kNumRanks + f].input_ready_offset),
                              stage);
            }
            for (int i = 0; i < 8; ++i) {
                words[i] = 0;
            }
            auto next = reinterpret_cast<__ubuf__ AFDSendState *>(stage);
            next->next_input_bit = saved.next_input_bit ^ 1;
            next->next_return_bit = saved.next_return_bit ^ 1;
            next->has_published = 1;
            next->last_input_bit = saved.next_input_bit;
            store_control(state, stage);
        }
        local_join();
    }
    if (vec_core_idx == 0) {
        // S3 [AFD] Publication status only, not permission to reuse the input slot.
        const uint32_t code = AscendC::ReadGmByPassDCache(error);
        for (int i = 0; i < 8; ++i) {
            words[i] = 0;
        }
        words[0] = code == OK ? 2 : 3;
        words[1] = code;
        words[2] = current_round;
        store_control(send_status, stage);
    }
}
} // namespace deep_ep::afd
// ### PATCH END: bounded AFD sender
