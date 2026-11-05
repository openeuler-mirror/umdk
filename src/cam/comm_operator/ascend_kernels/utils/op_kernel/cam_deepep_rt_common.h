/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2026-2026. All rights reserved.
 * Description: shared runtime-parameterized AFD transport helpers for CAM
 * Create: 2026-11-03
 * Note: model-dependent sizes are runtime arguments; only the timeout template of
 *       HcommJetty::drain/put stays compile-time and is fixed to one default.
 * History: 2026-11-03 extract from cam_deepep_dispatch_send_rt.h
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

// Helpers shared by all cam_deepep_* runtime bodies.
// Derived from deep_ep/impls/afd/dispatch_send.h. The production helpers take
// the timeout as a template argument; the CAM ports take it at runtime, so the
// transport-level drain/put calls keep one fixed compile-time timeout.
namespace deep_ep::afd::rt {
constexpr uint32_t kNumMaxPendingWrites = 32;
constexpr int64_t kDefaultTimeoutCycles = 1000000000;
// Correct physical UB on 950/3510. 192 KiB is the A2/2201 value and must not be
// used as the budget; the host still validates against GetCoreMemSize(UB).
constexpr uint32_t kMaxPhysicalUbBytes = 253952;

__aicore__ inline void local_join()
{
    asc_sync_notify(PIPE_MTE3, PIPE_V, EVENT_ID0);
    asc_sync_wait(PIPE_MTE3, PIPE_V, EVENT_ID0);
    AscendC::DataSyncBarrier<AscendC::MemDsbT::DDR>();
    AscendC::SyncAll<true>();
}
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
__aicore__ inline bool wait_control(__ubuf__ uint8_t *ub, __gm__ void *src, uint32_t wanted, uint64_t timeout_cycles)
{
    const uint64_t start = asc_get_system_cycle();
    do {
        load_control(ub, src);
        if (*reinterpret_cast<__ubuf__ uint32_t *>(ub) == wanted) {
            return true;
        }
    } while (uint64_t(asc_get_system_cycle()) - start < timeout_cycles);
    return false;
}
__aicore__ inline void flush_writes(handle::HcommJetty &jetty, uint32_t &inflight)
{
    if (inflight == 0) {
        return;
    }
    jetty.ring_doorbell();
    jetty.template drain<kDefaultTimeoutCycles>();
    inflight = 0;
}
__aicore__ inline void put_at_offset(handle::HcommJetty &jetty, const handle::HcommPeer &peer, uint64_t offset,
                                     __gm__ void *src, uint64_t bytes, uint32_t &inflight)
{
    EP_DEVICE_ASSERT(bytes > 0);
    EP_DEVICE_ASSERT(bytes <= UINT32_MAX);
    EP_DEVICE_ASSERT(offset <= peer.peer_info->rmt_buffer_size);
    // Bind the bound to a local so the assert below checks exactly one condition.
    const uint64_t remaining = peer.peer_info->rmt_buffer_size - offset;
    EP_DEVICE_ASSERT(bytes <= remaining);
    jetty.template put<kDefaultTimeoutCycles, false>(peer, nullptr, reinterpret_cast<__gm__ void *>(offset), src,
                                                     bytes);
    if (++inflight == kNumMaxPendingWrites) {
        flush_writes(jetty, inflight);
    }
}

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

template <int kNumSGEs>
__aicore__ inline void issue_write_task(handle::HcommJetty &jetty, uint32_t &num_tokens, uint32_t &inflight)
{
    if (num_tokens == 0) {
        return;
    }
    constexpr uint32_t kNumWQEBBsPerToken = (48 + 16 * kNumSGEs + 63) / 64;
    static_assert(kNumMaxPendingWrites * kNumWQEBBsPerToken < handle::kSQDepth);
    if (inflight + num_tokens > kNumMaxPendingWrites) {
        flush_writes(jetty, inflight);
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
        flush_writes(jetty, inflight);
    }
}

template <int kNumSGEs>
__aicore__ inline void append_write_task(handle::HcommJetty &jetty, const handle::HcommPeer &peer, uint64_t offset,
                                         __gm__ void *x, __gm__ void *metadata_send_buffer, uint32_t num_hidden_bytes,
                                         uint32_t num_metadata_bytes, uint32_t &num_tokens, uint32_t &inflight)
{
    const uint64_t bytes = uint64_t(num_hidden_bytes) + num_metadata_bytes;
    EP_DEVICE_ASSERT(num_hidden_bytes > 0);
    EP_DEVICE_ASSERT(bytes <= UINT32_MAX);
    EP_DEVICE_ASSERT(offset <= peer.peer_info->rmt_buffer_size);
    // Bind the bound to a local so the assert below checks exactly one condition.
    const uint64_t remaining = peer.peer_info->rmt_buffer_size - offset;
    EP_DEVICE_ASSERT(bytes <= remaining);
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
        issue_write_task<kNumSGEs>(jetty, num_tokens, inflight);
    }
}
} // namespace deep_ep::afd::rt
