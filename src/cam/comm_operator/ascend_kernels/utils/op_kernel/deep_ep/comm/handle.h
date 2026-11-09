/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2026-2026. All rights reserved.
 * Description: UB JFS/JFC queue and remote-memory handle helpers.
 * Create: 2026-11-03
 * Note: Device header for the CAM DeepEP-compatible operators.
 * History: 2026-11-03 create for the cam_deepep operators
 */
#pragma once

#include <cstddef>

#include <hcomm/hcomm.h>
#include <kernel_operator.h>
#include <simt_api/device_functions.h>
#include <c_api/asc_simd.h>
#include <c_api/sync/sync.h>
#include <c_api/vector_datamove/vector_datamove.h>

#include <deep_ep/common/compiled.h>
#include <deep_ep/common/exception.h>
#include <deep_ep/common/math.h>

namespace deep_ep::handle {

static constexpr int kNumMaxSGEPairsPerSQE = 6;
static constexpr int kNumWQEBBBytes = 64;
static constexpr uint32_t kSQDepth = 32768;

// sqe_bb_idx[15:0] = 0, odr[18:16] = 0, cqe[21] = 0,
// owner[31] = 0 (filled per WQEBB), opcode[47:40] = 0x11.
static constexpr uint64_t kNopSQEHeaderTemplate = 0x0000110000000000ULL;

// sqe_bb_idx[15:0] = 0, odr[18:16] = 1, fence[19] = 0, se[20] = 0,
// cqe[21] = 0, inline_en[22] = 0, udf_flag[23] = 0, nf[27] = 0,
// token_en[28] = 1, rmt_jetty_type[30:29] = 1, owner[31] = 0 (filled per WQEBB),
// target_hint[39:32] = 0, opcode[47:40] = 0x3, inline_msg_len[63:54] = 0.
static constexpr uint64_t kWriteSQEHeaderTemplate = 0x0000030030010000ULL;
// The final payload WRITE uses odr=5, fence=1 and cqe=1 to cover prior SQEs.
static constexpr uint64_t kWriteSQEFinalFlags = (1ULL << 18) | (1ULL << 19) | (1ULL << 21);

struct alignas(kNumUint64AlignmentBytes) HcommPeerInfo {
    // SQE bytes 8-15
    // [23:0] tp_id, [31:24] num_sges, [51:32] rmt_token_id
    uint64_t tp_id_num_sges_rmt_token_id;

    // SQE bytes 16-31
    uint64_t rmt_eid[2];

    // SQE bytes 32-47
    // [31:0] rmt_token_value, [63:32] UDF fields
    uint64_t rmt_token_value_udf;
    uint64_t rmt_base_addr;
    uint64_t rmt_buffer_size;

    // One SIMT thread loads one peer; callers choose the peer-to-thread mapping.
    static __simt_callee__ __forceinline__ void load_peer_info(__ubuf__ HcommPeerInfo *peer_info,
                                                               __gm__ const uint64_t *jetty_ptrs, const int jetty_idx)
    {
        const auto jetty_value = jetty_ptrs[jetty_idx];
        if (jetty_value == 0) {
            __asc_simt_vf::__trap();
        }
        const auto channel = reinterpret_cast<__gm__ const AscendC::ChannelEntity *>(jetty_value);
        if (channel->remoteBufferNum != 1) {
            __asc_simt_vf::__trap();
        }
        // HCOMM's generic pointers must be loaded as GM addresses in SIMT code.
        const auto channel_words = reinterpret_cast<__gm__ const uint64_t *>(channel);
        const auto remote_buffer = reinterpret_cast<__gm__ const AscendC::RegedBufferEntity *>(
            channel_words[offsetof(AscendC::ChannelEntity, remoteBufferAddr) / sizeof(uint64_t)]);
        const auto sq_context = reinterpret_cast<__gm__ const AscendC::SqContext *>(
                                    channel_words[offsetof(AscendC::ChannelEntity, sqContextAddr) / sizeof(uint64_t)]) +
                                AscendC::HCOMM_URMA_DEFAULT_QP_IDX;
        peer_info->rmt_token_value_udf = remote_buffer->bufferInfo.rma.protectionInfo.memInfo.ub.tokenValue;
        peer_info->rmt_base_addr = remote_buffer->bufferInfo.rma.addr;
        peer_info->rmt_buffer_size = remote_buffer->bufferInfo.rma.size;
        peer_info->tp_id_num_sges_rmt_token_id =
            static_cast<uint64_t>(sq_context->contextInfo.ubJfs.tpID) |
            (static_cast<uint64_t>(remote_buffer->bufferInfo.rma.protectionInfo.memInfo.ub.tokenId)
             << kNumHighHalfShiftBits);
        const auto eid = reinterpret_cast<__gm__ const uint64_t *>(sq_context->contextInfo.ubJfs.remoteEID);
        peer_info->rmt_eid[0] = eid[0];
        peer_info->rmt_eid[1] = eid[1];
    }
};
EP_STATIC_ASSERT(sizeof(HcommPeerInfo) == 48);
EP_STATIC_ASSERT(alignof(HcommPeerInfo) == kNumUint64AlignmentBytes);

struct alignas(kNumUint64AlignmentBytes) HcommJettyInfo {
    uint64_t sq_base_addr;
    uint64_t sq_head_addr;
    uint64_t completion_tail_addr;
    uint64_t sq_doorbell_addr;
    uint64_t cq_base_addr;
    uint64_t cq_tail_addr;
    uint64_t cq_doorbell_addr;
    // packed_head[31:0] = current SQ WQEBB head, [63:32] = expected completion count.
    uint64_t packed_head;
    // Match the SQ/CQ context words so each SIMT lane can copy one aligned u64.
    uint32_t reserved_jfs_id;
    uint32_t num_wqebb_bytes;
    uint32_t reserved_jfc_id;
    uint32_t num_cqe_bytes;
    uint32_t cq_depth;
    uint32_t reserved;

    // One warp loads one Jetty; lanes [0, 11) each copy one u64, including the live SQ head.
    static __simt_callee__ __forceinline__ void load_jetty_info(__ubuf__ HcommJettyInfo *jetty_info,
                                                                __gm__ const uint64_t *jetty_ptrs, const int jetty_idx,
                                                                const int lane_idx)
    {
        if (lane_idx >= sizeof(HcommJettyInfo) / sizeof(uint64_t)) {
            return;
        }
        const auto jetty_value = jetty_ptrs[jetty_idx];
        if (jetty_value == 0) {
            __asc_simt_vf::__trap();
        }
        const auto channel = reinterpret_cast<__gm__ const AscendC::ChannelEntity *>(jetty_value);
        if (channel->sqNum == 0 or channel->cqNum == 0) {
            __asc_simt_vf::__trap();
        }
        const auto channel_words = reinterpret_cast<__gm__ const uint64_t *>(channel);
        const auto sq_context = reinterpret_cast<__gm__ AscendC::SqContext *>(
                                    channel_words[offsetof(AscendC::ChannelEntity, sqContextAddr) / sizeof(uint64_t)]) +
                                AscendC::HCOMM_URMA_DEFAULT_QP_IDX;
        const auto cq_context = reinterpret_cast<__gm__ AscendC::CqContext *>(
                                    channel_words[offsetof(AscendC::ChannelEntity, cqContextAddr) / sizeof(uint64_t)]) +
                                AscendC::HCOMM_URMA_DEFAULT_QP_IDX;
        const auto sq_words = reinterpret_cast<__gm__ uint64_t *>(&sq_context->contextInfo.ubJfs);
        const auto cq_words = reinterpret_cast<__gm__ uint64_t *>(&cq_context->contextInfo.ubJfc);
        __gm__ uint64_t *src;
        if (lane_idx < 4) {
            src = sq_words + lane_idx;
        } else if (lane_idx < 7) {
            src = cq_words + (lane_idx == 4 ? 0 : lane_idx - 3);
        } else if (lane_idx == 7) {
            src = reinterpret_cast<__gm__ uint64_t *>(sq_words[1]);
        } else {
            src = lane_idx < 9 ? sq_words + lane_idx - 4 : cq_words + lane_idx - 5;
        }
        // Use one common load instruction, with a field-specific address in each lane.
        reinterpret_cast<__ubuf__ uint64_t *>(jetty_info)[lane_idx] = asc_ldcg(src);
    }
};
static_assert(sizeof(HcommJettyInfo) == 88);
static_assert(alignof(HcommJettyInfo) == kNumUint64AlignmentBytes);

struct HcommPeer {
    __ubuf__ HcommPeerInfo *peer_info = nullptr;

    __aicore__ __forceinline__ HcommPeer(__ubuf__ HcommPeerInfo *peer_info, __gm__ void *jetty_ptrs,
                                         const int jetty_idx)
        : peer_info(peer_info)
    {
        // Load the remote registered buffer
        const auto jetty_table = static_cast<__gm__ uint64_t *>(jetty_ptrs);
        const auto jetty_value = AscendC::ReadGmByPassDCache(jetty_table + jetty_idx);
        EP_DEVICE_ASSERT(jetty_value != 0);
        const auto jetty = reinterpret_cast<__gm__ AscendC::ChannelEntity *>(jetty_value);
        EP_DEVICE_ASSERT(jetty->remoteBufferNum == 1);
        const auto remote_buffer = jetty->remoteBufferAddr[0];
        peer_info->rmt_token_value_udf = remote_buffer.bufferInfo.rma.protectionInfo.memInfo.ub.tokenValue;
        peer_info->rmt_base_addr = remote_buffer.bufferInfo.rma.addr;
        peer_info->rmt_buffer_size = remote_buffer.bufferInfo.rma.size;

        // Load the remote Jetty transport metadata
        const auto sq_context = jetty->sqContextAddr[AscendC::HCOMM_URMA_DEFAULT_QP_IDX];
        peer_info->tp_id_num_sges_rmt_token_id =
            static_cast<uint64_t>(sq_context.contextInfo.ubJfs.tpID) |
            (static_cast<uint64_t>(remote_buffer.bufferInfo.rma.protectionInfo.memInfo.ub.tokenId)
             << kNumHighHalfShiftBits);
        peer_info->rmt_eid[0] = 0;
        peer_info->rmt_eid[1] = 0;
        for (int byte_idx = 0; byte_idx < 8; ++byte_idx) {
            peer_info->rmt_eid[0] |= static_cast<uint64_t>(sq_context.contextInfo.ubJfs.remoteEID[byte_idx])
                                     << (byte_idx * 8);
            peer_info->rmt_eid[1] |= static_cast<uint64_t>(sq_context.contextInfo.ubJfs.remoteEID[byte_idx + 8])
                                     << (byte_idx * 8);
        }
    }
};

struct HcommJetty {
    static constexpr uint32_t kNumWriteWQEBBs =
        (sizeof(AscendC::HcommUrmaSqeCtx) + sizeof(AscendC::HcommUrmaSgeCtx) + kNumWQEBBBytes - 1) / kNumWQEBBBytes;
    static constexpr uint32_t kNumWriteWithNotifyWQEBBs =
        (sizeof(AscendC::HcommUrmaSqeCtx) + sizeof(AscendC::HcommUrmaNotifyCtx) + sizeof(AscendC::HcommUrmaSgeCtx) +
         kNumWQEBBBytes - 1) /
        kNumWQEBBBytes;
    static constexpr uint32_t kNumMaxSQEBytes = kNumWriteWithNotifyWQEBBs * kNumWQEBBBytes;

    __ubuf__ HcommJettyInfo *jetty_info = nullptr;
    __ubuf__ uint8_t *ub_sqe = nullptr;

    __aicore__ __forceinline__ HcommJetty(__ubuf__ HcommJettyInfo *jetty_info, __ubuf__ uint8_t *ub_sqe,
                                          __gm__ void *jetty_ptrs, const int jetty_idx)
        : jetty_info(jetty_info), ub_sqe(ub_sqe)
    {
        // TODO(HUAWEI): enable loopback Jetty
        if (jetty_ptrs == nullptr) {
            return;
        }

        // Load shared Jetty info
        const auto jetty_table = static_cast<__gm__ uint64_t *>(jetty_ptrs);
        const auto jetty_value = AscendC::ReadGmByPassDCache(jetty_table + jetty_idx);
        EP_DEVICE_ASSERT(jetty_value != 0);
        const auto jetty = reinterpret_cast<__gm__ AscendC::ChannelEntity *>(jetty_value);
        EP_DEVICE_ASSERT(jetty->sqNum > 0 and jetty->cqNum > 0);

        // Load queue resources
        const auto sq_context = jetty->sqContextAddr[AscendC::HCOMM_URMA_DEFAULT_QP_IDX];
        const auto cq_context = jetty->cqContextAddr[AscendC::HCOMM_URMA_DEFAULT_QP_IDX];
        jetty_info->sq_base_addr = sq_context.contextInfo.ubJfs.sqVa;
        jetty_info->sq_head_addr = sq_context.contextInfo.ubJfs.headAddr;
        jetty_info->completion_tail_addr = sq_context.contextInfo.ubJfs.tailAddr;
        jetty_info->sq_doorbell_addr = sq_context.contextInfo.ubJfs.dbVa;
        jetty_info->cq_base_addr = cq_context.contextInfo.ubJfc.scqVa;
        jetty_info->cq_tail_addr = cq_context.contextInfo.ubJfc.tailAddr;
        jetty_info->cq_doorbell_addr = cq_context.contextInfo.ubJfc.dbVa;
        jetty_info->packed_head =
            AscendC::ReadGmByPassDCache(reinterpret_cast<__gm__ uint64_t *>(jetty_info->sq_head_addr));
        jetty_info->num_wqebb_bytes = sq_context.contextInfo.ubJfs.wqeSize;
        jetty_info->num_cqe_bytes = cq_context.contextInfo.ubJfc.cqeSize;
        jetty_info->cq_depth = cq_context.contextInfo.ubJfc.cqDepth;
    }

    template <int64_t kNumTimeoutCycles> __aicore__ __forceinline__ void poll_cq_when_sq_overflow()
    {
        // Trigger CQ polling before the completion ring reaches its wraparound threshold.
        static constexpr uint32_t kNumPollCQThreshold = 10;
        // Reclaim a bounded batch to free CQ slots without draining all in-flight writes.
        static constexpr uint32_t kNumCQEsPerPoll = 100;
        const auto num_completions = static_cast<uint32_t>(jetty_info->packed_head >> kNumHighHalfShiftBits);
        const auto completion_tail =
            AscendC::ReadGmByPassDCache(reinterpret_cast<__gm__ uint32_t *>(jetty_info->completion_tail_addr));

        if ((num_completions + kNumPollCQThreshold) % jetty_info->cq_depth == completion_tail % jetty_info->cq_depth) {
            poll_cq<kNumTimeoutCycles>(math::min(completion_tail + kNumCQEsPerPoll, num_completions));
        }
    }

    template <bool kWithNotify>
    __aicore__ __forceinline__ void
    build_write_sqe(const HcommPeer &peer, __gm__ void *local_base, __gm__ void *dst_sym_ptr, __gm__ void *src_ptr,
                    const uint64_t num_bytes, const uint32_t current_head, __gm__ void *notify_sym_ptr = nullptr,
                    const uint64_t notify_value = 0)
    {
        static constexpr uint32_t kStrongOrdering = 5;
        static constexpr uint32_t kFence = 1U << 3;
        static constexpr uint32_t kRequestCQE = 1U << 5;

        const auto peer_info = peer.peer_info;
        const auto dst_offset = reinterpret_cast<uint64_t>(dst_sym_ptr) - reinterpret_cast<uint64_t>(local_base);
        EP_DEVICE_ASSERT(dst_offset <= peer_info->rmt_buffer_size and
                         num_bytes <= peer_info->rmt_buffer_size - dst_offset);
        const auto remote_addr = peer_info->rmt_base_addr + dst_offset;

        // Fill the SQE header
        const auto sqe = reinterpret_cast<__ubuf__ AscendC::HcommUrmaSqeCtx *>(ub_sqe);
        sqe->sqeBbIdx = 0;
        sqe->flag = kStrongOrdering | kFence | kRequestCQE;
        sqe->rsv0 = 0;
        sqe->nf = 0;
        sqe->tokenEn = 1;
        sqe->rmtJettyType = 1;
        sqe->owner = (current_head & kSQDepth) == 0 ? 1 : 0;
        sqe->targetHint = 0;
        sqe->opcode = static_cast<uint32_t>(kWithNotify ? AscendC::HcommUrmaOpCode::WRITE_WITH_NOTIFY
                                                        : AscendC::HcommUrmaOpCode::WRITE);
        sqe->rsv1 = 0;
        sqe->inlineMsgLen = 0;
        sqe->tpId = static_cast<uint32_t>(peer_info->tp_id_num_sges_rmt_token_id);
        sqe->sgeNum = 1;
        sqe->rmtJettyOrSegId = static_cast<uint32_t>(peer_info->tp_id_num_sges_rmt_token_id >> kNumHighHalfShiftBits);
        sqe->rsv2 = 0;
        sqe->rmtEidL = peer_info->rmt_eid[0];
        sqe->rmtEidH = peer_info->rmt_eid[1];
        sqe->rmtTokenValue = static_cast<uint32_t>(peer_info->rmt_token_value_udf);
        sqe->udfType = 0;
        sqe->reduceDataType = 0;
        sqe->reduceOpcode = 0;
        sqe->rsv3 = 0;
        sqe->rmtAddrLOrTokenId = static_cast<uint32_t>(remote_addr);
        sqe->rmtAddrHOrTokenValue = static_cast<uint32_t>(remote_addr >> kNumHighHalfShiftBits);

        // Fill optional notify metadata
        __ubuf__ uint8_t *ub_sge = ub_sqe + sizeof(AscendC::HcommUrmaSqeCtx);
        if constexpr (kWithNotify) {
            EP_DEVICE_ASSERT(notify_sym_ptr != nullptr);
            const auto notify_offset =
                reinterpret_cast<uint64_t>(notify_sym_ptr) - reinterpret_cast<uint64_t>(local_base);
            EP_DEVICE_ASSERT(notify_offset <= peer_info->rmt_buffer_size and
                             sizeof(uint64_t) <= peer_info->rmt_buffer_size - notify_offset);
            const auto remote_notify_addr = peer_info->rmt_base_addr + notify_offset;
            const auto notify = reinterpret_cast<__ubuf__ AscendC::HcommUrmaNotifyCtx *>(ub_sge);
            notify->notifyTokenId =
                static_cast<uint32_t>(peer_info->tp_id_num_sges_rmt_token_id >> kNumHighHalfShiftBits);
            notify->rsv = 0;
            notify->notifyTokenValue = static_cast<uint32_t>(peer_info->rmt_token_value_udf);
            notify->notifyAddrL = static_cast<uint32_t>(remote_notify_addr);
            notify->notifyAddrH = static_cast<uint32_t>(remote_notify_addr >> kNumHighHalfShiftBits);
            notify->notifyDataL = static_cast<uint32_t>(notify_value);
            notify->notifyDataH = static_cast<uint32_t>(notify_value >> kNumHighHalfShiftBits);
            notify->rsv2[0] = 0;
            notify->rsv2[1] = 0;
            ub_sge += sizeof(AscendC::HcommUrmaNotifyCtx);
        }

        // Fill the local SGE
        const auto sge = reinterpret_cast<__ubuf__ AscendC::HcommUrmaSgeCtx *>(ub_sge);
        sge->len = static_cast<uint32_t>(num_bytes);
        sge->tokenId = 0;
        sge->va = reinterpret_cast<uint64_t>(src_ptr);
    }

    __aicore__ __forceinline__ void copy_sqe_to_sq(const uint32_t current_head, const uint32_t num_wqebbs)
    {
        // WRITE uses one WQEBB; WRITE_WITH_NOTIFY uses two and may wrap the SQ.
        const auto sq_idx = current_head & (kSQDepth - 1);
        const auto num_first_wqebbs = math::min<uint32_t>(num_wqebbs, kSQDepth - sq_idx);

        // Copy the first contiguous SQ segment
        asc_sync_notify(PIPE_S, PIPE_MTE3, EVENT_ID0);
        asc_sync_wait(PIPE_S, PIPE_MTE3, EVENT_ID0);
        asc_copy_ub2gm_align(
            reinterpret_cast<__gm__ uint8_t *>(jetty_info->sq_base_addr +
                                               static_cast<uint64_t>(jetty_info->num_wqebb_bytes) * sq_idx),
            ub_sqe,
            1,                                                               // n_burst
            jetty_info->num_wqebb_bytes * num_first_wqebbs,                  // len_burst
            static_cast<uint8_t>(ST_L2CacheType::L2_CACHE_HINT_NOTALLOC_CI), // l2_cache_mode
            0,                                                               // dst_gap
            0);                                                              // src_gap

        // Wrap the remaining WQEBBs to SQ base
        if (num_first_wqebbs < num_wqebbs) {
            asc_copy_ub2gm_align(reinterpret_cast<__gm__ uint8_t *>(jetty_info->sq_base_addr),
                                 ub_sqe + jetty_info->num_wqebb_bytes * num_first_wqebbs,
                                 1,                                                               // n_burst
                                 jetty_info->num_wqebb_bytes * (num_wqebbs - num_first_wqebbs),   // len_burst
                                 static_cast<uint8_t>(ST_L2CacheType::L2_CACHE_HINT_NOTALLOC_CI), // l2_cache_mode
                                 0,                                                               // dst_gap
                                 0);                                                              // src_gap
        }
        asc_sync_notify(PIPE_MTE3, PIPE_S, EVENT_ID0);
        asc_sync_wait(PIPE_MTE3, PIPE_S, EVENT_ID0);
    }

    __aicore__ __forceinline__ void advance_sq(const uint32_t num_wqebbs)
    {
        const auto new_head = static_cast<uint32_t>(jetty_info->packed_head) + num_wqebbs;
        const auto new_num_completions = static_cast<uint32_t>(jetty_info->packed_head >> kNumHighHalfShiftBits) + 1;
        jetty_info->packed_head =
            static_cast<uint64_t>(new_head) | (static_cast<uint64_t>(new_num_completions) << kNumHighHalfShiftBits);
    }

    __aicore__ __forceinline__ void set_sq_head(const uint32_t new_head)
    {
        jetty_info->packed_head = (jetty_info->packed_head & 0xFFFFFFFF00000000ULL) | new_head;
    }

    __aicore__ __forceinline__ void ring_doorbell()
    {
        AscendC::WriteGmByPassDCache(reinterpret_cast<__gm__ uint64_t *>(jetty_info->sq_head_addr),
                                     jetty_info->packed_head);
        AscendC::DataSyncBarrier<AscendC::MemDsbT::DDR>();
        AscendC::WriteGmByPassDCache(reinterpret_cast<__gm__ uint32_t *>(jetty_info->sq_doorbell_addr),
                                     static_cast<uint32_t>(jetty_info->packed_head));
        AscendC::DataSyncBarrier<AscendC::MemDsbT::DDR>();
    }

    template <int64_t kNumTimeoutCycles, bool kWithNotify, bool kDoCommit>
    __aicore__ __forceinline__ void post_write(const HcommPeer &peer, __gm__ void *local_base, __gm__ void *dst_sym_ptr,
                                               __gm__ void *src_ptr, const uint64_t num_bytes,
                                               __gm__ void *notify_sym_ptr = nullptr, const uint64_t notify_value = 0)
    {
        const auto num_wqebbs = kWithNotify ? kNumWriteWithNotifyWQEBBs : kNumWriteWQEBBs;
        const auto current_head = static_cast<uint32_t>(jetty_info->packed_head);

        // Reclaim CQ entries and prepare the SQE
        poll_cq_when_sq_overflow<kNumTimeoutCycles>();
        build_write_sqe<kWithNotify>(peer, local_base, dst_sym_ptr, src_ptr, num_bytes, current_head, notify_sym_ptr,
                                     notify_value);

        // Publish the SQE and optionally ring the doorbell
        copy_sqe_to_sq(current_head, num_wqebbs);
        advance_sq(num_wqebbs);
        if constexpr (kDoCommit) {
            ring_doorbell();
        }
    }

    template <int64_t kNumTimeoutCycles, bool kDoCommit = true>
    __aicore__ __forceinline__ void put(const HcommPeer &peer, __gm__ void *local_base, __gm__ void *dst_sym_ptr,
                                        __gm__ void *src_ptr, const uint64_t num_bytes)
    {
        post_write<kNumTimeoutCycles, false, kDoCommit>(peer, local_base, dst_sym_ptr, src_ptr, num_bytes);
    }

    template <int64_t kNumTimeoutCycles>
    __aicore__ __forceinline__ void
    put_with_notify(const HcommPeer &peer, __gm__ void *local_base, __gm__ void *dst_sym_ptr, __gm__ void *src_ptr,
                    const uint64_t num_bytes, __gm__ void *notify_sym_ptr, const uint64_t notify_value)
    {
        post_write<kNumTimeoutCycles, true, true>(peer, local_base, dst_sym_ptr, src_ptr, num_bytes, notify_sym_ptr,
                                                  notify_value);
    }

    template <int64_t kNumTimeoutCycles> __aicore__ __forceinline__ void poll_cq(const uint32_t expected_tail)
    {
        static constexpr uint32_t kNumCQDoorbellBits = 24;
        static constexpr uint32_t kCQEOwnerBit = 2;

        // Poll expected completions
        auto current_tail = AscendC::ReadGmByPassDCache(reinterpret_cast<__gm__ uint32_t *>(jetty_info->cq_tail_addr));
        while (current_tail != expected_tail) {
            const auto cqe = reinterpret_cast<__gm__ uint32_t *>(jetty_info->cq_base_addr +
                                                                 static_cast<uint64_t>(jetty_info->num_cqe_bytes) *
                                                                     (current_tail & (jetty_info->cq_depth - 1)));
            const auto tail_phase = (current_tail / jetty_info->cq_depth) & 1;
            const auto start_cycle = static_cast<uint64_t>(asc_get_system_cycle());
            uint32_t cqe_header = 0;
            while (true) {
                cqe_header = AscendC::ReadGmByPassDCache(cqe);
                const auto cqe_owner = (cqe_header >> kCQEOwnerBit) & 1;
                // Hardware flips the owner bit when publishing a new CQE; matching the tail phase means stale data.
                if (cqe_owner != tail_phase) {
                    break;
                }

                if (static_cast<uint64_t>(asc_get_system_cycle()) - start_cycle >= kNumTimeoutCycles) {
                    AscendC::printf(
                        "DeepEP HCOMM scalar CQ poll timeout, current tail: %u, expected tail: %u, cqe: 0x%x\n",
                        current_tail, expected_tail, cqe_header);
                    trap();
                }
                AscendC::Nop<300>();
            }

            const auto substatus = static_cast<uint8_t>(cqe_header >> 16);
            const auto status = static_cast<uint8_t>(cqe_header >> 24);
            if (status != 0 or substatus != 0) {
                AscendC::printf("DeepEP HCOMM scalar CQE failed, current tail: %u, status: %u, substatus: %u\n",
                                current_tail, status, substatus);
                trap();
            }
            ++current_tail;
        }

        // Publish reclaimed CQ and SQ tails
        AscendC::WriteGmByPassDCache(reinterpret_cast<__gm__ uint32_t *>(jetty_info->cq_tail_addr), current_tail);
        AscendC::WriteGmByPassDCache(reinterpret_cast<__gm__ uint32_t *>(jetty_info->cq_doorbell_addr),
                                     current_tail & ((1U << kNumCQDoorbellBits) - 1));
        AscendC::WriteGmByPassDCache(reinterpret_cast<__gm__ uint32_t *>(jetty_info->completion_tail_addr),
                                     current_tail);
    }

    template <int64_t kNumTimeoutCycles> __aicore__ __forceinline__ void drain()
    {
        poll_cq<kNumTimeoutCycles>(static_cast<uint32_t>(jetty_info->packed_head >> kNumHighHalfShiftBits));
    }
};

} // namespace deep_ep::handle
