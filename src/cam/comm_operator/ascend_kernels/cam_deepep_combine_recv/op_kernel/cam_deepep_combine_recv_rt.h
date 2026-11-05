/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2026-2026. All rights reserved.
 * Description: runtime-parameterized AFD combine_recv body for CAM
 * Create: 2026-11-03
 * Note: derived from deep_ep/impls/afd/combine_recv.h. Every
 *       model-dependent dimension is a runtime field; round_step/start are
 *       runtime booleans so single-round and multi-round share one binary. The
 *       UB struct is a static address-0 view sized by kMaxHiddenChunk=8192.
 * History: 2026-11-03 create runtime port
 */
#pragma once
#include <deep_ep/layout/afd/return.h>
#include "cam_deepep_rt_common.h"

// Runtime-parameterized weighted per-route epilogue.
namespace deep_ep::afd::rt {
constexpr uint32_t kMaxHiddenChunk = 8192;
constexpr uint32_t kMaxTopkCombined = 32;
// UB stages and the ledger are 32-byte aligned.
constexpr uint32_t kUbAlignBytes = 32;

// Address-0 UB view helper carried over from the production combine_recv.h.
template <typename T> __aicore__ inline AscendC::LocalTensor<T> combine_local(__ubuf__ T *ptr, uint32_t size)
{
    return AscendC::LocalTensor<T>(AscendC::TPosition::VECCALC, uint32_t(reinterpret_cast<uint64_t>(ptr)), size);
}

struct CombineRecvParams {
    uint32_t num_experts;
    uint32_t num_ranks;
    uint32_t num_topk;
    uint32_t num_hidden;       // hidden elements (bf16)
    uint32_t num_hidden_chunk; // <= num_hidden, 128-aligned
    uint32_t num_vec_cores;
    uint32_t num_ub_bytes;
    uint32_t round_step; // runtime bool: RETURN_ROUND_STEP when non-zero
    uint32_t start;      // runtime bool: round-step admission
    uint64_t timeout_cycles;
};

struct alignas(kUbAlignBytes) CombineRecvUBRT {
    alignas(kUbAlignBytes) bfloat16_t input_stage[2][kMaxHiddenChunk];
    alignas(kUbAlignBytes) float acc_fp32[kMaxHiddenChunk], value_fp32[kMaxHiddenChunk];
    alignas(kUbAlignBytes) bfloat16_t output_bf16[kMaxHiddenChunk];
    alignas(kUbAlignBytes) float weights[kMaxTopkCombined];
    alignas(kUbAlignBytes) int64_t expert_idx[kMaxTopkCombined];
    alignas(kUbAlignBytes) AFDRoundLedger ledger;
    alignas(kUbAlignBytes) uint8_t control_stage[64], status_zero_stage[128];
};
static_assert(sizeof(CombineRecvUBRT) <= kMaxPhysicalUbBytes);

// Native ring reducer DMA shape and two-stage lifetime, with weighted FP32
// accumulation. Rank-partial dedup and the BF16 count=2 shortcut stay absent:
// every route has its own weight. RoundStep only adds bounded per-slot progress
// and a one-time start admission around the same body.
__aicore__ inline void combine_recv_body(const CombineRecvParams &p, __gm__ bfloat16_t *combined_x,
                                         __gm__ int64_t *combined_topk_idx, __gm__ float *topk_weights,
                                         __gm__ uint8_t *token_mask, __gm__ uint8_t *buffer,
                                         __gm__ const AFDTaskInfo *task_info, __gm__ const AFDContextLayout *context,
                                         __gm__ void *control_buffer, __gm__ AFDRoundLedger *round_ledger,
                                         __gm__ void *workspace, __gm__ uint32_t *recv_status,
                                         __gm__ AFDReturnProgress *return_progress)
{
    const int num_experts = int(p.num_experts), num_ranks = int(p.num_ranks);
    const int num_topk = int(p.num_topk), num_hidden = int(p.num_hidden);
    const int num_hidden_chunk = int(p.num_hidden_chunk);
    const int num_vec_cores = int(p.num_vec_cores);
    const uint64_t timeout_cycles = p.timeout_cycles;
    const bool round_step = p.round_step != 0;
    const bool start = p.start != 0;
    const uint32_t weights_len = uint32_t((num_topk + 7) / 8 * 8);

    EP_DEVICE_ASSERT(num_hidden > 0 && num_hidden % 128 == 0);
    EP_DEVICE_ASSERT(num_hidden_chunk > 0 && num_hidden_chunk % 128 == 0 && num_hidden_chunk <= num_hidden &&
                     num_hidden_chunk <= int(kMaxHiddenChunk));
    EP_DEVICE_ASSERT(num_topk > 0 && num_topk <= int(kMaxTopkCombined));
    EP_DEVICE_ASSERT(sizeof(CombineRecvUBRT) <= p.num_ub_bytes);

    AscendC::InitSocState();
    const int vec_core_idx = AscendC::GetBlockIdx();
    const auto task = recv_read(task_info); // replay must not reuse scalar DCache task fields
    __ubuf__ CombineRecvUBRT *ub = 0;
    auto stage = ub->control_stage;
    auto words = reinterpret_cast<__ubuf__ uint32_t *>(stage);
    auto ctx = reinterpret_cast<__gm__ const uint8_t *>(context);
    auto controls = static_cast<__gm__ uint8_t *>(control_buffer);
    auto error = static_cast<__gm__ uint32_t *>(workspace);
    auto probe_ready = error + 8; // private 32B header block, shared by all launched cores
    auto core_error =
        reinterpret_cast<__gm__ uint32_t *>(static_cast<__gm__ uint8_t *>(workspace) + 256 + 32 * vec_core_idx);
    auto lanes = reinterpret_cast<__gm__ const AFDLane *>(ctx + context->lanes_offset);
    auto peers = reinterpret_cast<__gm__ const AFDPeer *>(ctx + context->peers_offset);
    auto addresses = reinterpret_cast<__gm__ const AFDAddress *>(ctx + context->addresses_offset);
    uint32_t lane_idx = context->num_source_lanes;
    for (uint32_t l = 0; l < context->num_source_lanes; ++l) {
        if (lanes[l].src_rank_idx == task.src_rank_idx && lanes[l].payload_slot_idx == task.payload_slot_idx) {
            lane_idx = l;
        }
    }
    if (vec_core_idx == 0) {
        uint32_t code = OK;
        if (context->abi_version != kAbiVersion || task.abi_version != kAbiVersion || !context->reserved_address ||
            context->return_progress_mode != uint32_t(round_step ? RETURN_ROUND_STEP : RETURN_TRANSACTION)) {
            code = BAD_ABI;
        } else if (lane_idx == context->num_source_lanes || task.src_rank_idx != context->src_rank_idx ||
                   task.num_tokens > context->num_token_capacity || !task.num_comm_rounds ||
                   task.payload_slot_idx >= context->num_slots) {
            code = BAD_TASK;
        } else {
            auto layers = reinterpret_cast<__gm__ const uint32_t *>(ctx + context->layers_offset);
            bool valid_layer = false;
            for (uint32_t l = 0; l < context->num_layers; ++l) {
                valid_layer |= layers[l] == task.layer_idx;
            }
            if (!valid_layer) {
                code = BAD_LAYER;
            }
            uint32_t num_local_lanes = 0;
            for (uint32_t l = 0; l < context->num_source_lanes; ++l) {
                num_local_lanes += lanes[l].src_rank_idx == context->src_rank_idx;
            }
            if (code == OK && !round_step && num_local_lanes > 1 && task.num_comm_rounds > 1) {
                code = BAD_TASK;
            }
        }
        if (round_step) {
            if (task.payload_slot_idx < context->num_slots) {
                auto progress = return_progress + task.payload_slot_idx;
                // Preserve the first failure, even if a later sweep has invalid TaskInfo.
                if (AscendC::ReadGmByPassDCache(&progress->state) == RETURN_ERROR) {
                    const uint32_t first_error = AscendC::ReadGmByPassDCache(&progress->error_code);
                    code = first_error != OK ? first_error : uint32_t(STATE_ORDER);
                } else if (code != OK) {
                    AscendC::WriteGmByPassDCache(&progress->error_code, code);
                    AscendC::WriteGmByPassDCache(&progress->state, uint32_t(RETURN_ERROR));
                }
            }
        }
        AscendC::WriteGmByPassDCache(error, code);
        for (int i = 0; i < 8; ++i) {
            words[i] = 0;
        }
        words[0] = 1;
        store_control(recv_status, stage);
    }
    local_join();
    if (AscendC::ReadGmByPassDCache(error) != OK) {
        if (vec_core_idx == 0) {
            words[0] = 3;
            words[1] = AscendC::ReadGmByPassDCache(error);
            store_control(recv_status, stage);
        }
        return;
    }
    const auto lane = recv_read(lanes + lane_idx);
    auto directory = reinterpret_cast<__gm__ const AFDReturnDirectory *>(ctx + context->reserved_address);
    auto return_lanes = reinterpret_cast<__gm__ const AFDReturnLane *>(ctx + directory->lanes_offset);
    const auto return_lane = recv_read(return_lanes + lane_idx);
    if (vec_core_idx == 0) {
        if (directory->version != 1 || directory->return_stride < uint64_t(2) * uint64_t(num_hidden) ||
            !lane.capacity || lane.capacity > kMaxLaneTokens ||
            task.num_comm_rounds < (uint64_t(task.num_tokens) + lane.capacity - 1) / lane.capacity ||
            return_lane.return_offset > context->payload_bytes ||
            uint64_t(lane.capacity) * uint32_t(num_topk) * directory->return_stride >
                context->payload_bytes - return_lane.return_offset) {
            AscendC::WriteGmByPassDCache(error, uint32_t(CAPACITY));
        }
    }
    local_join();
    uint32_t first_round = 0, current_round = 0, last_input_bit = 0;
    // [AFD] Admission is separate from polling. A stable sweep graph uses start=false.
    // This kernel never waits for another slot, and final input ACK is also a probe.
    if (round_step) {
        auto progress = return_progress + task.payload_slot_idx;
        if (vec_core_idx == 0 && AscendC::ReadGmByPassDCache(error) == OK) {
            const auto saved = recv_read(progress);
            uint32_t code = OK;
            if (saved.state == RETURN_ERROR) {
                code = saved.error_code;
            } else if (start) {
                if (saved.state != RETURN_IDLE && saved.state != RETURN_DONE) {
                    code = STATE_ORDER;
                } else {
                    auto dst = reinterpret_cast<__gm__ uint32_t *>(&progress->task);
                    const auto src = reinterpret_cast<const uint32_t *>(&task);
                    for (int i = 0; i < 16; ++i) {
                        AscendC::WriteGmByPassDCache(dst + i, src[i]);
                    }
                    AscendC::WriteGmByPassDCache(&progress->next_round, uint32_t(0));
                    AscendC::WriteGmByPassDCache(&progress->last_input_bit, uint32_t(0));
                    AscendC::WriteGmByPassDCache(&progress->error_code, uint32_t(OK));
                    AscendC::WriteGmByPassDCache(&progress->state, uint32_t(RETURN_RUNNING));
                }
            } else {
                if (saved.state == RETURN_IDLE || saved.state > RETURN_DONE) {
                    code = STATE_ORDER;
                }
                const auto a = reinterpret_cast<const uint32_t *>(&saved.task);
                const auto b = reinterpret_cast<const uint32_t *>(&task);
                for (int i = 0; i < 16; ++i) {
                    if (a[i] != b[i]) {
                        code = STATE_ORDER;
                    }
                }
            }
            if (code != OK) {
                AscendC::WriteGmByPassDCache(error, code);
            }
        }
        local_join();
        const auto saved = recv_read(progress);
        first_round = saved.next_round;
        current_round = first_round;
        last_input_bit = saved.last_input_bit;
    }
    for (uint32_t round_idx = first_round;
         round_idx < task.num_comm_rounds && (!round_step || round_idx == first_round); ++round_idx) {
        current_round = round_idx;
        if (AscendC::ReadGmByPassDCache(error) != OK) {
            break;
        }
        auto ledger = round_ledger + uint64_t(lane.payload_slot_idx) * 2 + round_idx % 2;
        if (vec_core_idx == 0) {
            if (round_step) {
                load_control(stage, ledger);
                AscendC::WriteGmByPassDCache(probe_ready, uint32_t(words[0] == 1));
            } else if (!wait_control(stage, ledger, 1, timeout_cycles)) {
                AscendC::WriteGmByPassDCache(error, uint32_t(TIMEOUT));
            }
        }
        local_join();
        if (AscendC::ReadGmByPassDCache(error) != OK) {
            break;
        }
        if (round_step && !AscendC::ReadGmByPassDCache(probe_ready)) {
            break;
        }
        asc_copy_gm2ub_align(reinterpret_cast<__ubuf__ uint8_t *>(&ub->ledger),
                             reinterpret_cast<__gm__ uint8_t *>(ledger), 1, 64, 0, 0, true,
                             asc_load_l2_cache_mode::NORMAL_FIRST_VICTIM, 0, 0);
        asc_sync_notify(PIPE_MTE2, PIPE_S, EVENT_ID3);
        asc_sync_wait(PIPE_MTE2, PIPE_S, EVENT_ID3);
        AFDRoundLedger saved{};
        {
            auto in = reinterpret_cast<__ubuf__ const uint32_t *>(&ub->ledger);
            auto out = reinterpret_cast<uint32_t *>(&saved);
#pragma unroll
            for (int i = 0; i < int(sizeof(AFDRoundLedger) / sizeof(uint32_t)); ++i) {
                out[i] = in[i];
            }
        }
        last_input_bit = saved.input_bit;
        const uint32_t token_begin =
            uint32_t(math::min(uint64_t(task.num_tokens), uint64_t(round_idx) * lane.capacity));
        const uint32_t num_tokens = math::min(lane.capacity, task.num_tokens - token_begin);
        uint32_t code = OK;
        if (saved.round_idx != round_idx || saved.microbatch_idx != task.microbatch_idx ||
            saved.token_begin != token_begin || saved.num_round_tokens != num_tokens || saved.input_bit > 1 ||
            saved.return_bit > 1 || saved.final_round != uint32_t(round_idx + 1 == task.num_comm_rounds)) {
            code = STATE_ORDER;
        }
        if (round_step) {
            if (vec_core_idx == 0) {
                if (code != OK) {
                    AscendC::WriteGmByPassDCache(error, code);
                }
                bool ready = code == OK;
                for (int f = 0; f < num_ranks && ready; ++f) {
                    load_control(stage, controls + return_lane.done_offset + 64 * f);
                    ready = words[0] == saved.return_bit;
                }
                AscendC::WriteGmByPassDCache(probe_ready, uint32_t(ready));
            }
            local_join();
            if (AscendC::ReadGmByPassDCache(error) != OK || !AscendC::ReadGmByPassDCache(probe_ready)) {
                break;
            }
        }
        // Preflight is parallel, bounded, and completes before any output or credit.
        const uint32_t num_tokens_per_core = (num_tokens + uint32_t(num_vec_cores) - 1) / uint32_t(num_vec_cores);
        const uint32_t core_begin = math::min(num_tokens, uint32_t(vec_core_idx) * num_tokens_per_core);
        const uint32_t core_end = math::min(num_tokens, core_begin + num_tokens_per_core);
        uint32_t mask_begin = UINT32_MAX;
        auto is_live = [&](uint32_t t) __aicore__ {
            if (!token_mask) {
                return true;
            }
            if (mask_begin == UINT32_MAX || t - mask_begin >= 32) {
                mask_begin = t;
                // Exact byte count, including a short final tile; no allocation-tail overread.
                recv_load(ub->status_zero_stage, token_mask + uint64_t(token_begin) + t,
                          math::min(uint32_t(32), core_end - t));
            }
            return ub->status_zero_stage[t - mask_begin] != 0;
        };
        for (uint32_t t = core_begin; t < core_end && code == OK; ++t) {
            const uint32_t token_idx = token_begin + t;
            if (!is_live(t)) {
                continue;
            }
            asc_copy_gm2ub_align(
                reinterpret_cast<__ubuf__ uint8_t *>(ub->expert_idx),
                reinterpret_cast<__gm__ uint8_t *>(combined_topk_idx + uint64_t(token_idx) * uint32_t(num_topk)), 1,
                8 * num_topk, 0, 0, true, asc_load_l2_cache_mode::NORMAL_FIRST_VICTIM, 0, 0);
            asc_sync_notify(PIPE_MTE2, PIPE_S, EVENT_ID3);
            asc_sync_wait(PIPE_MTE2, PIPE_S, EVENT_ID3);
            for (int k = 0; k < num_topk; ++k) {
                const auto expert_idx = ub->expert_idx[k];
                if (expert_idx < 0 || expert_idx >= num_experts) {
                    code = BAD_ROUTE;
                }
                for (int j = 0; j < k; ++j) {
                    if (ub->expert_idx[j] == expert_idx) {
                        code = BAD_ROUTE;
                    }
                }
            }
        }
        AscendC::WriteGmByPassDCache(core_error, code);
        local_join();
        if (vec_core_idx == 0) {
            for (int i = 0; i < num_vec_cores; ++i) {
                auto cptr =
                    reinterpret_cast<__gm__ uint32_t *>(static_cast<__gm__ uint8_t *>(workspace) + 256 + 32 * i);
                const uint32_t c = AscendC::ReadGmByPassDCache(cptr);
                if (c) {
                    AscendC::WriteGmByPassDCache(error, c);
                }
            }
            if (!round_step && AscendC::ReadGmByPassDCache(error) == OK) {
                for (int f = 0; f < num_ranks; ++f) {
                    if (!wait_control(stage, controls + return_lane.done_offset + 64 * f, saved.return_bit,
                                      timeout_cycles)) {
                        AscendC::WriteGmByPassDCache(error, uint32_t(TIMEOUT));
                        break;
                    }
                }
            }
        }
        local_join();
        if (AscendC::ReadGmByPassDCache(error) != OK) {
            break;
        }
        mask_begin = UINT32_MAX;
        for (uint32_t t = core_begin; t < core_end; ++t) {
            const uint32_t token_idx = token_begin + t;
            const bool live = is_live(t);
            if (live) {
                asc_copy_gm2ub_align(ub->weights, topk_weights + uint64_t(token_idx) * uint32_t(num_topk), 1,
                                     4 * num_topk, 0, 0, true, asc_load_l2_cache_mode::NORMAL_FIRST_VICTIM, 0, 0);
                asc_sync_notify(PIPE_MTE2, PIPE_S, EVENT_ID3);
                asc_sync_wait(PIPE_MTE2, PIPE_S, EVENT_ID3);
            }
            for (uint32_t offset = 0; offset < uint32_t(num_hidden); offset += uint32_t(num_hidden_chunk)) {
                const uint32_t count = math::min(uint32_t(num_hidden_chunk), uint32_t(num_hidden) - offset);
                auto acc = combine_local(ub->acc_fp32, num_hidden_chunk);
                auto value = combine_local(ub->value_fp32, num_hidden_chunk);
                auto output = combine_local(ub->output_bf16, num_hidden_chunk);
                AscendC::Duplicate(acc, 0.0f, count);
                AscendC::PipeBarrier<PIPE_V>();
                if (live) {
                    // Two independent stages: prefetch k+1 while V consumes k.
                    for (int k = 0; k < math::min(num_topk, 2); ++k) {
                        auto input = reinterpret_cast<__gm__ bfloat16_t *>(
                                         buffer + return_lane.return_offset +
                                         (uint64_t(t) * uint32_t(num_topk) + uint32_t(k)) * directory->return_stride) +
                                     offset;
                        asc_copy_gm2ub_align(ub->input_stage[k], input, 1, 2 * count, 0, 0, true,
                                             asc_load_l2_cache_mode::NOTALLOC_KEEP, 0, 0);
                        asc_sync_notify(PIPE_MTE2, PIPE_V, static_cast<event_t>(k));
                    }
                    for (int k = 0; k < num_topk; ++k) {
                        const auto event = static_cast<event_t>(k % 2);
                        asc_sync_wait(PIPE_MTE2, PIPE_V, event);
                        AscendC::Cast(value, combine_local(ub->input_stage[k % 2], num_hidden_chunk),
                                      AscendC::RoundMode::CAST_NONE, count);
                        AscendC::PipeBarrier<PIPE_V>();
                        // Read the UB scalar before passing it to vector arithmetic.
                        const float weight = combine_local(ub->weights, weights_len).GetValue(k);
                        asc_sync_notify(PIPE_S, PIPE_V, EVENT_ID4);
                        asc_sync_wait(PIPE_S, PIPE_V, EVENT_ID4);
                        AscendC::Muls(value, value, weight, count);
                        AscendC::PipeBarrier<PIPE_V>();
                        AscendC::Add(acc, acc, value, count);
                        AscendC::PipeBarrier<PIPE_V>();
                        if (k + 2 < num_topk) {
                            asc_sync_notify(PIPE_V, PIPE_MTE2, event);
                            asc_sync_wait(PIPE_V, PIPE_MTE2, event);
                            auto input =
                                reinterpret_cast<__gm__ bfloat16_t *>(
                                    buffer + return_lane.return_offset +
                                    (uint64_t(t) * uint32_t(num_topk) + uint32_t(k + 2)) * directory->return_stride) +
                                offset;
                            asc_copy_gm2ub_align(ub->input_stage[k % 2], input, 1, 2 * count, 0, 0, true,
                                                 asc_load_l2_cache_mode::NOTALLOC_KEEP, 0, 0);
                            asc_sync_notify(PIPE_MTE2, PIPE_V, event);
                        }
                    }
                    // Both input buffers have finished V reads before the next chunk can refill them.
                    asc_sync_notify(PIPE_V, PIPE_MTE2, EVENT_ID2);
                    asc_sync_wait(PIPE_V, PIPE_MTE2, EVENT_ID2);
                }
                AscendC::Cast(output, acc, AscendC::RoundMode::CAST_RINT, count);
                asc_sync_notify(PIPE_V, PIPE_MTE3, EVENT_ID2);
                asc_sync_wait(PIPE_V, PIPE_MTE3, EVENT_ID2);
                asc_copy_ub2gm_align(combined_x + uint64_t(token_idx) * uint32_t(num_hidden) + offset, ub->output_bf16,
                                     1, 2 * count, asc_store_l2_cache_mode::NORMAL_FIRST_VICTIM, 0, 0);
                asc_sync_notify(PIPE_MTE3, PIPE_V, EVENT_ID2);
                asc_sync_wait(PIPE_MTE3, PIPE_V, EVENT_ID2);
            }
        }
        local_join();
        if (vec_core_idx == 0) {
            for (int i = 0; i < 8; ++i) {
                words[i] = 0;
            }
            words[0] = saved.return_bit ^ 1;
            for (int f = 0; f < num_ranks; ++f) {
                store_control(reinterpret_cast<__gm__ void *>(peers[f].control_base + return_lane.credit_offset),
                              stage);
            }
            // SPSC bank is released only after all credit stores completed, never by send_status.
            for (int i = 0; i < 8; ++i) {
                words[i] = 0;
            }
            store_control(ledger, stage);
            if (round_step) {
                auto progress = return_progress + task.payload_slot_idx;
                AscendC::WriteGmByPassDCache(&progress->next_round, round_idx + 1);
                AscendC::WriteGmByPassDCache(&progress->last_input_bit, saved.input_bit);
                AscendC::WriteGmByPassDCache(&progress->state,
                                             uint32_t(saved.final_round ? RETURN_WAIT_ACK : RETURN_RUNNING));
            }
        }
        local_join();
    }
    if (vec_core_idx == 0) {
        if (round_step) {
            auto progress = return_progress + task.payload_slot_idx;
            const auto saved = recv_read(progress);
            uint32_t code = AscendC::ReadGmByPassDCache(error);
            bool complete = saved.state == RETURN_DONE;
            if (code == OK && saved.state == RETURN_WAIT_ACK) {
                complete = true;
                for (int f = 0; f < num_ranks && complete; ++f) {
                    const uint64_t lane_base = uint64_t(lane_idx) * uint32_t(num_ranks) + f;
                    load_control(stage, controls + addresses[lane_base].consumed_offset);
                    complete = words[0] == saved.last_input_bit;
                }
                if (complete) {
                    AscendC::WriteGmByPassDCache(&progress->state, uint32_t(RETURN_DONE));
                }
            }
            if (code != OK) {
                AscendC::WriteGmByPassDCache(&progress->error_code, code);
                AscendC::WriteGmByPassDCache(&progress->state, uint32_t(RETURN_ERROR));
            }
            for (int i = 0; i < 8; ++i) {
                words[i] = 0;
            }
            words[0] = code != OK ? 3 : (complete ? 2 : 1);
            words[1] = code;
            words[2] = saved.next_round;
            words[3] = task.payload_slot_idx;
            store_control(recv_status, stage);
            return;
        }
        if (AscendC::ReadGmByPassDCache(error) == OK) {
            for (int f = 0; f < num_ranks; ++f) {
                if (!wait_control(stage,
                                  controls + addresses[uint64_t(lane_idx) * uint32_t(num_ranks) + f].consumed_offset,
                                  last_input_bit, timeout_cycles)) {
                    AscendC::WriteGmByPassDCache(error, uint32_t(TIMEOUT));
                    break;
                }
            }
        }
        for (int i = 0; i < 8; ++i) {
            words[i] = 0;
        }
        words[0] = AscendC::ReadGmByPassDCache(error) == OK ? 2 : 3;
        words[1] = AscendC::ReadGmByPassDCache(error);
        words[2] = current_round;
        store_control(recv_status, stage);
    }
}
} // namespace deep_ep::afd::rt
