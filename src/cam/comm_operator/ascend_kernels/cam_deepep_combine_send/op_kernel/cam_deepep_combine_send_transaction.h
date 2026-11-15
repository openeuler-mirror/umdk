/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2026-2026. All rights reserved.
 * Description: F-local transaction validation and commit for CAM combine_send.
 *
 * CAM modifications: Validates the slice and updates transaction and
 * round retirement state after the return writes drain.
 */
#pragma once

#include <deep_ep/layout/afd/ffn_transaction.h>

namespace deep_ep::afd::rt {

struct FfnCombineSliceView {
    const AFDActive &task;
    const AFDFfnTransaction &tx;
    __gm__ const AFDFfnEntry *tx_entries;
    __gm__ const AFDActiveMember *tx_members;
    __gm__ const uint32_t *tx_counts;
    __gm__ const AFDActiveEntry *entries;
    __gm__ const AFDActiveMember *members;
    __gm__ const AFDActiveSegment *segments;
    uint32_t lanes;
    uint32_t experts;
};

struct FfnCombineSliceProgress {
    uint32_t slice_entry = 0;
    uint32_t slice_member = 0;
    uint32_t slice_segment = 0;
    uint32_t retired = 0;
    uint32_t finished = 0;
    uint32_t next_tx_member = 0;
    uint64_t total_rows = 0;
};

struct FfnCombineRoundProgress {
    bool present;
    uint64_t rows = 0;
    uint64_t remaining_rows = 0;
    bool has_representative = false;
};

__aicore__ static uint32_t validate_ffn_combine_member_segments(
    const FfnCombineSliceView &view, const AFDFfnEntry &round, const AFDActiveMember &member,
    uint32_t tx_member, FfnCombineSliceProgress &slice, FfnCombineRoundProgress &progress)
{
    uint64_t route_begin = 0;
    for (uint32_t e = 0; e < view.experts; ++e) {
        const uint32_t count = recv_read(view.tx_counts + uint64_t(tx_member) * view.experts + e);
        const uint32_t group = round.layer_slot * view.experts + e;
        if (count > kMaxLaneTokens) {
            return BAD_ROUTE;
        }
        if (group >= view.tx.next_group) {
            progress.remaining_rows += count;
        }
        if (group >= view.tx.next_group && group < view.tx.slice_end && count != 0) {
            if (!progress.present || slice.slice_segment >= view.task.num_segments) {
                return BAD_TASK;
            }
            const auto segment = recv_read(view.segments + slice.slice_segment);
            if (segment.entry_idx != slice.slice_entry || segment.source_lane_idx != member.source_lane_idx ||
                segment.local_expert_idx != e || segment.reserved[0] != group ||
                segment.route_begin != route_begin || segment.num_routes != count) {
                return BAD_TASK;
            }
            ++slice.slice_segment;
            progress.rows += count;
        }
        route_begin += count;
    }
    return OK;
}

__aicore__ static uint32_t validate_ffn_combine_round_members(
    const FfnCombineSliceView &view, const AFDFfnEntry &round,
    FfnCombineSliceProgress &slice, FfnCombineRoundProgress &progress)
{
    for (uint32_t j = 0; j < round.num_members; ++j) {
        const uint32_t tx_member = round.member_begin + j;
        const auto member = recv_read(view.tx_members + tx_member);
        if (member.source_lane_idx >= view.lanes || member.input_bit > 1 || member.return_bit > 1 ||
            member.num_experts != view.experts || member.reserved[0] != round.layer_slot) {
            return BAD_TASK;
        }
        progress.has_representative |= member.source_lane_idx == round.pending_idx;
        if (progress.present) {
            const auto actual = recv_read(view.members + slice.slice_member + j);
            if (actual.source_lane_idx != member.source_lane_idx || actual.input_bit != member.input_bit ||
                actual.return_bit != member.return_bit || actual.num_experts != view.experts ||
                actual.reserved[0] != round.layer_slot) {
                return BAD_TASK;
            }
        }
        const uint32_t error = validate_ffn_combine_member_segments(view, round, member, tx_member, slice, progress);
        if (error != OK) {
            return error;
        }
    }
    return OK;
}

__aicore__ static uint32_t validate_ffn_combine_round(
    const FfnCombineSliceView &view, const AFDFfnEntry &round, FfnCombineSliceProgress &slice)
{
    if (round.grant_state > HELD) {
        return STATE_ORDER;
    }
    AFDActiveEntry entry{};
    if (slice.slice_entry < view.task.num_entries) {
        entry = recv_read(view.entries + slice.slice_entry);
    }
    const bool present = slice.slice_entry < view.task.num_entries && entry.pending_idx == round.pending_idx;
    const uint32_t first_segment = slice.slice_segment;
    if (present && (entry.member_begin != slice.slice_member || entry.segment_begin != first_segment ||
                    entry.num_members != round.num_members ||
                    entry.num_members > view.task.num_members - slice.slice_member ||
                    entry.grant_state != round.grant_state)) {
        return BAD_TASK;
    }
    FfnCombineRoundProgress progress{present};
    const uint32_t error = validate_ffn_combine_round_members(view, round, slice, progress);
    if (error != OK) {
        return error;
    }
    if (!progress.has_representative || progress.remaining_rows != round.remaining_rows ||
        present != (progress.rows != 0 || round.remaining_rows == 0)) {
        return STATE_ORDER;
    }
    if (present) {
        const bool is_final = progress.rows == round.remaining_rows;
        if (entry.num_rows != progress.rows || entry.is_final != uint32_t(is_final) ||
            entry.num_segments != slice.slice_segment - first_segment) {
            return STATE_ORDER;
        }
        ++slice.slice_entry;
        slice.slice_member += round.num_members;
        slice.finished += uint32_t(is_final);
        slice.total_rows += progress.rows;
    }
    return OK;
}

__aicore__ static uint32_t validate_ffn_combine_rounds(
    const FfnCombineSliceView &view, __gm__ const uint32_t *layers, uint32_t num_layers,
    FfnCombineSliceProgress &slice)
{
    for (uint32_t i = 0; i < view.tx.num_entries; ++i) {
        const auto round = recv_read(view.tx_entries + i);
        if (round.pending_idx >= view.lanes || round.layer_slot >= num_layers ||
            recv_read(layers + round.layer_slot) == kFfnMixedLayer ||
            round.member_begin != slice.next_tx_member || round.num_members == 0 ||
            round.num_members > view.tx.num_members - slice.next_tx_member || round.retired > 1) {
            return BAD_TASK;
        }
        slice.next_tx_member += round.num_members;
        if (round.retired) {
            if (round.remaining_rows != 0 || round.grant_state != FINISHED) {
                return STATE_ORDER;
            }
            ++slice.retired;
            continue;
        }
        const uint32_t error = validate_ffn_combine_round(view, round, slice);
        if (error != OK) {
            return error;
        }
    }
    return OK;
}

// The DR planner emits entries, then their members, then each member's nonzero
// experts in ascending order. Match the whole slice against the immutable
// snapshot before issuing any remote write.
__aicore__ static uint32_t validate_ffn_combine_slice(
    const AFDActive &task, const AFDFfnTransaction &tx, __gm__ const uint8_t *active,
    __gm__ const uint32_t *layers, uint32_t lanes, uint32_t experts, uint32_t num_layers)
{
    const uint32_t groups = num_layers * experts;
    if (tx.state != kFfnSlice || tx.num_entries == 0 || tx.num_entries > lanes ||
        tx.num_members > lanes || tx.completed_entries >= tx.num_entries ||
        tx.slice_idx == UINT32_MAX || tx.next_group > tx.slice_end || tx.slice_end > groups ||
        (tx.next_group == tx.slice_end && tx.slice_end != groups)) {
        return STATE_ORDER;
    }
    const FfnCombineSliceView view{
        task, tx,
        reinterpret_cast<__gm__ const AFDFfnEntry *>(active + ffn_entries_offset(lanes, experts)),
        reinterpret_cast<__gm__ const AFDActiveMember *>(active + ffn_members_offset(lanes, experts)),
        reinterpret_cast<__gm__ const uint32_t *>(active + ffn_counts_offset(lanes, experts)),
        reinterpret_cast<__gm__ const AFDActiveEntry *>(active + task.entries_offset),
        reinterpret_cast<__gm__ const AFDActiveMember *>(active + task.members_offset),
        reinterpret_cast<__gm__ const AFDActiveSegment *>(active + task.segments_offset),
        lanes, experts
    };
    auto group_counts = reinterpret_cast<__gm__ const uint32_t *>(active + ffn_groups_offset(lanes, experts));
    FfnCombineSliceProgress slice{};
    const uint32_t error = validate_ffn_combine_rounds(view, layers, num_layers, slice);
    if (error != OK) {
        return error;
    }
    uint64_t group_rows = 0;
    for (uint32_t group = tx.next_group; group < tx.slice_end; ++group) {
        group_rows += recv_read(group_counts + group);
    }
    if (slice.next_tx_member != tx.num_members || slice.retired != tx.completed_entries ||
        slice.slice_entry != task.num_entries || slice.slice_member != task.num_members ||
        slice.slice_segment != task.num_segments || slice.total_rows != task.num_expanded_tokens ||
        slice.total_rows != group_rows ||
        ((slice.retired + slice.finished == tx.num_entries) != (tx.slice_end == groups))) {
        return STATE_ORDER;
    }
    return OK;
}

// Called by the coordinator after every peer queue drains and before ACKs can
// let an A rank replace a retired lane's Inbox and payload.
__aicore__ static void retire_ffn_slice_rounds(
    const AFDActive &task, __gm__ AFDFfnTransaction *transaction, __gm__ uint8_t *active,
    __gm__ const AFDActiveEntry *entries, uint32_t lanes, uint32_t experts)
{
    const auto tx = recv_read(transaction);
    auto tx_entries = reinterpret_cast<__gm__ AFDFfnEntry *>(active + ffn_entries_offset(lanes, experts));
    uint32_t slice_entry = 0, completed = tx.completed_entries;
    for (uint32_t i = 0; i < tx.num_entries && slice_entry < task.num_entries; ++i) {
        const auto entry = recv_read(entries + slice_entry);
        auto round_ptr = tx_entries + i;
        const auto round = recv_read(round_ptr);
        if (round.retired || round.pending_idx != entry.pending_idx) {
            continue;
        }
        AscendC::WriteGmByPassDCache(&round_ptr->remaining_rows, round.remaining_rows - entry.num_rows);
        AscendC::WriteGmByPassDCache(&round_ptr->grant_state, uint32_t(entry.is_final ? FINISHED : HELD));
        if (entry.is_final) {
            AscendC::WriteGmByPassDCache(&round_ptr->retired, 1u);
            ++completed;
        }
        ++slice_entry;
    }
    AscendC::WriteGmByPassDCache(&transaction->completed_entries, completed);
}

}  // namespace deep_ep::afd::rt
