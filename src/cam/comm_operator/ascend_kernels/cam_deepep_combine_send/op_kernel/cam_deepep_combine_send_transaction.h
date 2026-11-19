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

struct FfnCombineAckView {
    __gm__ const AFDPeer *source_peers;
    __gm__ const AFDLane *lane_table;
    __gm__ const AFDReturnLane *return_lanes;
    __gm__ const AFDAddress *addresses;
    uint32_t num_src_ranks;
    uint32_t num_ranks;
    uint32_t rank_idx;
    // Bounds the generic ACK path checks before it publishes; the zero-row path
    // must apply the same contract because those lanes never reach that loop.
    uint32_t num_lanes_per_message;
    uint32_t task_phase;
};

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
    const FfnCombineAckView &ack;
};

struct FfnCombineSliceProgress {
    uint32_t slice_entry = 0;
    uint32_t slice_member = 0;
    uint32_t slice_segment = 0;
    uint32_t retired = 0;
    uint32_t finished = 0;
    // Rounds that already reached zero remaining rows and carry no slice entry.
    uint32_t zero_retired = 0;
    uint32_t next_tx_member = 0;
    uint64_t total_rows = 0;
};

struct FfnCombineRoundProgress {
    bool present;
    uint64_t rows = 0;
    uint64_t remaining_rows = 0;
    bool has_representative = false;
};

__aicore__ static bool valid_ffn_zero_row_ack(const FfnCombineSliceView &view, uint32_t lane_idx)
{
    const auto &ack = view.ack;
    const auto lane = recv_read(ack.lane_table + lane_idx);
    if (lane.src_rank_idx >= ack.num_src_ranks || lane.phase != view.task.phase) {
        return false;
    }
    const auto peer = recv_read(ack.source_peers + lane.src_rank_idx);
    const auto ret = recv_read(ack.return_lanes + lane_idx);
    const auto address = recv_read(ack.addresses + uint64_t(lane_idx) * ack.num_ranks + ack.rank_idx);
    constexpr uint64_t kAckBytes = sizeof(AFDControlBlock);
    const uint64_t done_rank_offset = uint64_t(ack.rank_idx) * 2 * kAckBytes;
    return peer.control_base != 0 && peer.control_bytes <= UINT64_MAX - peer.control_base &&
           recv_range(ret.done_offset, done_rank_offset + kAckBytes, peer.control_bytes) &&
           recv_range(address.consumed_offset, kAckBytes, peer.control_bytes);
}

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
        } else if (round.remaining_rows == 0 && !valid_ffn_zero_row_ack(view, member.source_lane_idx)) {
            // No Active entry means the common member preflight will not see this lane.
            return BAD_ABI;
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
    // The Active describes this slice; a round whose rows already reached zero
    // may have no slice entry at all (zero-route round). It still has to retire.
    const bool empty_round = !present && progress.rows == 0 && round.remaining_rows == 0;
    if (!progress.has_representative || progress.remaining_rows != round.remaining_rows ||
        (!empty_round && present != (progress.rows != 0 || round.remaining_rows == 0))) {
        return STATE_ORDER;
    }
    if (empty_round) {
        ++slice.zero_retired;
        return OK;
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
    __gm__ const uint32_t *layers, uint32_t lanes, uint32_t experts, uint32_t num_layers,
    const FfnCombineAckView &ack)
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
        lanes, experts, ack
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
        ((slice.retired + slice.finished + slice.zero_retired == tx.num_entries) !=
         (tx.slice_end == groups))) {
        return STATE_ORDER;
    }
    return OK;
}

constexpr uint32_t kLanesPerAckWord = 32;
// A zero-row round can list at most every source lane once per message.
constexpr uint32_t kMaxAckLanesPerRound = 256;

template <bool kDone>
__aicore__ inline void publish_entry_acks(const AFDActiveEntry &entry, __gm__ const AFDActiveMember *members,
    uint32_t num_lanes, uint32_t *lanes_seen, const FfnCombineAckView &ack, __ubuf__ uint8_t *tmp)
{
    auto words = reinterpret_cast<__ubuf__ uint32_t *>(tmp);
    constexpr uint32_t kAckBytes = sizeof(AFDControlBlock);
    for (uint32_t m = entry.member_begin; m < entry.member_begin + entry.num_members; ++m) {
        const auto member = recv_read(members + m);
        const uint32_t l = member.source_lane_idx;
        if (l >= num_lanes) {
            continue;
        }
        const uint32_t bit = 1u << (l % kLanesPerAckWord);
        auto &seen = lanes_seen[l / kLanesPerAckWord];
        if ((seen & bit) != 0u) {
            continue;
        }
        seen |= bit;
        for (uint32_t w = 0; w < kAckBytes / sizeof(*words); ++w) {
            words[w] = 0;
        }
        words[0] = kDone ? member.return_bit : member.input_bit;
        auto dst = reinterpret_cast<__gm__ uint8_t *>(ack.source_peers[ack.lane_table[l].src_rank_idx].control_base);
        const uint64_t offset = kDone ? ack.return_lanes[l].done_offset + uint64_t(ack.rank_idx) * 2 * kAckBytes :
            ack.addresses[uint64_t(l) * ack.num_ranks + ack.rank_idx].consumed_offset;
        store_control(dst + offset, tmp);
    }
}

template <uint32_t kMaxLanes>
__aicore__ inline void publish_completion_acks(__gm__ const AFDActiveEntry *entries, uint32_t num_entries,
    __gm__ const AFDActiveMember *members, uint32_t num_lanes, const FfnCombineAckView &ack, __ubuf__ uint8_t *tmp)
{
    // A lane has one control block per ACK kind for this F rank. Keep the
    // first publication even when a later completion member repeats the lane.
    constexpr uint32_t kAckBitmapWords = (kMaxLanes + kLanesPerAckWord - 1) / kLanesPerAckWord;
    uint32_t done_lanes_seen[kAckBitmapWords]{};
    uint32_t consumed_lanes_seen[kAckBitmapWords]{};
    for (uint32_t i = 0; i < num_entries; ++i) {
        const auto entry = recv_read(entries + i);
        if (!entry.is_final) {
            continue;
        }
        publish_entry_acks<true>(entry, members, num_lanes, done_lanes_seen, ack, tmp);
        publish_entry_acks<false>(entry, members, num_lanes, consumed_lanes_seen, ack, tmp);
    }
}

// Validate one zero-row ACK target exactly like the generic ACK path
// (combine_send_rt.h: the lane sweep before any store). Zero-row members never
// reach that sweep, so their lane metadata and control offsets must be checked
// here instead of being trusted from the round record.
__aicore__ static uint32_t validate_zero_row_ack_target(const AFDFfnEntry &round,
    __gm__ const AFDActiveMember *tx_members, const FfnCombineAckView &ack, uint32_t *lanes_seen)
{
    if (round.num_members > kMaxAckLanesPerRound) {
        return BAD_TASK;
    }
    for (uint32_t m = 0; m < round.num_members; ++m) {
        const auto member = recv_read(tx_members + round.member_begin + m);
        const uint32_t l = member.source_lane_idx;
        if (l >= ack.num_lanes_per_message || member.input_bit > 1 || member.return_bit > 1) {
            return BAD_TASK;
        }
        const uint32_t bit = 1u << (l % kLanesPerAckWord);
        auto &seen = lanes_seen[l / kLanesPerAckWord];
        if ((seen & bit) != 0u) {
            continue;
        }
        seen |= bit;
        const auto lane = recv_read(ack.lane_table + l);
        // capacity sizes the return window, which a zero-row ACK never touches; only the
        // routing identity (src rank, phase) and the control offsets are load-bearing here.
        if (lane.src_rank_idx >= ack.num_src_ranks || lane.phase != ack.task_phase) {
            return BAD_ABI;
        }
        const auto peer = recv_read(ack.source_peers + lane.src_rank_idx);
        const auto ret = recv_read(ack.return_lanes + l);
        if (!recv_range(ret.done_offset + uint64_t(ack.rank_idx) * 2 * sizeof(AFDControlBlock),
                        sizeof(AFDControlBlock), peer.control_bytes) ||
            !recv_range(ack.addresses[uint64_t(l) * ack.num_ranks + ack.rank_idx].consumed_offset,
                        sizeof(AFDControlBlock), peer.control_bytes)) {
            return BAD_ABI;
        }
    }
    return OK;
}

template <bool kDone>
__aicore__ static void publish_ffn_zero_row_acks(const AFDFfnEntry &round, __gm__ const AFDActiveMember *tx_members,
                                                const FfnCombineAckView &ack, __ubuf__ uint8_t *tmp)
{
    auto words = reinterpret_cast<__ubuf__ uint32_t *>(tmp);
    constexpr uint64_t kAckBytes = sizeof(AFDControlBlock);
    for (uint32_t m = 0; m < round.num_members; ++m) {
        const auto member = recv_read(tx_members + round.member_begin + m);
        const uint32_t l = member.source_lane_idx;
        const auto lane = recv_read(ack.lane_table + l);
        uint64_t offset;
        if constexpr (kDone) {
            const auto ret = recv_read(ack.return_lanes + l);
            offset = ret.done_offset + uint64_t(ack.rank_idx) * 2 * kAckBytes;
        } else {
            offset = ack.addresses[uint64_t(l) * ack.num_ranks + ack.rank_idx].consumed_offset;
        }
        for (uint32_t w = 1; w < kAckBytes / sizeof(*words); ++w) {
            words[w] = 0;
        }
        words[0] = kDone ? member.return_bit : member.input_bit;
        auto dst = reinterpret_cast<__gm__ uint8_t *>(ack.source_peers[lane.src_rank_idx].control_base);
        store_control(dst + offset, tmp);
    }
}

__aicore__ static bool commit_matching_ffn_slice_entry(
    __gm__ AFDFfnEntry *round_ptr, const AFDFfnEntry &round, __gm__ const AFDActiveEntry *entries,
    uint32_t num_entries, uint32_t &slice_entry, uint32_t &completed)
{
    if (slice_entry >= num_entries) {
        return false;
    }
    const auto entry = recv_read(entries + slice_entry);
    if (entry.pending_idx != round.pending_idx) {
        return false;
    }
    AscendC::WriteGmByPassDCache(&round_ptr->remaining_rows, round.remaining_rows - entry.num_rows);
    AscendC::WriteGmByPassDCache(&round_ptr->grant_state, uint32_t(entry.is_final ? FINISHED : HELD));
    if (entry.is_final) {
        AscendC::WriteGmByPassDCache(&round_ptr->retired, 1u);
        ++completed;
    }
    ++slice_entry;
    return true;
}

// Called by the coordinator after every peer queue drains and before ACKs can
// let an A rank replace a retired lane's Inbox and payload.
// Returns OK, or BAD_ABI when a zero-row ACK target fails the same lane/control
// validation the generic ACK sweep performs. Callers must stop on a non-OK value
// instead of publishing further protocol state.
__aicore__ static uint32_t retire_ffn_slice_rounds(
    const AFDActive &task, __gm__ AFDFfnTransaction *transaction, __gm__ uint8_t *active,
    __gm__ const AFDActiveEntry *entries, uint32_t lanes, uint32_t experts,
    const FfnCombineAckView &ack, __ubuf__ uint8_t *tmp)
{
    auto tx_counts = reinterpret_cast<__gm__ const uint32_t *>(active + ffn_counts_offset(lanes, experts));
    const auto tx = recv_read(transaction);
    auto tx_entries = reinterpret_cast<__gm__ AFDFfnEntry *>(active + ffn_entries_offset(lanes, experts));
    auto tx_members = reinterpret_cast<__gm__ const AFDActiveMember *>(active + ffn_members_offset(lanes, experts));
    uint32_t slice_entry = 0, completed = tx.completed_entries;
    for (uint32_t i = 0; i < tx.num_entries; ++i) {
        auto round_ptr = tx_entries + i;
        const auto round = recv_read(round_ptr);
        if (round.retired) {
            continue;
        }
        if (commit_matching_ffn_slice_entry(round_ptr, round, entries, task.num_entries, slice_entry, completed)) {
            continue;
        }
        if (round.remaining_rows != 0) {
            continue;
        }
        // A round owns one group per local expert (layer_slot * experts + e). A slice
        // window can cut through that span, and validate_ffn_combine_round_members
        // already counts only groups >= next_group as outstanding. Mirror that rule
        // here: retire only when no group of this round at or beyond next_group still
        // carries rows, i.e. the round is fully consumed rather than merely having
        // this slice's groups consumed. Otherwise Done/Consumed would be published for
        // a round that still owes rows to a later slice.
        bool owes_later_slice = false;
        for (uint32_t e = 0; e < experts && !owes_later_slice; ++e) {
            const uint32_t group = round.layer_slot * experts + e;
            if (group < tx.next_group) {
                continue;
            }
            const uint32_t count = recv_read(tx_counts + uint64_t(i) * experts + e);
            owes_later_slice = count != 0;
        }
        if (owes_later_slice) {
            continue;
        }
        // Zero-row round with no Active entry: acknowledge its members here, since
        // the generic ACK loop below only walks slice entries. Validate the lanes
        // and control offsets first so this path keeps the same ABI contract as
        // the generic ACK sweep, and publish nothing when validation fails.
        uint32_t zero_row_seen[(kMaxAckLanesPerRound + kLanesPerAckWord - 1) / kLanesPerAckWord]{};
        if (validate_zero_row_ack_target(round, tx_members, ack, zero_row_seen) != OK) {
            AscendC::WriteGmByPassDCache(&transaction->completed_entries, completed);
            return BAD_ABI;
        }
        publish_ffn_zero_row_acks<true>(round, tx_members, ack, tmp);
        publish_ffn_zero_row_acks<false>(round, tx_members, ack, tmp);
        AscendC::WriteGmByPassDCache(&round_ptr->grant_state, uint32_t(FINISHED));
        AscendC::WriteGmByPassDCache(&round_ptr->retired, 1u);
        ++completed;
    }
    AscendC::WriteGmByPassDCache(&transaction->completed_entries, completed);
    return OK;
}

}  // namespace deep_ep::afd::rt
