/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2026-2026. All rights reserved.
 *
 * Description: Builds and validates the CAM FFN transaction slice.
 * CAM modifications: Groups whole layer/expert segments into a slice
 * under the valid-row and padded-row capacities.
 */
#pragma once

#include <afd_async/layout/afd/ffn_transaction.h>

namespace afd_async::afd::rt {

// The planner runs on AIV 0. Each record consists of 32-bit words, including
// the two halves of the legacy Active's 64-bit offsets.
template <typename Record>
__aicore__ inline void write_dispatch_plan_record(__gm__ Record *dst, const Record &record)
{
    auto words = reinterpret_cast<__gm__ uint32_t *>(dst);
    auto values = reinterpret_cast<const uint32_t *>(&record);
#pragma unroll
    for (uint32_t i = 0; i < sizeof(Record) / sizeof(uint32_t); ++i) {
        AscendC::WriteGmByPassDCache(words + i, values[i]);
    }
}

__aicore__ static uint32_t dispatch_group_lower_bound(__gm__ const uint32_t *group_ids,
                                                     uint32_t size, uint32_t group)
{
    uint32_t lo = 0;
    while (lo < size) {
        const uint32_t mid = lo + (size - lo) / 2;
        if (recv_read(group_ids + mid) < group) {
            lo = mid + 1;
        } else {
            size = mid;
        }
    }
    return lo;
}

struct DispatchSliceGroups {
    __gm__ uint32_t *ids;
    __gm__ uint32_t *write_rows;
    uint64_t capacity;
    uint32_t begin, end, used, expanded, physical;
};

struct DispatchSliceTables {
    __gm__ const AFDFfnEntry *tx_entries;
    __gm__ const AFDActiveMember *tx_members;
    __gm__ const uint32_t *counts;
    __gm__ AFDActiveEntry *entries;
    __gm__ AFDActiveMember *members;
    __gm__ AFDActiveSegment *segments;
    __gm__ uint32_t *grants;
};

// Whole groups are packed in ascending (layer slot, local expert) order.
// The existing DR scratch arrays temporarily hold the nonempty groups' IDs
// and output cursors. Preflight reuses the arrays for sorting after this join.
__aicore__ static uint32_t select_dispatch_groups(
    const DispatchRecvParams &p, __gm__ const uint8_t *base, __gm__ uint8_t *workspace,
    uint32_t next_group, DispatchSliceGroups &groups)
{
    const uint32_t lanes = p.num_source_lanes, experts = p.experts_per_rank;
    const uint32_t num_groups = p.num_layers * experts;
    const auto group_rows = reinterpret_cast<__gm__ const uint32_t *>(base + ffn_groups_offset(lanes, experts));
    const uint64_t scratch_bytes = recv_segment_index_bytes(lanes, experts, p.max_expanded_tokens);
    auto scratch = workspace + recv_workspace_bytes(p.num_vec_cores);
    groups.ids = reinterpret_cast<__gm__ uint32_t *>(scratch);
    groups.write_rows = reinterpret_cast<__gm__ uint32_t *>(scratch + scratch_bytes);
    groups.capacity = recv_segment_capacity(lanes, experts, p.max_expanded_tokens);
    groups.begin = groups.end = next_group;
    while (groups.end < num_groups) {
        const uint32_t rows = recv_read(group_rows + groups.end);
        if (rows == 0) {
            ++groups.end;
            continue;
        }
        const uint64_t padded =
            (uint64_t(rows) + p.expert_alignment - 1) / p.expert_alignment * p.expert_alignment;
        if (rows > p.max_expanded_tokens - groups.expanded || padded > p.max_padded_tokens - groups.physical) {
            if (groups.used == 0) {
                return CAPACITY;
            }
            break;
        }
        if (groups.used >= groups.capacity) {
            return CAPACITY;
        }
        AscendC::WriteGmByPassDCache(groups.ids + groups.used, groups.end);
        AscendC::WriteGmByPassDCache(groups.write_rows + groups.used, groups.physical);
        ++groups.used;
        ++groups.end;
        groups.expanded += rows;
        groups.physical += uint32_t(padded);
    }
    AscendC::DataSyncBarrier<AscendC::MemDsbT::DDR>();
    return OK;
}

__aicore__ static uint32_t count_dispatch_entry_rows(
    const DispatchRecvParams &p, const DispatchSliceTables &tables, const DispatchSliceGroups &groups,
    const AFDFfnEntry &entry, uint64_t &rows)
{
    const uint32_t experts = p.experts_per_rank;
    const uint32_t layer_base = entry.layer_slot * experts;
    const uint32_t member_end = entry.member_begin + entry.num_members;
    uint64_t remaining_rows = 0;
    for (uint32_t m = entry.member_begin; m < member_end; ++m) {
        const auto member = recv_read(tables.tx_members + m);
        if (member.source_lane_idx >= p.num_source_lanes || member.num_experts != experts ||
            member.reserved[0] != entry.layer_slot || member.input_bit > 1 || member.return_bit > 1) {
            return BAD_TASK;
        }
        for (uint32_t e = 0; e < experts; ++e) {
            const uint32_t count = recv_read(tables.counts + uint64_t(m) * experts + e);
            if (count > kMaxLaneTokens) {
                return BAD_ROUTE;
            }
            const uint32_t group = layer_base + e;
            if (group >= groups.begin) {
                remaining_rows += count;
                if (group < groups.end) {
                    rows += count;
                }
            }
        }
    }
    return remaining_rows == entry.remaining_rows ? OK : BAD_ROUTE;
}

__aicore__ static uint32_t append_dispatch_member(
    const DispatchSliceTables &tables, const DispatchSliceGroups &groups, uint32_t experts,
    uint32_t layer_base, uint32_t member_idx, AFDActive &plan)
{
    auto member = recv_read(tables.tx_members + member_idx);
    member.delta_begin = plan.num_members * experts;
    write_dispatch_plan_record(tables.members + plan.num_members++, member);
    uint32_t route_begin = 0;
    for (uint32_t e = 0; e < experts; ++e) {
        const uint32_t count = recv_read(tables.counts + uint64_t(member_idx) * experts + e);
        const uint32_t group = layer_base + e;
        if (count && group >= groups.begin && group < groups.end) {
            const uint32_t slot = dispatch_group_lower_bound(groups.ids, groups.used, group);
            if (slot >= groups.used || recv_read(groups.ids + slot) != group || plan.num_segments >= groups.capacity) {
                return BAD_ROUTE;
            }
            const uint32_t dst = recv_read(groups.write_rows + slot);
            if (dst > groups.physical || count > groups.physical - dst) {
                return BAD_ROUTE;
            }
            AFDActiveSegment segment{};
            segment.entry_idx = plan.num_entries;
            segment.source_lane_idx = member.source_lane_idx;
            segment.local_expert_idx = e;
            segment.route_begin = route_begin;
            segment.num_routes = count;
            segment.dst_row_begin = dst;
            segment.reserved[0] = group;
            write_dispatch_plan_record(tables.segments + plan.num_segments++, segment);
            AscendC::WriteGmByPassDCache(groups.write_rows + slot, dst + count);
        }
        route_begin += count;
    }
    return OK;
}

__aicore__ static uint32_t append_dispatch_entry(
    const DispatchSliceTables &tables, const DispatchSliceGroups &groups, uint32_t experts,
    const AFDFfnEntry &entry, uint64_t rows, AFDActive &plan)
{
    AFDActiveEntry slice{};
    slice.pending_idx = entry.pending_idx;
    slice.member_begin = plan.num_members;
    slice.num_members = entry.num_members;
    slice.segment_begin = plan.num_segments;
    slice.num_rows = uint32_t(rows);
    slice.is_final = rows == entry.remaining_rows;
    slice.grant_state = entry.grant_state;
    const uint32_t layer_base = entry.layer_slot * experts;
    const uint32_t member_end = entry.member_begin + entry.num_members;
    for (uint32_t m = entry.member_begin; m < member_end; ++m) {
        const uint32_t error = append_dispatch_member(tables, groups, experts, layer_base, m, plan);
        if (error != OK) {
            return error;
        }
    }
    slice.num_segments = plan.num_segments - slice.segment_begin;
    write_dispatch_plan_record(tables.entries + plan.num_entries, slice);
    AscendC::WriteGmByPassDCache(tables.grants + plan.num_entries++, slice.grant_state);
    return OK;
}

__aicore__ static uint32_t build_dispatch_slice_records(
    const DispatchRecvParams &p, const DispatchSliceTables &tables, const DispatchSliceGroups &groups,
    const AFDFfnTransaction &tx, AFDActive &plan)
{
    uint32_t seen_members = 0;
    uint32_t retired = 0;
    uint64_t seen_rows = 0;
    for (uint32_t i = 0; i < tx.num_entries; ++i) {
        const auto entry = recv_read(tables.tx_entries + i);
        if (entry.member_begin != seen_members || entry.num_members == 0 ||
            entry.num_members > tx.num_members - seen_members || entry.layer_slot >= p.num_layers ||
            entry.pending_idx >= p.num_source_lanes || entry.retired > 1 || entry.grant_state > FINISHED) {
            return BAD_TASK;
        }
        seen_members += entry.num_members;
        if (entry.retired) {
            if (entry.remaining_rows != 0 || entry.grant_state != FINISHED) {
                return STATE_ORDER;
            }
            ++retired;
            continue;
        }
        if (entry.grant_state > HELD) {
            return STATE_ORDER;
        }
        uint64_t rows = 0;
        uint32_t error = count_dispatch_entry_rows(p, tables, groups, entry, rows);
        if (error != OK) {
            return error;
        }
        if (rows > groups.expanded - seen_rows) {
            return BAD_ROUTE;
        }
        if (rows == 0 && entry.remaining_rows != 0) {
            continue;
        }
        seen_rows += rows;
        error = append_dispatch_entry(tables, groups, p.experts_per_rank, entry, rows, plan);
        if (error != OK) {
            return error;
        }
    }
    if (seen_members != tx.num_members || seen_rows != groups.expanded || plan.num_entries == 0 ||
        retired != tx.completed_entries) {
        return BAD_TASK;
    }
    return OK;
}

__aicore__ static uint32_t prepare_dispatch_slice(
    const DispatchRecvParams &p, __gm__ AFDActive *active, __gm__ AFDExecutionState *exec,
    __gm__ uint8_t *workspace)
{
    const uint32_t lanes = p.num_source_lanes, experts = p.experts_per_rank;
    auto base = reinterpret_cast<__gm__ uint8_t *>(active);
    auto tx_ptr = reinterpret_cast<__gm__ AFDFfnTransaction *>(base + ffn_tx_offset(lanes, experts));
    auto tx = recv_read(tx_ptr);
    auto plan = recv_read(active);
    if (tx.state != kFfnSelected || tx.next_group > p.num_layers * experts ||
        tx.slice_end != tx.next_group || tx.completed_entries >= tx.num_entries) {
        return STATE_ORDER;
    }
    if (plan.layer_idx != kFfnMixedLayer || tx.num_entries > lanes || tx.num_members > lanes) {
        return BAD_ABI;
    }
    DispatchSliceGroups groups{};
    const uint32_t group_error = select_dispatch_groups(p, base, workspace, tx.next_group, groups);
    if (group_error != OK) {
        return group_error;
    }
    const DispatchSliceTables tables{
        reinterpret_cast<__gm__ const AFDFfnEntry *>(base + ffn_entries_offset(lanes, experts)),
        reinterpret_cast<__gm__ const AFDActiveMember *>(base + ffn_members_offset(lanes, experts)),
        reinterpret_cast<__gm__ const uint32_t *>(base + ffn_counts_offset(lanes, experts)),
        reinterpret_cast<__gm__ AFDActiveEntry *>(base + active_entries_offset()),
        reinterpret_cast<__gm__ AFDActiveMember *>(base + active_members_offset(lanes)),
        reinterpret_cast<__gm__ AFDActiveSegment *>(base + active_segments_offset(lanes)),
        reinterpret_cast<__gm__ uint32_t *>(reinterpret_cast<__gm__ uint8_t *>(exec) + 32),
    };
    plan.valid = 1;
    plan.kind = groups.expanded ? WORK : CONTROL;
    plan.num_entries = plan.num_members = plan.num_segments = 0;
    plan.num_expanded_tokens = groups.expanded;
    plan.num_padded_tokens = groups.physical;
    plan.entries_offset = active_entries_offset();
    plan.members_offset = active_members_offset(lanes);
    plan.segments_offset = active_segments_offset(lanes);
    const uint32_t plan_error = build_dispatch_slice_records(p, tables, groups, tx, plan);
    if (plan_error != OK) {
        return plan_error;
    }
    const AFDExecutionState selected{SELECTED, OK, plan.num_entries, {}};
    tx.slice_end = groups.end;
    tx.state = kFfnSlice;
    write_dispatch_plan_record(exec, selected);
    write_dispatch_plan_record(tx_ptr, tx);
    write_dispatch_plan_record(active, plan);
    return OK;
}

__aicore__ inline void abort_dispatch_transaction(
    __gm__ AFDActive *active, uint32_t lanes, uint32_t experts)
{
    auto base = reinterpret_cast<__gm__ uint8_t *>(active);
    auto tx = reinterpret_cast<__gm__ AFDFfnTransaction *>(base + ffn_tx_offset(lanes, experts));
    AscendC::WriteGmByPassDCache(&tx->state, kFfnAborted);
}

} // namespace afd_async::afd::rt
