// SPDX-License-Identifier: MIT
// Description: F-local FFN transaction layout for CAM.
// AFD source: puxiaokun3721/DeepEP-Ascend @ 8757a68d
// AFD file: deep_ep/include/deep_ep/layout/afd/ffn_transaction.hpp
// CAM modifications: Uses the CAM Active header and the named UB
// alignment constant for the shared transaction records.
#pragma once

#include <deep_ep/layout/afd/active.h>

namespace deep_ep::afd {

// The legacy Active is the current slice. This F-local trailer owns the fixed
// selection and survives all slices. It is not part of the A/F wire protocol.
constexpr uint32_t kFfnTransactionMagic = 0x41465431u;
constexpr uint32_t kFfnMixedLayer = 0xffffffffu;
constexpr uint32_t kFfnIdle = 0;
constexpr uint32_t kFfnSelected = 1;
constexpr uint32_t kFfnSlice = 2;
constexpr uint32_t kFfnComplete = 3;
constexpr uint32_t kFfnAborted = 4;

struct alignas(kNumUbAlignmentBytes) AFDFfnTransaction {
    uint32_t state, txn_id, next_group, slice_end;
    uint32_t num_entries, num_members, completed_entries, slice_idx;
};

struct alignas(kNumUbAlignmentBytes) AFDFfnEntry {
    uint32_t pending_idx, member_begin, num_members, layer_slot;
    uint32_t remaining_rows, grant_state, retired, reserved;
};

constexpr __aicore__ __forceinline__ uint64_t ffn_tx_offset(uint32_t l, uint32_t r)
{
    return active_bytes(l, r);
}

constexpr __aicore__ __forceinline__ uint64_t ffn_entries_offset(uint32_t l, uint32_t r)
{
    return ffn_tx_offset(l, r) + sizeof(AFDFfnTransaction);
}

constexpr __aicore__ __forceinline__ uint64_t ffn_members_offset(uint32_t l, uint32_t r)
{
    return ffn_entries_offset(l, r) + uint64_t(l) * sizeof(AFDFfnEntry);
}

constexpr __aicore__ __forceinline__ uint64_t ffn_counts_offset(uint32_t l, uint32_t r)
{
    return ffn_members_offset(l, r) + uint64_t(l) * sizeof(AFDActiveMember);
}

constexpr __aicore__ __forceinline__ uint64_t ffn_groups_offset(uint32_t l, uint32_t r)
{
    return ffn_counts_offset(l, r) + align32(4uLL * l * r);
}

constexpr __aicore__ __forceinline__ uint64_t ffn_active_bytes(uint32_t l, uint32_t r, uint32_t layers)
{
    return ffn_groups_offset(l, r) + align32(4uLL * layers * r);
}

static_assert(sizeof(AFDFfnTransaction) == 32 && sizeof(AFDFfnEntry) == 32);

} // namespace deep_ep::afd
