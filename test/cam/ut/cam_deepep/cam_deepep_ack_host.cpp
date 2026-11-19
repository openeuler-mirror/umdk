// SPDX-License-Identifier: MIT
// Run the production transaction planner, validator and ACK publisher against host storage.
#include <array>
#include <cassert>
#include <cstring>

#define __aicore__
#define __forceinline__ inline
#define __gm__
#define __ubuf__
#include <deep_ep/layout/afd/return.h>
#include <deep_ep/layout/afd/ffn_transaction.h>

namespace AscendC {
enum class MemDsbT { DDR };
template <MemDsbT> void DataSyncBarrier() {}
template <typename T> void WriteGmByPassDCache(T *dst, T value) { *dst = value; }
}

namespace deep_ep::afd::rt {
struct DispatchRecvParams {
    uint32_t num_source_lanes, experts_per_rank, num_layers, num_vec_cores;
    uint32_t max_expanded_tokens, max_padded_tokens, expert_alignment;
};
template <typename T> T recv_read(const T *src) { return *src; }
bool recv_range(uint64_t offset, uint64_t bytes, uint64_t size) { return offset <= size && bytes <= size - offset; }
unsigned remote_writes = 0;
void store_control(void *dst, const uint8_t *src)
{
    ++remote_writes;
    std::memcpy(dst, src, sizeof(AFDControlBlock));
}
}

#include "cam_deepep_dispatch_recv/op_kernel/cam_deepep_dispatch_recv_transaction.h"
#include "cam_deepep_combine_send/op_kernel/cam_deepep_combine_send_transaction.h"

using namespace deep_ep::afd;
using namespace deep_ep::afd::rt;

namespace {
constexpr uint32_t lanes = 2, experts = 1;
struct ActiveStorage {
    AFDActive task{};
    AFDActiveEntry entries[lanes]{};
    AFDActiveMember members[lanes]{};
    AFDActiveSegment segments[lanes * experts]{};
    AFDFfnTransaction tx{};
    AFDFfnEntry rounds[lanes]{};
    AFDActiveMember frozen[lanes]{};
    alignas(32) uint32_t counts[lanes * experts]{};
    alignas(32) uint32_t group_counts[1]{};
};
static_assert(offsetof(ActiveStorage, rounds) == ffn_entries_offset(lanes, experts));
static_assert(offsetof(ActiveStorage, frozen) == ffn_members_offset(lanes, experts));
static_assert(offsetof(ActiveStorage, group_counts) == ffn_groups_offset(lanes, experts));
struct ExecStorage {
    AFDExecutionState state{};
    alignas(32) uint32_t grants[lanes]{};
};
struct Control {
    AFDControlBlock consumed{}, done{};
};

struct Fixture {
    ActiveStorage s{};
    AFDLane lane[lanes]{};
    AFDReturnLane returns[lanes]{};
    AFDAddress addresses[lanes]{};
    AFDPeer peer{};
    FfnCombineAckView ack{&peer, lane, returns, addresses, 1, 1, 0, lanes, 0};
    uint32_t layers[1]{0};
    alignas(32) uint8_t message[sizeof(AFDControlBlock)]{};

    Fixture(Control (&window)[lanes], uint32_t bit)
    {
        peer.control_base = reinterpret_cast<uintptr_t>(window);
        peer.control_bytes = sizeof(window);
        s.task.reserved = kFfnTransactionMagic;
        s.task.layer_idx = kFfnMixedLayer;
        s.tx = {kFfnSelected, 1, 0, 0, lanes, lanes, 0, 0};
        for (uint32_t l = 0; l < lanes; ++l) {
            s.rounds[l] = {l, l, 1, 0, l, NONE, 0, 0}; // zero rows on lane 0, one on lane 1
            s.frozen[l] = {l, bit, bit, l, experts, {}};
            s.counts[l] = l;
            addresses[l].consumed_offset = l * sizeof(Control);
            returns[l].done_offset = addresses[l].consumed_offset + sizeof(AFDControlBlock);
        }
        s.group_counts[0] = 1;
        ExecStorage exec{};
        const DispatchRecvParams params{lanes, experts, 1, 1, 8, 8, 1};
        alignas(32) uint8_t scratch[dispatch_recv_workspace_bytes(1, lanes, experts, 8)]{};
        assert(prepare_dispatch_slice(params, &s.task, &exec.state, scratch) == OK);
        // prepare_dispatch_slice owns the group window (it writes groups.end into
        // slice_end); re-read it so retirement sees the same window the kernel does.
        s.tx = *reinterpret_cast<AFDFfnTransaction *>(
            reinterpret_cast<uint8_t *>(&s) + ffn_tx_offset(lanes, experts));
        assert(s.task.num_entries == 2 && s.entries[0].is_final && s.entries[0].num_rows == 0);
        assert(s.entries[1].is_final && s.entries[1].num_rows == 1);
    }

    void omit_empty_entry()
    {
        // Deliberately supply a different, still nonempty Active snapshot.
        s.task.num_entries = s.task.num_members = 1;
        s.entries[0] = s.entries[1];
        s.entries[0].member_begin = 0;
        s.members[0] = s.members[1];
        s.members[0].delta_begin = 0;
        s.segments[0].entry_idx = 0;
    }

    uint32_t finish()
    {
        auto *base = reinterpret_cast<uint8_t *>(&s);
        const uint32_t error = validate_ffn_combine_slice(s.task, s.tx, base, layers, lanes, experts, 1, ack);
        if (error != OK) {
            return error;
        }
        const uint32_t retire_error =
            retire_ffn_slice_rounds(s.task, &s.tx, base, s.entries, lanes, experts, ack, message);
        if (retire_error != OK) {
            return retire_error;
        }
        publish_completion_acks<256>(s.entries, s.task.num_entries, s.members, lanes, ack, message);
        return OK;
    }
};

void test_retirement(bool omit_empty)
{
    Control window[lanes]{};
    for (uint32_t iteration = 0; iteration < 4; ++iteration) {
        const uint32_t bit = iteration % 2;
        Fixture f(window, bit);
        if (omit_empty) {
            f.omit_empty_entry();
        }
        remote_writes = 0;
        assert(f.finish() == OK);
        assert(f.s.tx.completed_entries == 2 && remote_writes == 4);
        for (uint32_t l = 0; l < lanes; ++l) {
            assert(f.s.rounds[l].retired == 1 && f.s.rounds[l].grant_state == FINISHED);
            assert(window[l].done.value == bit && window[l].consumed.value == bit);
        }
    }
}

template <typename Invalidate> void test_bad_address(Invalidate invalidate)
{
    Control window[lanes]{};
    Fixture f(window, 1);
    f.omit_empty_entry();
    invalidate(f);
    remote_writes = 0;
    assert(f.finish() == BAD_ABI);
    assert(remote_writes == 0 && f.s.tx.completed_entries == 0);
    assert(!f.s.rounds[0].retired && !f.s.rounds[1].retired);
}

void test_repeated_completion_lanes()
{
    constexpr uint32_t size = 256;
    std::array<Control, size> window{};
    std::array<AFDLane, size> lane{};
    std::array<AFDReturnLane, size> ret{};
    std::array<AFDAddress, size> addr{};
    const AFDPeer peer{0, 0, 0, reinterpret_cast<uintptr_t>(window.data()), sizeof(window)};
    const FfnCombineAckView ack{&peer, lane.data(), ret.data(), addr.data(), 1, 1, 0, size, 0};
    for (uint32_t l = 0; l < size; ++l) {
        addr[l].consumed_offset = l * sizeof(Control);
        ret[l].done_offset = addr[l].consumed_offset + sizeof(AFDControlBlock);
    }
    const AFDActiveEntry entries[] = {{0, 0, 3, 0, 0, 0, 1, 0}, {1, 3, 4, 0, 0, 0, 1, 0}};
    const AFDActiveMember members[] = {{0, 1, 0}, {31, 0, 1}, {31, 8, 8},
                                        {32, 1, 0}, {255, 0, 1}, {0, 8, 8}, {32, 0, 1}};
    alignas(32) uint8_t message[sizeof(AFDControlBlock)]{};
    remote_writes = 0;
    publish_completion_acks<size>(entries, 2, members, size, ack, message);
    assert(remote_writes == 8);
    for (uint32_t l : {0u, 32u}) {
        assert(window[l].consumed.value == 1 && window[l].done.value == 0);
    }
    for (uint32_t l : {31u, 255u}) {
        assert(window[l].consumed.value == 0 && window[l].done.value == 1);
    }
}
}

int main()
{
    test_retirement(false);
    test_retirement(true);
    test_bad_address([](Fixture &f) { f.lane[0].src_rank_idx = 1; });
    test_bad_address([](Fixture &f) { f.lane[0].phase = 1; });
    test_bad_address([](Fixture &f) { f.returns[0].done_offset = UINT64_MAX; });
    test_bad_address([](Fixture &f) { f.addresses[0].consumed_offset = f.peer.control_bytes; });
    test_bad_address([](Fixture &f) { f.peer.control_base = UINT64_MAX - 7; });
    test_repeated_completion_lanes();
}
