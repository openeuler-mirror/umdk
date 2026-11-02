/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2026-2026. All rights reserved.
 * Description: FusedDeepMoe operator kernel utils function header file, for a3
 * Create: 2026-05-12
 * Note:
 * History: 2026-05-12 create FusedDeepMoe operator kernel utils function header file, for a3
 */
#ifndef FUSED_DEEP_MOE_UTILS_H
#define FUSED_DEEP_MOE_UTILS_H

#include <kernel_operator.h>
#include "../fused_deep_moe_base.h"

namespace CVSoftSync {
    constexpr uint32_t SOFT_SYNC_SPACE_SIZE = 512;
    // The per-direction event id pool is 0..7 on the inference series. Allocate DOWN from
    // the top: the epilogue/token pipelines pre-Set small ids (the per-token-dequant
    // epilogue ctor pre-Sets V_MTE2/MTE3_V/V_MTE3 lists starting at 0 and consumes them
    // much later, the quant path uses V_MTE3 2/3, notify/writer/handoff use 4), and a
    // pre-Set or stale Set on a shared (direction, id) could falsely satisfy this
    // helper's Wait - the staged copy would then read unflushed UB. Nothing anywhere
    // pre-Sets id 7, so these helpers take it; the next free one down is 6.
    constexpr int32_t SOFT_SYNC_EVENT_ID = 7;
}

// Combine data-as-flag. A receive token is h * sizeof(bf16) bytes, cut into whole 512B blocks
// (256 bf16 elements; tiling rejects an h that is not a multiple of 256). This rank's gmm1 writes
// SENTINEL_FLAG into the last 32B of every block before it sends the token, and the peer's gmm2
// epilogue overwrites those bytes with the real payload. A block has landed exactly when none of
// its tail words still hold the sentinel. The sentinel sits in bytes the payload overwrites, so
// the receive stride is unchanged.
namespace CombineDataAsFlag {
    // Two bf16 sNaNs (0x7F81), compared together as one int32 word.
    constexpr int32_t SENTINEL_FLAG = 0x7F817F81;
    constexpr uint32_t BLOCK_BYTES = 512;
    constexpr uint32_t TAIL_BYTES = 32;
    constexpr uint32_t TAIL_OFFSET = BLOCK_BYTES - TAIL_BYTES;   // 480
    constexpr uint32_t INTS_PER_BLOCK = BLOCK_BYTES / sizeof(int32_t);
    constexpr uint32_t TAIL_INTS = TAIL_BYTES / sizeof(int32_t);  // 8
    // Blocks per token. h must be a multiple of 256; tiling rejects anything else.
    constexpr uint32_t BLOCK_ELEMS = 256;
}

template<typename T>
__aicore__ inline T FlushAndGetValue(AscendC::GlobalTensor<T> &globalTensor, uint64_t index)
{
        __asm__ __volatile__("");
        AscendC::DataCacheCleanAndInvalid<T, AscendC::CacheLine::SINGLE_CACHE_LINE,
                                          AscendC::DcciDst::CACHELINE_OUT>(globalTensor[index]);
        __asm__ __volatile__("");
        T value = globalTensor.GetValue(index);
        return value;
}

template<typename T>
__aicore__ inline void SetValueAndFlush(AscendC::GlobalTensor<T> &globalTensor, uint64_t index, T value)
{
        globalTensor.SetValue(index, value);
        __asm__ __volatile__("");
        AscendC::DataCacheCleanAndInvalid<T, AscendC::CacheLine::SINGLE_CACHE_LINE,
                                          AscendC::DcciDst::CACHELINE_OUT>(globalTensor[index]);
        __asm__ __volatile__("");
}

template<typename T>
__aicore__ inline T FlushAndSpinValue(AscendC::GlobalTensor<T> &globalTensor, uint64_t index)
{
        T value = FlushAndGetValue(globalTensor, index);
        if (value == 0) {
            SetValueAndFlush(globalTensor, index, 1);
        } else {
            SetValueAndFlush(globalTensor, index, 0);
        }
        return value;
}

// The old scalar RMW, kept for the cube core: the AIC has no V-pipe instructions (no
// Duplicate) and does not support LocalTensor SetValue staging, so the only write path
// is a GM read-modify-write. It operates on the SAME int32 word 0 every other variant
// uses - one DCCI line read plus one DCCI line flush per call, and the launch-end 32B
// zero restores word 0 to 0 (byte-level uint8 would also cap the count at 255).
__aicore__ inline void EncreaseSyncFlag(__gm__ uint8_t *flagAddr, uint8_t idx)
{
    // flag++, like set flag
    AscendC::PipeBarrier<PIPE_ALL>();
    AscendC::GlobalTensor<int32_t> global;
    global.SetGlobalBuffer(reinterpret_cast<__gm__ int32_t *>(
        flagAddr + idx * CVSoftSync::SOFT_SYNC_SPACE_SIZE));
    int32_t value = FlushAndGetValue<int32_t>(global, 0);
    SetValueAndFlush<int32_t>(global, 0, value + 1);
    AscendC::PipeBarrier<PIPE_ALL>();
}

// Per-core soft-sync publish (the writer side). The flag is ALWAYS int32 word 0 of the
// writer's 512B slot and the value is always its running block count - only the
// assignment differs by core type:
// - AIV: the writer owns the slot AND the count, so the value comes from the caller and
//   lands as one Duplicate broadcast + ONE MTE3 copy through L2 - no DCCI at all.
// - AIC: falls back to EncreaseSyncFlag's GM read-modify-write (the caller's count is
//   unused there; the RMW derives the same value from word 0).
// The Duplicate->DataCopy handoff is cross-pipe (V->MTE3), so it MUST be a
// SetFlag/WaitFlag event pair - a PipeBarrier only orders within one pipe. The id is
// SOFT_SYNC_EVENT_ID (7), allocated top-down precisely because the epilogue/token
// pipelines pre-Set the small ids and a shared id could be falsely notified.
__aicore__ inline void PublishSyncFlag(__gm__ uint8_t *flagAddr, uint8_t idx, int32_t value,
                                       AscendC::LocalTensor<int32_t> scratch)
{
    if ASCEND_IS_AIV {
        // entry barrier: the flag must not overtake this core's in-flight MTE3 stores of
        // the block it announces (also drains the previous publish's copy before this one
        // restages the scratch on V); trailing same-pipe MTE3 barrier orders the copies.
        AscendC::PipeBarrier<PIPE_ALL>();
        AscendC::Duplicate<int32_t>(scratch, value, 8);
        AscendC::SetFlag<AscendC::HardEvent::V_MTE3>(CVSoftSync::SOFT_SYNC_EVENT_ID);
        AscendC::WaitFlag<AscendC::HardEvent::V_MTE3>(CVSoftSync::SOFT_SYNC_EVENT_ID);
        AscendC::GlobalTensor<int32_t> global;
        global.SetGlobalBuffer(reinterpret_cast<__gm__ int32_t *>(
            flagAddr + idx * CVSoftSync::SOFT_SYNC_SPACE_SIZE));
        AscendC::DataCopy(global, scratch, 8UL);
        AscendC::PipeBarrier<PIPE_MTE3>();
    } else {
        EncreaseSyncFlag(flagAddr, idx);
    }
}

// check flag, like wait flag. The flag is int32 word 0 on both sides; only the read
// differs by core type. AIV: one MTE2 block copy per poll through L2 instead of a DCCI
// line read per spin - the writer publishes via MTE3, MTE2/MTE3 meet coherently in L2,
// and the waiters stop invalidating each other's (and the writer's) lines. The SCALAR
// (S-pipe) GetValue needs the MTE2->S handoff, which is cross-pipe and therefore a
// SetFlag/WaitFlag pair (a PipeBarrier cannot notify across pipes) on
// SOFT_SYNC_EVENT_ID - the other MTE2_S users take id 0 with immediately-consumed
// pairs, so 7 has nothing stale or pre-Set to falsely satisfy it. AIC: the cube core's
// MTE2 does not deliver to UB, so keep the original DCCI scalar spin (no AIC caller
// today; kept so the helper stays symmetric).
__aicore__ inline void CheckSyncFlag(__gm__ uint8_t *flagAddr, uint8_t idx, uint32_t target,
                                     AscendC::LocalTensor<int32_t> scratch)
{
    AscendC::PipeBarrier<PIPE_ALL>();
    if ASCEND_IS_AIV {
        AscendC::GlobalTensor<int32_t> global;
        global.SetGlobalBuffer(reinterpret_cast<__gm__ int32_t *>(
            flagAddr + idx * CVSoftSync::SOFT_SYNC_SPACE_SIZE));
        while (true) {
            AscendC::DataCopy(scratch, global, 8UL);
            AscendC::SetFlag<AscendC::HardEvent::MTE2_S>(CVSoftSync::SOFT_SYNC_EVENT_ID);
            AscendC::WaitFlag<AscendC::HardEvent::MTE2_S>(CVSoftSync::SOFT_SYNC_EVENT_ID);
            int32_t value = scratch.GetValue(0);
            if (static_cast<uint32_t>(value) >= target) {
                break;
            }
            SPIN_WAIT_CYCLES();
        }
    } else {
        AscendC::GlobalTensor<int32_t> global;
        global.SetGlobalBuffer(reinterpret_cast<__gm__ int32_t *>(
            flagAddr + idx * CVSoftSync::SOFT_SYNC_SPACE_SIZE));
        while (true) {
            int32_t value = FlushAndGetValue<int32_t>(global, 0);
            if (static_cast<uint32_t>(value) >= target) {
                break;
            }
            SPIN_WAIT_CYCLES();
        }
    }
    AscendC::PipeBarrier<PIPE_ALL>();
}

#endif  // FUSED_DEEP_MOE_UTILS_H
