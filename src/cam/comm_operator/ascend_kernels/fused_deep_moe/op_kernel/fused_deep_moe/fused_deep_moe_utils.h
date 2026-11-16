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

__aicore__ inline void EncreaseSyncFlag(__gm__ uint8_t *flagAddr, uint8_t idx)
{
    // flag++, like set flag
    AscendC::PipeBarrier<PIPE_ALL>();
    AscendC::GlobalTensor<uint8_t> global;
    global.SetGlobalBuffer(flagAddr + idx * CVSoftSync::SOFT_SYNC_SPACE_SIZE);
    uint8_t value = FlushAndGetValue<uint8_t>(global, 0);
    SetValueAndFlush<uint8_t>(global, 0, value + 1);
    AscendC::PipeBarrier<PIPE_ALL>();
}

__aicore__ inline void CheckSyncFlag(__gm__ uint8_t *flagAddr, uint8_t idx, uint32_t target)
{
    //  check flag, like wait flag
    AscendC::PipeBarrier<PIPE_ALL>();
    AscendC::GlobalTensor<uint8_t> global;
    global.SetGlobalBuffer(flagAddr + idx * CVSoftSync::SOFT_SYNC_SPACE_SIZE);
    while (true) {
        uint8_t value = FlushAndGetValue<uint8_t>(global, 0);
        if (value >= target) {
            break;
        }
        SPIN_WAIT_CYCLES();
    }
    AscendC::PipeBarrier<PIPE_ALL>();
}

#endif  // FUSED_DEEP_MOE_UTILS_H
