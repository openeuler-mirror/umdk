/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2026-2026. All rights reserved.
 * Description: Shared device constants for the CAM DeepEP-compatible operators.
 * Create: 2026-11-03
 * Note: Device header for the CAM DeepEP-compatible operators.
 * History: 2026-11-03 create for the cam_deepep operators
 */
#pragma once

#include <cstdint>

namespace deep_ep {

using sf_pack_t = int16_t;

static constexpr int kNumMaxRanks = 256;
static constexpr int kNumMaxExperts = 2048;
static constexpr int kNumMaxVecCores = 64;
static constexpr int kNumUbAlignmentBytes = 32;
static constexpr int kNumUint64AlignmentBytes = 8;
// Shift between the two 32-bit halves packed in one 64-bit word.
static constexpr int kNumHighHalfShiftBits = 32;
static constexpr int kNumVectorRegisterBytes = 256;
static constexpr int kNumSectorBytes = 512;
static constexpr int kNumSectorInts = kNumSectorBytes / sizeof(int);
static constexpr int kNumMaxContexts = 8;
static constexpr int kNumRDMAAlignmentBytes = 32;
static constexpr int kNumTMAAlignmentBytes = 32;
// After dispatch / combine, ensure the sqebb_idx is aligned to 4
// to prevent a WQE to be warp-split across the queue's end and begin
static constexpr int kSQEBBAlignment = 4;
static constexpr int64_t kNumAllocationAlignmentBytes = 2097152;

} // namespace deep_ep
