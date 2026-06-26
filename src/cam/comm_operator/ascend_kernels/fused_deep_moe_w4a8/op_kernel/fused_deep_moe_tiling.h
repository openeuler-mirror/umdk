/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2025-2025. All rights reserved.
 * Description: FusedDeepMoe tilingData definition file
 * Create: 2025-07-19
 * Note:
 * History: 2025-07-19 create FusedDeepMoe tilingData definition file
 */

#ifndef FUSED_DEEP_MOE_TILING_H
#define FUSED_DEEP_MOE_TILING_H

#include <cstdint>
#include "kernel_tiling/kernel_tiling.h"

namespace Cam {
struct FusedDeepMoeInfo {
    uint32_t epRankSize;           // epRankSize
    uint32_t epRankId;             // epRankId
    uint32_t moeExpertNum;         // moe expert number
    uint32_t moeExpertNumPerRank;  // moe expert number per rank
    uint32_t quantMode;            // quant mode
    uint32_t globalBs;             // globalBs = BS * worldSize
    uint32_t bs;                   // bs
    uint32_t k;                    // k
    uint32_t h;                    // h
    uint32_t aicNum;               // aicNum
    uint32_t aivNum;               // aivNum
    uint64_t totalUbSize;
    uint64_t totalWinSize;
    uint64_t gmm1HLen;
    uint64_t shareGmm1HLen;  // shared expert gmm1 hidden length
    bool isTensorList;
};

struct FusedDeepMoeTilingData {
    Mc2InitTiling mc2InitTiling;
    Mc2CcTiling mc2CcTiling;
    FusedDeepMoeInfo disGmmDeqSwigluQuantGmmDeqComInfo;
};

constexpr uint32_t GM_ALIGN_BYTE = 512;
constexpr uint32_t CUSTOM_PRELOAD_STAGES = 1;
constexpr uint32_t CUSTOM_L1_STAGES = 2;
constexpr uint32_t CUSTOM_L0A_STAGES = 2;
constexpr uint32_t CUSTOM_L0B_STAGES = 2;
constexpr uint32_t CUSTOM_L0C_STAGES = 1;
constexpr bool CUSTOM_ENABLE_UNIT_FLAG = true;
constexpr bool CUSTOM_ENABLE_SHUFFLE_K = true;

constexpr uint32_t GMM1_L1M = 256;
constexpr uint32_t GMM1_L1N = 128;
constexpr uint32_t GMM1_L1K = 1024;
constexpr uint32_t GMM1_L0K = 256;
constexpr uint32_t GMM1_EPIM = 64;
constexpr uint32_t GMM1_SWIZZLE_OFFSET = 3;
constexpr uint32_t GMM1_SWIZZLE_DIRECTION = 0;

constexpr uint32_t GMM2_L1A_STAGES = 4;
constexpr uint32_t GMM2_L1B_STAGES = 2;
constexpr uint32_t GMM2_L0A_STAGES = 4;
constexpr uint32_t GMM2_L0B_STAGES = 2;
constexpr uint32_t GMM2_L1M = 128;
constexpr uint32_t GMM2_L1N = 256;
constexpr uint32_t GMM2_L1K = 1024;
constexpr uint32_t GMM2_L0K = 256;
constexpr uint32_t GMM2_EPIM = 32;
constexpr uint32_t GMM2_SWIZZLE_OFFSET = 3;
constexpr uint32_t GMM2_SWIZZLE_DIRECTION = 0;

constexpr uint32_t WORKSPACE_STAGES = 4;

constexpr uint32_t EXEC_FLAG_DEEP_FUSE = (1U << 0);
constexpr uint32_t EXEC_FLAG_TENSOR_LIST = (1U << 1);
constexpr uint32_t EXEC_FLAG_X_ACTIVE_MASK = (1U << 2);
constexpr uint32_t EXEC_FLAG_SHARED_EXPERT = (1U << 3);
constexpr uint32_t EXEC_FLAG_SMOOTH_QUANT = (1U << 4);
} // namespace Cam
#endif  // FUSED_DEEP_MOE_TILING_H
