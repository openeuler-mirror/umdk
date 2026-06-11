/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2026-2026. All rights reserved.
 * Description: MoeCombineLowlatencyZeroBuffer tiling data header file
 * Create: 2026-06-10
 * Note:
 * History: 2026-06-10 create MoeCombineLowlatencyZeroBuffer tiling data header file
 */
#ifndef ASCENDC_MOE_COMBINE_LOWLATENCY_ZERO_BUFFER_TILING_H
#define ASCENDC_MOE_COMBINE_LOWLATENCY_ZERO_BUFFER_TILING_H

#include <cstdint>
#include "kernel_tiling/kernel_tiling.h"

// a3
struct MoeCombineLowlatencyZeroBufferInfo {
    uint32_t epWorldSize;
    uint32_t tpWorldSize;
    uint32_t epRankId;
    uint32_t tpRankId;
    uint32_t expertShardType;
    uint32_t sharedExpertNum;
    uint32_t sharedExpertRankNum;
    uint32_t moeExpertNum;
    uint32_t moeExpertPerRankNum;
    uint32_t zeroExpertNum;
    uint32_t copyExpertNum;
    uint32_t constExpertNum;
    uint32_t globalBs;
    uint32_t bs;
    uint32_t k;
    uint32_t h;
    uint32_t aivNum;
    bool isTokenMask;       // input active mask 1dims or not
    bool isExpertMask;      // input active mask 2dims or not
    bool hasSharedExpertX;  // input shared expert x or not
    bool hasElasticInfo;    // has elasticinfo or not
    uint64_t totalUbSize;
    uint64_t totalWinSize;
    float armAvgFactor;
    float epsilon;
    uint64_t zeroBufferPtr;  // zero buffer ptr
};
struct MoeCombineLowlatencyZeroBufferTilingData {
    Mc2InitTiling mc2InitTiling;
    Mc2CcTiling mc2CcTiling1;
    Mc2CcTiling mc2CcTiling2;
    MoeCombineLowlatencyZeroBufferInfo moeCombineLowlatencyZeroBufferInfo;
};

#endif  // ASCENDC_MOE_COMBINE_LOWLATENCY_ZERO_BUFFER_TILING_H
