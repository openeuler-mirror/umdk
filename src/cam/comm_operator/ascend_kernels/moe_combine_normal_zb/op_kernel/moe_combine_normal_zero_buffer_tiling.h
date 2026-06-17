/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2026-2026. All rights reserved.
 * Description: MoeCombineNormalZeroBuffer tiling data header file
 * Create: 2026-06-10
 * Note:
 * History: 2026-06-10 create MoeCombineNormalZeroBuffer tiling data header file
 */
#ifndef MOE_COMBINE_NORMAL_ZERO_BUFFER_TILING_H
#define MOE_COMBINE_NORMAL_ZERO_BUFFER_TILING_H

#include <cstdint>
#include "kernel_tiling/kernel_tiling.h"

struct MoeCombineNormalZeroBufferInfo {
    uint32_t epWorldSize;
    uint32_t tpWorldSize;
    uint32_t epRankId;
    uint32_t tpRankId;
    uint32_t expertShardType;
    uint32_t moeExpertNum;
    uint32_t moeExpertPerRankNum;
    uint32_t globalBs;
    uint32_t bs;
    uint32_t k;
    uint32_t h;
    uint32_t aivNum;
    uint64_t totalUbSize;
    uint64_t totalWinSize;
    float armAvgFactor;
    float epsilon;
    bool isEnableDiagnose;
    bool isGetProb;
};
struct MoeCombineNormalZeroBufferTilingData {
    MoeCombineNormalZeroBufferInfo moeCombineNormalInfo;
    uint64_t zeroBufferPtr;  // zero buffer symmetric point
};

#endif  // MOE_COMBINE_NORMAL_ZERO_BUFFER_TILING_H
