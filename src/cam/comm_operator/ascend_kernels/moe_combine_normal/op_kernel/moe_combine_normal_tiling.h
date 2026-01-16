/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2025-2025. All rights reserved.
 * Description: Normal combine tiling header file
 * Create: 2025-11-28
 * Note:
 * History: 2025-11-28 create normal combine tiling header file
 */

#ifndef MOE_COMBINE_NORMAL_TILING_H
#define MOE_COMBINE_NORMAL_TILING_H

#include "kernel_tiling/kernel_tiling.h"
#include <cstdint>

struct MoeCombineNormalInfo {
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
};
struct MoeCombineNormalTilingData {
    Mc2InitTiling mc2InitTiling;
    Mc2CcTiling mc2CcTiling1;
    Mc2CcTiling mc2CcTiling2;
    MoeCombineNormalInfo moeCombineNormalInfo;
};

#endif // MOE_COMBINE_NORMAL_TILING_H