/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2025-2025. All rights reserved.
 * Description: Normal dispatch tiling header file
 * Create: 2025-11-28
 * Note:
 * History: 2025-11-28 create normal dispatch tiling header file
 */

#ifndef MOE_DISPATCH_NORMAL_TILING_H
#define MOE_DISPATCH_NORMAL_TILING_H

#include "kernel_tiling/kernel_tiling.h"
#include <cstdint>

struct MoeDispatchNormalInfo {
    uint32_t epWorldSize;  // epWorldSize
    uint32_t tpWorldSize;  // tpWorldSize
    uint32_t epRankId;     // epRankId
    uint32_t tpRankId;     // tpRankId
    uint32_t moeExpertNum; // moe expert number
    uint32_t quantMode;    // quant mode
    uint32_t globalBs;     // globalBs = BS * worldSize
    uint32_t bs;           // bs
    uint32_t k;            // k
    uint32_t h;            // h
    uint32_t aivNum;       // aivNum
    bool isQuant;          // whether quant or not
    bool isEnableDiagnose; // whether enable diagnose or not
    bool reserved2;        // reserved
    bool reserved3;        // reserved
    uint64_t totalUbSize;  // epWorldSize
    uint64_t totalWinSize;
};

struct MoeDispatchNormalTilingData {
    Mc2InitTiling mc2InitTiling;
    Mc2CcTiling mc2CcTiling1;
    Mc2CcTiling mc2CcTiling2;
    MoeDispatchNormalInfo moeDispatchNormalInfo;
};

#endif