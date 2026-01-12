/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2026-2026. All rights reserved.
 * Description: dispatch layout tiling header file
 * Create: 2026-01-05
 * Note:
 * History: 2026-01-05 create dispatch layout tiling header file
 */

#ifndef DISPATCH_LAYOUT_TILING_H
#define DISPATCH_LAYOUT_TILING_H

#include "kernel_tiling/kernel_tiling.h"

struct DispatchLayoutInfo {
    uint32_t numTokens;
    uint32_t numRanks;
    uint32_t numExperts;
    uint32_t numTopk;
    uint32_t localRankSize;
    uint64_t totalUbSize;
};

struct DispatchLayoutTilingData {
    Mc2InitTiling mc2InitTiling;
    Mc2CcTiling mc2CcTiling1;
    DispatchLayoutInfo dispatchLayoutInfo;
};

#endif