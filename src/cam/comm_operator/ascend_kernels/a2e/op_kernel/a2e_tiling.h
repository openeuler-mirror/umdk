/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2026-2026. All rights reserved.
 * Description: a2e tiling header file
 * Create: 2026-02-06
 * Note:
 * History: 2026-02-06 create a2e tiling header file
 */

#ifndef A2E_TILING_H
#define A2E_TILING_H

#include <cstdint>
#include "kernel_tiling/kernel_tiling.h"

namespace Cam {
struct A2ETilingData {
    Mc2InitTiling mc2InitTiling;
    Mc2CcTiling mc2CcTiling1;
    uint32_t batchSize;
    uint32_t hiddenSize;
    uint32_t topk;
    uint32_t expertRankSize;
    uint32_t attentionRankSize;
    uint32_t rank;
    uint32_t computeGate;
};
} // namespace Cam

#endif