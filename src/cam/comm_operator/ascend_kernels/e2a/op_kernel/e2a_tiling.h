/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2026-2026. All rights reserved.
 * Description: e2a tiling header file
 * Create: 2026-02-06
 * Note:
 * History: 2026-02-06 create e2a tiling header file
 */

#ifndef E2A_TILING_H
#define E2A_TILING_H

#include <cstdint>
#include "kernel_tiling/kernel_tiling.h"

namespace Cam {
struct E2ATilingData {
    Mc2InitTiling mc2InitTiling;
    Mc2CcTiling mc2CcTiling1;
    uint32_t batchSize;
    uint32_t hiddenSize;
    uint32_t topk;
    uint32_t expertRankSize;
    uint32_t attentionRankSize;
    uint32_t rank;
};
} // namespace Cam

#endif