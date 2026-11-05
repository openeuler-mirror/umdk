/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2026-2026. All rights reserved.
 * Description: cam_deepep_combine_send tiling data structure
 * Create: 2026-11-03
 * Note: model-dependent sizes are runtime tiling fields;
 *       no per-model tiling key is derived from them.
 * History: 2026-11-03 create runtime parameter port
 */

#ifndef CAM_DEEPEP_COMBINE_SEND_TILING_H
#define CAM_DEEPEP_COMBINE_SEND_TILING_H

#include <cstdint>
#include "kernel_tiling/kernel_tiling.h"

namespace Cam {
struct CamDeepepCombineSendTilingData {
    uint32_t blockDim;
    uint32_t numSrcRanks;
    uint32_t numRanks;
    uint32_t expertsPerRank;
    uint32_t numTopk;
    uint32_t numHidden;
    uint32_t numVecCores;
    uint32_t numSourceLanes;
    uint32_t numLayers;
    uint32_t maxPaddedTokens;
    uint32_t numTokensPerTile;
    uint32_t numUbBytes;
    uint32_t rankIdx;
    uint64_t timeoutCycles;
    uint32_t reserved[2];
};
}  // namespace Cam

#endif
