/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2026-2026. All rights reserved.
 * Description: cam_deepep_combine_recv tiling data structure
 * Create: 2026-11-03
 * Note: model-dependent sizes are runtime tiling fields;
 *       no per-model tiling key is derived from them. round_step/start stay
 *       runtime booleans so single-round and multi-round share one binary.
 * History: 2026-11-03 create runtime parameter port
 */

#ifndef CAM_DEEPEP_COMBINE_RECV_TILING_H
#define CAM_DEEPEP_COMBINE_RECV_TILING_H

#include <cstdint>
#include "kernel_tiling/kernel_tiling.h"

namespace Cam {
struct CamDeepepCombineRecvTilingData {
    uint32_t blockDim;
    uint32_t numExperts;
    uint32_t numRanks;
    uint32_t numTopk;
    uint32_t numHidden;
    uint32_t numHiddenChunk;
    uint32_t numVecCores;
    uint32_t numUbBytes;
    uint32_t roundStep;
    uint32_t start;
    uint64_t timeoutCycles;
    uint32_t reserved[2];
};
}  // namespace Cam

#endif
