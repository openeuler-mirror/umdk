/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2026-2026. All rights reserved.
 * Description: cam_deepep_dispatch_send tiling data structure
 * Create: 2026-11-03
 * Note: model-dependent sizes are runtime tiling fields;
 *       no per-model tiling key is derived from them.
 * History: 2026-11-03 create probe shell; 2026-11-03 runtime parameter fields;
 *          2026-11-03 tensor-interface fields (sf strides, status words)
 */

#ifndef CAM_DEEPEP_DISPATCH_SEND_TILING_H
#define CAM_DEEPEP_DISPATCH_SEND_TILING_H

#include <cstdint>
#include "kernel_tiling/kernel_tiling.h"

namespace Cam {
struct CamDeepepDispatchSendTilingData {
    uint32_t blockDim;
    uint32_t numRanks;
    uint32_t numExperts;
    uint32_t expertsPerRank;
    uint32_t numTopk;
    uint32_t numTokensPerTile;
    uint32_t numVecCores;
    uint32_t numHiddenBytes;
    uint32_t numSFPacks;
    uint32_t numUbBytes;
    uint64_t timeoutCycles;
    // Scale-factor tensor strides in elements; zero selects the packed layout
    // derived from numHiddenBytes on the device.
    int32_t sfTokenStride;
    int32_t sfHiddenStride;
    uint32_t sendStatusWords;
    uint32_t reserved;
};
}  // namespace Cam

#endif
