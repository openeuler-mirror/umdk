/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2026-2026. All rights reserved.
 * Description: cam_deepep_dispatch_recv tiling data structure
 * Create: 2026-11-03
 * Note: model-dependent sizes are runtime tiling fields;
 *       no per-model tiling key is derived from them.
 * History: 2026-11-03 create runtime parameter port
 */

#ifndef CAM_DEEPEP_DISPATCH_RECV_TILING_H
#define CAM_DEEPEP_DISPATCH_RECV_TILING_H

#include <cstdint>
#include "kernel_tiling/kernel_tiling.h"

namespace Cam {
struct CamDeepepDispatchRecvTilingData {
    uint32_t blockDim;
    uint32_t numRanks;
    uint32_t numExperts;
    uint32_t expertsPerRank;
    uint32_t numTopk;
    uint32_t numVecCores;
    uint32_t numHiddenBytes;
    uint32_t numSFPacks;
    uint32_t numSourceLanes;
    uint32_t numLayers;
    uint32_t maxExpandedTokens;
    uint32_t maxPaddedTokens;
    uint32_t expertAlignment;
    uint32_t numTokensPerStage;
    uint32_t numUbBytes;
    uint32_t rankIdx;
    int32_t recvSfTokenStride;
    int32_t recvSfHiddenStride;
    uint64_t payloadBytes;
    uint64_t controlBytes;
    uint64_t contextBytes;
    uint32_t reserved[2];
};
}  // namespace Cam

#endif
