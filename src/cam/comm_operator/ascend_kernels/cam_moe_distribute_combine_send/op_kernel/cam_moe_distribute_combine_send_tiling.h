/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2026-2026. All rights reserved.
 * Description: cam_moe_distribute_combine_send tiling header file
 * Create: 2026-09-17
 * Note:
 * History: 2026-09-17 port from cam_async repository
 */

#ifndef CAM_H_COMM_MOE_DISTRIBUTE_COMBINE_SEND_TILING_H
#define CAM_H_COMM_MOE_DISTRIBUTE_COMBINE_SEND_TILING_H

#include <cstdint>
#include "kernel_tiling/kernel_tiling.h"

namespace Cam {
struct CamMoeDistributeCombineSendInfo {
    int64_t magic;
    uint32_t maxSeqLen;
    uint32_t hiddenSize;
    uint32_t topk;
    uint32_t moeRankNum;
    uint32_t attnRankNum;
    uint32_t routeExpertNumPerMoe;
    uint32_t moeRankId;
    uint32_t worldSize;
    uint32_t tpSize;
    uint32_t aivNum;
    uint64_t totalUbSize;
    uint64_t totalWorkspaceSize;
};
struct CamMoeDistributeCombineSendTilingData {
    Mc2InitTiling mc2InitTiling;
    Mc2CcTiling mc2CcTiling1;
    Mc2CcTiling mc2CcTiling2;
    CamMoeDistributeCombineSendInfo moeDistributeCombineInfo;
};
} // namespace Cam

#endif //__CAM_H_COMM_MOE_DISTRIBUTE_COMBINE_SEND_TILING_H
