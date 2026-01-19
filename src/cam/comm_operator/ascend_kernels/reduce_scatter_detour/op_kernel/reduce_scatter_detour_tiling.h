/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2026-2026. All rights reserved.
 * Description: ReduceScatter operator tiling data structure file
 * Create: 2026-01-22
 * Note:
 * History: 2026-01-22 create a ReduceScatter operator tiling data structure file
 */

#ifndef REDUCE_SCATTER_DETOUR_TILING_H
#define REDUCE_SCATTER_DETOUR_TILING_H

#include "cstdint"

namespace Cam {
struct ReduceScatterDetourTilingData {
    uint32_t sendCount;
    uint32_t op;
    int64_t magic;
    uint32_t commRankCount;
};
}

#endif