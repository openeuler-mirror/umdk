/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2026-2026. All rights reserved.
 * Description: all2all with detour tiling function implementation file
 * Create: 2026-01-22
 * Note:
 * History: 2026-01-22 create all2all with detour tiling function file
 */

#ifndef ALL2All_DETOUR_TILING_H
#define ALL2All_DETOUR_TILING_H

#include "register/tilingdata_base.h"

namespace optiling {
BEGIN_TILING_DATA_DEF(All2AllDetourTilingData)
    TILING_DATA_FIELD_DEF(uint32_t, magic);
    TILING_DATA_FIELD_DEF(uint32_t, sendCount);
    TILING_DATA_FIELD_DEF(uint32_t, commRankCount);
END_TILING_DATA_DEF;

REGISTER_TILING_DATA_CLASS(All2AllDetour, All2AllDetourTilingData)
}

#endif