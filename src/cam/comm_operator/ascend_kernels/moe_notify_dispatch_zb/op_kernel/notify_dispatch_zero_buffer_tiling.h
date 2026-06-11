/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2026-2026. All rights reserved.
 * Description: NotifyDispatchZeroBuffer tiling data header file
 * Create: 2026-06-10
 * Note:
 * History: 2026-06-10 create NotifyDispatchZeroBuffer tiling data header file
 */
#ifndef NOTIFY_DISPATCH_ZERO_BUFFER_TILING_H
#define NOTIFY_DISPATCH_ZERO_BUFFER_TILING_H

#include "kernel_tiling/kernel_tiling.h"

struct NotifyDispatchZeroBufferInfo {
    uint32_t rankSize;
    uint32_t rankId;
    uint32_t localRankSize;
    uint32_t localRankId;
    uint32_t sendCount;
    uint32_t topkNum;
    uint32_t aivNum;
    uint64_t totalUbSize;
};

struct NotifyDispatchZeroBufferTilingData {
    NotifyDispatchZeroBufferInfo notifyDispatchInfo;
    uint64_t zeroBufferPtr;  // zero buffer symmetric point
};

#endif
