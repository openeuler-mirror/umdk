/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2026-2026. All rights reserved.
 * Description: create tiling_args header file
 * Create: 2026-01-13
 * Note:
 * History: 2026-01-13 create tiling_args header file
 */

#ifndef TILING_ARGS_H
#define TILING_ARGS_H
#include <cstdint>

namespace Moe {
constexpr uint64_t COMBINE_STATE_WIN_OFFSET = 3U * 1024UL * 1024UL;
constexpr uint64_t NOTIFY_DISPATCH_WIN_OFFSET = 204U * 1024UL * 1024UL;
} // namespace Moe
#endif // TILING_ARGS_H