/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2025-2025. All rights reserved.
 * Description: FusedDeepMoe operator kernel function implementation file
 * Create: 2025-07-19
 * Note:
 * History: 2025-07-19 create FusedDeepMoe operator kernel function implementation file
 */
#pragma once
#include "catlass/epilogue/block/block_epilogue.hpp"

#include "block_epilogue_per_token_dequant_swiglu.h"
#include "block_epilogue_per_token_dequant.hpp"
