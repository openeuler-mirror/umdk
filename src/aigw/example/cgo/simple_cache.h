/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2026-2026. All rights reserved.
 *
 * @file simple_cache.h
 * @brief simulate redis-like cache.
 *
 * @create 2026-01-26
 */

#ifndef SIMPLE_CACHE_H
#define SIMPLE_CACHE_H

#include "aigw.h"

#ifdef __cplusplus
extern "C" {
#endif

aigw_cache_driver_t *get_simple_cache_driver(void);
aigw_error_t test_simple_cache(void);

#ifdef __cplusplus
}
#endif

#endif // SIMPLE_CACHE_H